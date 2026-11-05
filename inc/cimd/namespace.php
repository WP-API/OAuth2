<?php
/**
 * OAuth Client ID Metadata Document (CIMD) support.
 *
 * @package WordPress
 * @subpackage JSON API
 */

namespace WP\OAuth2\CIMD;

use WP\OAuth2\Client;
use WP\OAuth2\Well_Known;
use WP_Error;
use WpOrg\Requests\Capability;
use WpOrg\Requests\Exception as RequestsException;
use WpOrg\Requests\Requests;
use WpOrg\Requests\Transport\Curl;

const MAX_URL_LENGTH     = 2048;
const MAX_DOCUMENT_BYTES = 5120;
const MIN_CACHE_TTL      = 300;
const MAX_CACHE_TTL      = 3600;
const LOCK_TIMEOUT       = 30;

/*
 * The CIMD draft (section 10.7) says the server MUST NOT fetch from special-use addresses
 * (the RFC 6890 registry). PHP's FILTER_FLAG_NO_PRIV_RANGE and FILTER_FLAG_NO_RES_RANGE miss
 * several of them, so the lists are explicit.
 */
const IPV4_BLOCKLIST = [
	'0.0.0.0/8',          // This network, RFC 791.
	'10.0.0.0/8',         // Private, RFC 1918.
	'100.64.0.0/10',      // Shared address space, CGNAT, RFC 6598.
	'127.0.0.0/8',        // Loopback.
	'169.254.0.0/16',     // Link-local, RFC 3927.
	'172.16.0.0/12',      // Private, RFC 1918.
	'192.0.0.0/24',       // IETF protocol assignments.
	'192.0.2.0/24',       // Documentation, RFC 5737.
	'192.88.99.0/24',     // 6to4 relay anycast, RFC 7526.
	'192.168.0.0/16',     // Private, RFC 1918.
	'198.18.0.0/15',      // Benchmarking, RFC 2544.
	'198.51.100.0/24',    // Documentation, RFC 5737.
	'203.0.113.0/24',     // Documentation, RFC 5737.
	'224.0.0.0/4',        // Multicast.
	'240.0.0.0/4',        // Reserved.
	'255.255.255.255/32', // Broadcast.
];

const IPV6_BLOCKLIST = [
	'::/128',         // Unspecified.
	'::/96',          // IPv4-compatible, deprecated, RFC 4291.
	'::1/128',        // Loopback.
	'::ffff:0:0/96',  // IPv4-mapped.
	'64:ff9b::/96',   // NAT64, RFC 6052.
	'64:ff9b:1::/48', // Local-use NAT64, RFC 8215.
	'100::/64',       // Discard-only, RFC 6666.
	'2001::/23',      // IETF protocol assignments, including Teredo, RFC 4380.
	'2001:db8::/32',  // Documentation, RFC 3849.
	'2002::/16',      // 6to4, RFC 3056.
	'fc00::/7',       // Unique local, RFC 4193.
	'fe80::/10',      // Link-local.
	'fec0::/10',      // Site-local, deprecated, RFC 3879.
	'ff00::/8',       // Multicast.
	'3fff::/20',      // Documentation, RFC 9637.
	'5f00::/16',      // SRv6 SIDs, RFC 9602.
];

/**
 * Check whether client ID metadata documents are enabled.
 *
 * @return bool
 */
function is_enabled() {
	/**
	 * Filters whether client ID metadata documents are supported.
	 *
	 * @param bool $enabled Whether CIMD is enabled. Default true.
	 */
	return (bool) apply_filters( 'oauth2.cimd.enabled', true );
}

/**
 * Build a WP_Error with a CIMD error code.
 *
 * @param string    $reason    Reason suffix for the `oauth2.cimd.` error code.
 * @param string    $message   Error message.
 * @param int       $status    HTTP status.
 * @param bool|null $transient Whether retrying later may succeed. Omitted from the data when null.
 * @return WP_Error
 */
function make_error( $reason, $message, $status, $transient = null ) {
	$data = [ 'status' => $status ];
	if ( null !== $transient ) {
		$data['transient'] = $transient;
	}

	return new WP_Error( 'oauth2.cimd.' . $reason, $message, $data );
}

/**
 * Check whether a client ID is a CIMD URL rather than a registered client slug.
 *
 * @param mixed $id Client ID.
 * @return bool
 */
function is_cimd_client_id( $id ) {
	return is_string( $id ) && 0 === strpos( $id, 'https://' );
}

/**
 * Validate a client ID URL.
 *
 * @param mixed $url Candidate client ID URL.
 * @return true|WP_Error True if the URL is acceptable.
 */
function validate_client_id_url( $url ) {
	if ( ! is_string( $url ) || strlen( $url ) > MAX_URL_LENGTH ) {
		return make_error( 'invalid_client_id', __( 'The client ID must be a URL of at most 2048 bytes.', 'oauth2' ), 400 );
	}

	if ( ! is_cimd_client_id( $url ) ) {
		return make_error( 'invalid_client_id', __( 'The client ID URL must use the https scheme.', 'oauth2' ), 400 );
	}

	$parts = wp_parse_url( $url );
	if ( ! is_array( $parts ) || empty( $parts['host'] ) ) {
		return make_error( 'invalid_client_id', __( 'The client ID URL could not be parsed or has no host.', 'oauth2' ), 400 );
	}

	$labels = explode( '.', $parts['host'] );
	if ( ! preg_match( '/^[a-z0-9.-]+$/i', $parts['host'] ) || ! preg_match( '/^[a-z][a-z0-9-]*$/i', end( $labels ) ) ) {
		return make_error( 'invalid_client_id', __( 'The client ID URL host must be a plain ASCII host name, not an IP address.', 'oauth2' ), 400 );
	}

	/** This filter is documented in wp-includes/http.php */
	$allowed_ports = apply_filters( 'http_allowed_safe_ports', [ 80, 443, 8080 ], $parts['host'], $url );
	if ( ! is_array( $allowed_ports ) || ! in_array( $parts['port'] ?? 443, $allowed_ports, true ) ) {
		return make_error( 'invalid_client_id', __( 'The client ID URL port is not allowed.', 'oauth2' ), 400 );
	}

	if ( isset( $parts['user'] ) || isset( $parts['pass'] ) ) {
		return make_error( 'invalid_client_id', __( 'The client ID URL must not contain credentials.', 'oauth2' ), 400 );
	}

	if ( false !== strpos( $url, '#' ) ) {
		return make_error( 'invalid_client_id', __( 'The client ID URL must not contain a fragment.', 'oauth2' ), 400 );
	}

	if ( false !== strpos( $url, '?' ) ) {
		return make_error( 'invalid_client_id', __( 'The client ID URL must not contain a query string.', 'oauth2' ), 400 );
	}

	if ( ! isset( $parts['path'] ) || '/' === $parts['path'] ) {
		return make_error( 'invalid_client_id', __( 'The client ID URL must have a path.', 'oauth2' ), 400 );
	}

	foreach ( explode( '/', $parts['path'] ) as $segment ) {
		$segment = rawurldecode( $segment );
		if ( '.' === $segment || '..' === $segment ) {
			return make_error( 'invalid_client_id', __( 'The client ID URL must not contain dot path segments.', 'oauth2' ), 400 );
		}
	}

	$issuers = [ home_url(), Well_Known\get_issuer(), Well_Known\get_published_issuer() ];
	foreach ( $issuers as $issuer ) {
		if ( $url === $issuer || trailingslashit( $issuer ) === $url ) {
			return make_error( 'invalid_client_id', __( 'The client ID URL must not be this site\'s issuer.', 'oauth2' ), 400 );
		}
	}

	/**
	 * Filters whether a client ID URL may be fetched.
	 *
	 * @param bool   $admit Whether to admit the URL. Default true.
	 * @param string $url   Client ID URL.
	 */
	if ( ! apply_filters( 'oauth2.cimd.admit_url', true, $url ) ) {
		return make_error( 'not_allowed', __( 'The client ID URL is not allowed.', 'oauth2' ), 403 );
	}

	return true;
}

/**
 * Check whether a packed IP address falls inside a CIDR range.
 *
 * @param string $packed Address packed by inet_pton().
 * @param string $cidr   Range in CIDR notation.
 * @return bool
 */
function ip_in_cidr( $packed, $cidr ) {
	list( $network, $bits ) = explode( '/', $cidr );

	$network = inet_pton( $network );
	if ( false === $network || strlen( $network ) !== strlen( $packed ) ) {
		return false;
	}

	$bits  = (int) $bits;
	$bytes = intdiv( $bits, 8 );
	$rest  = $bits % 8;

	if ( 0 !== strncmp( $packed, $network, $bytes ) ) {
		return false;
	}

	if ( 0 === $rest ) {
		return true;
	}

	$mask = ( 0xFF << ( 8 - $rest ) ) & 0xFF;

	return ( ord( $packed[ $bytes ] ) & $mask ) === ( ord( $network[ $bytes ] ) & $mask );
}

/**
 * Check whether an address is a public IPv4 or IPv6 address.
 *
 * @param mixed $ip IP address.
 * @return bool
 */
function is_public_ip( $ip ) {
	if ( ! is_string( $ip ) || false === filter_var( $ip, FILTER_VALIDATE_IP ) ) {
		return false;
	}

	$packed = inet_pton( $ip );
	if ( false === $packed ) {
		return false;
	}

	$is_v4 = 4 === strlen( $packed );

	/**
	 * Filters whether loopback addresses count as public. For local development only.
	 *
	 * @param bool $allow Whether to allow loopback addresses. Default false.
	 */
	if ( apply_filters( 'oauth2.cimd.allow_loopback', false ) && ip_in_cidr( $packed, $is_v4 ? '127.0.0.0/8' : '::1/128' ) ) {
		return true;
	}

	if ( false === filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
		return false;
	}

	foreach ( $is_v4 ? IPV4_BLOCKLIST : IPV6_BLOCKLIST as $cidr ) {
		if ( ip_in_cidr( $packed, $cidr ) ) {
			return false;
		}
	}

	return true;
}

/**
 * Resolve a host name to all of its IP addresses.
 *
 * @param string $host Host name or IP literal.
 * @return string[] IP addresses, empty if the lookup failed.
 */
function resolve_host( $host ) {
	/**
	 * Short-circuits host resolution.
	 *
	 * @param string[]|null $ips  IP addresses to use instead of a DNS lookup. Default null.
	 * @param string        $host Host name.
	 */
	$pre = apply_filters( 'oauth2.cimd.pre_resolve_host', null, $host );
	if ( is_array( $pre ) ) {
		return $pre;
	}

	$literal = trim( $host, '[]' );
	if ( false !== filter_var( $literal, FILTER_VALIDATE_IP ) ) {
		return [ $literal ];
	}

	$ips = [];

	// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Lookup failures are handled by the empty result.
	$a = @dns_get_record( $host, DNS_A );
	foreach ( is_array( $a ) ? $a : [] as $record ) {
		if ( isset( $record['ip'] ) ) {
			$ips[] = $record['ip'];
		}
	}

	// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Lookup failures are handled by the empty result.
	$aaaa = @dns_get_record( $host, DNS_AAAA );
	foreach ( is_array( $aaaa ) ? $aaaa : [] as $record ) {
		if ( isset( $record['ipv6'] ) ) {
			$ips[] = $record['ipv6'];
		}
	}

	return $ips;
}

/**
 * Check whether HTTPS requests will be sent with the curl transport.
 *
 * Only the curl transport runs the `http_api_curl` action used to pin the connection.
 *
 * @return bool
 */
function is_curl_transport_in_use() {
	$capabilities = [ Capability::SSL => true ];

	Requests::has_capabilities( $capabilities );

	// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.serialize_serialize -- Matches the cache key used by Requests.
	return Curl::class === ( Requests::$transport[ serialize( $capabilities ) ] ?? '' );
}

/**
 * Work out how many seconds a fetched document may be cached for.
 *
 * @param string $cache_control Cache-Control header value.
 * @param array  $response      HTTP response.
 * @return int
 */
function get_cache_ttl( $cache_control, $response ) {
	$ttl     = MIN_CACHE_TTL;
	$no_hint = false;
	$max_age = null;

	foreach ( explode( ',', strtolower( $cache_control ) ) as $directive ) {
		$directive = trim( $directive );
		if ( 'no-store' === $directive || 'no-cache' === $directive ) {
			$no_hint = true;
		} elseif ( preg_match( '/^max-age\s*=\s*"?(\d+)"?$/', $directive, $matches ) ) {
			$max_age = (int) $matches[1];
		}
	}

	if ( ! $no_hint && null !== $max_age ) {
		$ttl = $max_age;
	}

	$ttl = max( MIN_CACHE_TTL, min( MAX_CACHE_TTL, $ttl ) );

	/**
	 * Filters the cache lifetime of a client metadata document.
	 *
	 * @param int   $ttl      Lifetime in seconds, already clamped to the default bounds.
	 * @param array $response HTTP response.
	 */
	return max( 0, (int) apply_filters( 'oauth2.cimd.cache_ttl', $ttl, $response ) );
}

/**
 * Fetch a client metadata document.
 *
 * @param string $url Client ID URL.
 * @return array|WP_Error Array with `document` and `expires` keys. Error data has `status` and `transient`.
 */
function fetch_document( $url ) {
	if ( ! class_exists( '\WpOrg\Requests\Requests' ) ) {
		return make_error( 'unsafe_transport', __( 'The HTTP library cannot pin the connection to the vetted address.', 'oauth2' ), 500, false );
	}

	$valid = validate_client_id_url( $url );
	if ( is_wp_error( $valid ) ) {
		return $valid;
	}

	$host = wp_parse_url( $url, PHP_URL_HOST );
	$port = wp_parse_url( $url, PHP_URL_PORT );
	$port = $port ? $port : 443;

	$ips = array_values( resolve_host( $host ) );
	if ( empty( $ips ) ) {
		return make_error( 'fetch_failed', __( 'The client ID URL host could not be resolved.', 'oauth2' ), 503, true );
	}

	foreach ( $ips as $ip ) {
		if ( ! is_public_ip( $ip ) ) {
			return make_error( 'unsafe_host', __( 'The client ID URL host resolves to a non-public address.', 'oauth2' ), 400, false );
		}
	}

	if ( ! is_curl_transport_in_use() ) {
		return make_error( 'unsafe_transport', __( 'The HTTP transport cannot pin the connection to the vetted address.', 'oauth2' ), 500, false );
	}

	$proxy = new \WP_HTTP_Proxy();
	if ( $proxy->is_enabled() && $proxy->send_through_proxy( $url ) ) {
		return make_error( 'unsafe_transport', __( 'The request would be sent through a proxy, which cannot be pinned to the vetted address.', 'oauth2' ), 500, false );
	}

	$options = [
		CURLOPT_PROXY          => '',
		CURLOPT_NOPROXY        => '*',
		CURLOPT_FOLLOWLOCATION => false,
		CURLOPT_PROTOCOLS      => CURLPROTO_HTTPS,
	];
	if ( defined( 'CURLOPT_REDIR_PROTOCOLS' ) ) {
		$options[ CURLOPT_REDIR_PROTOCOLS ] = CURLPROTO_HTTPS;
	}

	$ip      = false !== strpos( $ips[0], ':' ) ? '[' . $ips[0] . ']' : $ips[0];
	$called  = false;
	$applied = false;
	$failed  = false;
	$pinned  = false;

	// Runs on http_api_curl: checks the request is for this URL and runs only once.
	$check = static function ( $handle, $args, $request_url ) use ( $url, &$called, &$failed ) {
		if ( $called || $request_url !== $url ) {
			$failed = true;
			throw new RequestsException( 'The connection could not be pinned to the vetted address.', 'oauth2.cimd.unsafe_transport' );
		}
		$called = true;
	};

	// Runs on requests-curl.before_send, the last hook before curl_exec: sets the pin and its options.
	$apply = static function ( $handle ) use ( $host, $port, $ip, $options, &$called, &$applied, &$failed, &$pinned ) {
		if ( ! $called || $applied ) {
			$failed = true;
			throw new RequestsException( 'The connection could not be pinned to the vetted address.', 'oauth2.cimd.unsafe_transport' );
		}
		$applied = true;

		// The resolve entry goes last so that every other option is already in place.
		$options[ CURLOPT_RESOLVE ] = [ "{$host}:{$port}:{$ip}" ];
		foreach ( $options as $option => $value ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.curl_curl_setopt -- Fixes the connection to the vetted address.
			if ( ! curl_setopt( $handle, $option, $value ) ) {
				$failed = true;
				throw new RequestsException( 'The connection could not be pinned to the vetted address.', 'oauth2.cimd.unsafe_transport' );
			}
		}

		$pinned = true;
	};

	add_action( 'http_api_curl', $check, PHP_INT_MAX, 3 );
	add_action( 'requests-curl.before_send', $apply, PHP_INT_MAX, 1 );
	try {
		$response = wp_remote_get(
			$url,
			[
				'timeout'             => 5,
				'redirection'         => 0,
				'limit_response_size' => MAX_DOCUMENT_BYTES + 1,
				'sslverify'           => true,
				'reject_unsafe_urls'  => false,
				'cookies'             => [],
				'headers'             => [ 'Accept' => 'application/json' ],
			]
		);
	} finally {
		remove_action( 'http_api_curl', $check, PHP_INT_MAX );
		remove_action( 'requests-curl.before_send', $apply, PHP_INT_MAX );
	}

	if ( $failed || ! $pinned ) {
		return make_error( 'unsafe_transport', __( 'The connection could not be pinned to the vetted address.', 'oauth2' ), 500, false );
	}

	if ( is_wp_error( $response ) ) {
		return make_error( 'fetch_failed', __( 'The client metadata document could not be fetched.', 'oauth2' ), 503, true );
	}

	$code = (int) wp_remote_retrieve_response_code( $response );
	if ( 429 === $code || ( $code >= 500 && $code < 600 ) ) {
		return make_error( 'fetch_failed', __( 'The client metadata document server is unavailable.', 'oauth2' ), 503, true );
	}

	if ( 200 !== $code ) {
		return make_error( 'fetch_failed', __( 'The client metadata document request did not return 200.', 'oauth2' ), 400, false );
	}

	$body = wp_remote_retrieve_body( $response );
	if ( strlen( $body ) > MAX_DOCUMENT_BYTES ) {
		return make_error( 'document_too_large', __( 'The client metadata document is larger than 5120 bytes.', 'oauth2' ), 400, false );
	}

	$content_type = implode( ',', (array) wp_remote_retrieve_header( $response, 'content-type' ) );
	$media_type   = strtolower( trim( explode( ';', $content_type )[0] ) );
	if ( 'application/json' !== $media_type && '+json' !== substr( $media_type, -5 ) ) {
		return make_error( 'invalid_document', __( 'The client metadata document must be served as JSON.', 'oauth2' ), 400, false );
	}

	$document = json_decode( $body, true );
	if ( ! is_array( $document ) || array_values( $document ) === $document ) {
		return make_error( 'invalid_document', __( 'The client metadata document must be a JSON object.', 'oauth2' ), 400, false );
	}

	$cache_control = implode( ',', (array) wp_remote_retrieve_header( $response, 'cache-control' ) );

	return [
		'document' => $document,
		'expires'  => time() + get_cache_ttl( $cache_control, $response ),
	];
}

/**
 * Build an invalid document error.
 *
 * @param string $message Message naming the rule that failed.
 * @param string $reason  Reason suffix for the error code.
 * @return WP_Error
 */
function invalid_document( $message, $reason = 'invalid_document' ) {
	return make_error( $reason, $message, 400, false );
}

/**
 * Check that a value is an array with sequential integer keys.
 *
 * @param mixed $value Value to check.
 * @return bool
 */
function is_list( $value ) {
	return is_array( $value ) && array_values( $value ) === $value;
}

/**
 * Check that a value is a list containing only strings.
 *
 * @param mixed $value Value to check.
 * @return bool
 */
function is_string_list( $value ) {
	return is_list( $value ) && array_filter( $value, 'is_string' ) === $value;
}

/**
 * Check whether a host is a loopback host name or address.
 *
 * @param string $host Host from parse_url().
 * @return bool
 */
function is_loopback_host( $host ) {
	if ( 'localhost' === strtolower( $host ) ) {
		return true;
	}

	if ( '[' === substr( $host, 0, 1 ) && ']' === substr( $host, -1 ) ) {
		$v6 = substr( $host, 1, -1 );

		return false !== filter_var( $v6, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) && inet_pton( $v6 ) === inet_pton( '::1' );
	}

	return false !== filter_var( $host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) && ip_in_cidr( inet_pton( $host ), '127.0.0.0/8' );
}

/**
 * Check that a JWKS contains only public keys.
 *
 * @param mixed $jwks Decoded `jwks` value.
 * @return bool
 */
function is_public_jwks( $jwks ) {
	if ( ! is_array( $jwks ) || is_list( $jwks ) || ! isset( $jwks['keys'] ) || ! is_array( $jwks['keys'] ) || ! is_list( $jwks['keys'] ) ) {
		return false;
	}

	foreach ( $jwks['keys'] as $key ) {
		if ( ! is_array( $key ) || is_list( $key ) ) {
			return false;
		}

		if ( array_intersect_key( $key, array_flip( [ 'd', 'p', 'q', 'dp', 'dq', 'qi', 'k' ] ) ) || 'oct' === ( $key['kty'] ?? null ) ) {
			return false;
		}
	}

	return true;
}

/**
 * Validate a client metadata document and normalise it.
 *
 * @param array  $document Decoded document.
 * @param string $url      Client ID URL the document was fetched from.
 * @return array|WP_Error Normalised client data.
 */
function validate_document( $document, $url ) {
	if ( ! is_array( $document ) ) {
		return invalid_document( __( 'The client metadata document must be a JSON object.', 'oauth2' ) );
	}

	if ( ! isset( $document['client_id'] ) || ! is_string( $document['client_id'] ) || $document['client_id'] !== $url ) {
		return invalid_document( __( 'The client_id must exactly match the document URL.', 'oauth2' ) );
	}

	if ( array_key_exists( 'client_secret', $document ) || array_key_exists( 'client_secret_expires_at', $document ) ) {
		return invalid_document( __( 'The document must not contain client_secret or client_secret_expires_at.', 'oauth2' ) );
	}

	$redirect_uris = $document['redirect_uris'] ?? null;
	if ( ! is_string_list( $redirect_uris ) || empty( $redirect_uris ) ) {
		return invalid_document( __( 'The redirect_uris must be a non-empty array of strings.', 'oauth2' ) );
	}

	foreach ( $redirect_uris as $redirect_uri ) {
		$parts = wp_parse_url( $redirect_uri );
		if ( ! is_array( $parts ) || empty( $parts['scheme'] ) || empty( $parts['host'] ) || false !== strpos( $redirect_uri, '#' ) ) {
			return invalid_document( __( 'Each redirect URI must be an absolute URL without a fragment.', 'oauth2' ) );
		}

		if ( 'https' !== $parts['scheme'] && ! ( 'http' === $parts['scheme'] && is_loopback_host( $parts['host'] ) ) ) {
			return invalid_document( __( 'Each redirect URI must use https, or http on a loopback host.', 'oauth2' ) );
		}
	}

	if ( array_key_exists( 'token_endpoint_auth_method', $document ) && ! is_string( $document['token_endpoint_auth_method'] ) ) {
		return invalid_document( __( 'The token_endpoint_auth_method must be a string.', 'oauth2' ) );
	}

	if ( array_key_exists( 'token_endpoint_auth_methods_supported', $document ) && ! is_string_list( $document['token_endpoint_auth_methods_supported'] ) ) {
		return invalid_document( __( 'The token_endpoint_auth_methods_supported must be an array of strings.', 'oauth2' ) );
	}

	$singular = $document['token_endpoint_auth_method'] ?? null;
	$plural   = $document['token_endpoint_auth_methods_supported'] ?? null;
	if ( null !== $plural && null !== $singular && ! in_array( $singular, $plural, true ) ) {
		return invalid_document( __( 'The token_endpoint_auth_method must be listed in token_endpoint_auth_methods_supported.', 'oauth2' ) );
	}

	$methods = $plural ?? ( null !== $singular ? [ $singular ] : [ 'none' ] );

	if ( array_intersect( [ 'client_secret_basic', 'client_secret_post', 'client_secret_jwt' ], $methods ) ) {
		return invalid_document( __( 'Shared-secret client authentication methods are not allowed.', 'oauth2' ) );
	}

	if ( ! in_array( 'none', $methods, true ) ) {
		return invalid_document( __( 'The document must allow the none authentication method.', 'oauth2' ), 'unsupported_auth_method' );
	}

	if ( array_key_exists( 'jwks', $document ) && array_key_exists( 'jwks_uri', $document ) ) {
		return invalid_document( __( 'The document must not contain both jwks and jwks_uri.', 'oauth2' ) );
	}

	if ( array_key_exists( 'jwks', $document ) && ! is_public_jwks( $document['jwks'] ) ) {
		return invalid_document( __( 'The jwks must be an object with a keys array of public keys.', 'oauth2' ) );
	}

	if ( array_key_exists( 'jwks_uri', $document ) ) {
		$jwks_uri = is_string( $document['jwks_uri'] ) ? wp_parse_url( $document['jwks_uri'] ) : false;
		if ( ! is_array( $jwks_uri ) || ! isset( $jwks_uri['scheme'] ) || 'https' !== $jwks_uri['scheme'] || empty( $jwks_uri['host'] ) ) {
			return invalid_document( __( 'The jwks_uri must be an https URL.', 'oauth2' ) );
		}
	}

	$grant_types = array_key_exists( 'grant_types', $document ) ? $document['grant_types'] : [ 'authorization_code' ];
	if ( ! is_string_list( $grant_types ) ) {
		return invalid_document( __( 'The grant_types must be an array of strings.', 'oauth2' ) );
	}

	$grant_types = array_values( array_intersect( [ 'authorization_code' ], $grant_types ) );
	if ( empty( $grant_types ) ) {
		return invalid_document( __( 'The grant_types must include authorization_code.', 'oauth2' ) );
	}

	$response_types = array_key_exists( 'response_types', $document ) ? $document['response_types'] : [ 'code' ];
	if ( ! is_string_list( $response_types ) ) {
		return invalid_document( __( 'The response_types must be an array of strings.', 'oauth2' ) );
	}

	$response_types = array_values( array_intersect( [ 'code' ], $response_types ) );
	if ( empty( $response_types ) ) {
		return invalid_document( __( 'The response_types must include code.', 'oauth2' ) );
	}

	$name = '';
	if ( isset( $document['client_name'] ) && is_string( $document['client_name'] ) ) {
		$name = mb_substr( sanitize_text_field( $document['client_name'] ), 0, 200, 'UTF-8' );
	}
	if ( '' === $name ) {
		$name = (string) wp_parse_url( $url, PHP_URL_HOST );
	}

	return [
		'client_id'                  => $url,
		'client_name'                => $name,
		'redirect_uris'              => $redirect_uris,
		'grant_types'                => $grant_types,
		'response_types'             => $response_types,
		'token_endpoint_auth_method' => 'none',
	];
}

/**
 * Get the policy for a client ID metadata document.
 *
 * @param string      $url      Client ID URL.
 * @param array       $metadata Normalised client metadata.
 * @param Client|null $existing Shadow client already stored for the URL, if any.
 * @return string One of `auto`, `manual` or `deny`.
 */
function get_policy( $url, array $metadata, $existing = null ) {
	/**
	 * Filters what to do with a client ID metadata document.
	 *
	 * A new client is approved with `auto`, saved as a draft with `manual`, and
	 * refused with `deny`. An existing client keeps its status, but `deny` also
	 * stops it from authorizing, exchanging codes or authenticating.
	 *
	 * @param string      $policy   One of `auto`, `manual` or `deny`. Default `auto`.
	 * @param array       $metadata Normalised client metadata.
	 * @param string      $url      Client ID URL.
	 * @param Client|null $existing Shadow client already stored for the URL, if any.
	 */
	return (string) apply_filters( 'oauth2.cimd.policy', 'auto', $metadata, $url, $existing );
}

/**
 * Get the stored client to fall back on, or an error if there is none.
 *
 * A client whose last refresh failed for good is never used as a fallback.
 *
 * @param Client|null   $stored Stored client.
 * @param WP_Error|null $error  Error to return when there is no usable stored client.
 * @return Client|WP_Error
 */
function stored_or_error( $stored, $error = null ) {
	if ( $stored && ! $stored->is_cimd_failed() ) {
		return $stored;
	}

	return $error ? $error : make_error( 'client_failed', __( 'The client metadata document could not be refreshed.', 'oauth2' ), 400, false );
}

/**
 * Check whether an error says that retrying later may succeed.
 *
 * @param WP_Error $error Error from the fetcher or validator.
 * @return bool
 */
function is_transient_error( WP_Error $error ) {
	$data = $error->get_error_data();

	return is_array( $data ) && ! empty( $data['transient'] );
}

/**
 * Fetch, validate and store the client for a client ID metadata document.
 *
 * @param string      $url    Client ID URL.
 * @param Client|null $stored Shadow client already stored for the URL, if any.
 * @return Client|WP_Error
 */
function discover_client( $url, $stored = null ) {
	if ( $stored && ! $stored->is_cimd_failed() && $stored->get_cimd_expires() > time() ) {
		return $stored;
	}

	$valid = validate_client_id_url( $url );
	if ( is_wp_error( $valid ) ) {
		return $valid;
	}

	$busy = stored_or_error( $stored, make_error( 'busy', __( 'The client metadata document is being fetched. Try again shortly.', 'oauth2' ), 503, true ) );
	$lock = acquire_lock( $url );
	if ( false === $lock ) {
		return $busy;
	}

	try {
		// Another request may have stored or refreshed the client since it was loaded.
		if ( $stored ) {
			wp_cache_delete( $stored->get_post_id(), 'post_meta' );
			clean_post_cache( $stored->get_post_id() );
		} elseif ( function_exists( 'wp_cache_set_posts_last_changed' ) ) {
			// Drop the cached query results so a record added by another request is found.
			wp_cache_set_posts_last_changed();
		}

		$stored = Client::get_by_id( $url, true );
		if ( $stored && ! $stored->is_cimd_failed() && $stored->get_cimd_expires() > time() ) {
			if ( 'deny' === get_policy( $url, $stored->get_cimd_metadata(), $stored ) ) {
				return make_error( 'not_allowed', __( 'This client is not allowed.', 'oauth2' ), 403 );
			}

			return $stored;
		}

		if ( ! reserve_fetch( get_current_user_id() ) ) {
			return stored_or_error( $stored, make_error( 'rate_limited', __( 'Too many client metadata document fetches. Try again later.', 'oauth2' ), 429, true ) );
		}

		$fetched = fetch_document( $url );
		$result  = is_wp_error( $fetched ) ? $fetched : validate_document( $fetched['document'], $url );
		if ( is_wp_error( $result ) ) {
			if ( ! is_transient_error( $result ) ) {
				if ( $stored ) {
					$stored->mark_cimd_failed();
				}

				return $result;
			}

			return stored_or_error( $stored, $result );
		}

		$policy = get_policy( $url, $result, $stored );
		if ( 'deny' === $policy ) {
			return make_error( 'not_allowed', __( 'This client is not allowed.', 'oauth2' ), 403 );
		}

		return Client::save_cimd( $url, $result, $fetched['expires'], 'auto' === $policy ? 'publish' : 'draft' );
	} finally {
		release_lock( $url, $lock );
	}
}

/**
 * Print where a CIMD client comes from, for the consent screen.
 *
 * Shows the host of the client ID and of the redirect URI, and warns when the
 * redirect URI is on this device.
 *
 * @param Client      $client       Client being authorised.
 * @param string|null $redirect_uri Redirect URI of the request.
 */
function render_origin_notice( Client $client, $redirect_uri = null ) {
	if ( ! $client->is_cimd() ) {
		return;
	}

	$client_host = (string) wp_parse_url( $client->get_id(), PHP_URL_HOST );
	if ( '' !== $client_host ) {
		printf(
			'<p class="login-origin" style="margin-bottom: 16px;">%s</p>',
			wp_kses(
				sprintf(
					/* translators: %s: host name of the client ID URL */
					__( 'This app is published at %s.', 'oauth2' ),
					'<strong>' . esc_html( $client_host ) . '</strong>'
				),
				[ 'strong' => [] ]
			)
		);
	}

	$redirect_host = is_string( $redirect_uri ) ? (string) wp_parse_url( $redirect_uri, PHP_URL_HOST ) : '';
	if ( '' === $redirect_host ) {
		return;
	}

	printf(
		'<p class="login-origin" style="margin-bottom: 16px;">%s</p>',
		wp_kses(
			sprintf(
				/* translators: %s: host name of the redirect URI */
				__( 'After you approve, you will be sent to %s.', 'oauth2' ),
				'<strong>' . esc_html( $redirect_host ) . '</strong>'
			),
			[ 'strong' => [] ]
		)
	);

	if ( is_loopback_host( $redirect_host ) ) {
		printf(
			'<p class="login-origin login-origin-warning" style="margin-bottom: 16px;"><strong>%s</strong></p>',
			esc_html__( 'This app will run on this device. Only continue if you started it yourself.', 'oauth2' )
		);
	}
}
