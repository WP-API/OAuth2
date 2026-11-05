<?php
/**
 * OAuth Client ID Metadata Document (CIMD) support.
 *
 * @package WordPress
 * @subpackage JSON API
 */

namespace WP\OAuth2\CIMD;

use WP_Error;

const MAX_URL_LENGTH     = 2048;
const MAX_DOCUMENT_BYTES = 5120;
const MIN_CACHE_TTL      = 300;
const MAX_CACHE_TTL      = 3600;

const IPV4_BLOCKLIST = [
	'0.0.0.0/8',
	'10.0.0.0/8',
	'100.64.0.0/10',
	'127.0.0.0/8',
	'169.254.0.0/16',
	'172.16.0.0/12',
	'192.0.0.0/24',
	'192.0.2.0/24',
	'192.88.99.0/24',
	'192.168.0.0/16',
	'198.18.0.0/15',
	'198.51.100.0/24',
	'203.0.113.0/24',
	'224.0.0.0/4',
	'240.0.0.0/4',
	'255.255.255.255/32',
];

const IPV6_BLOCKLIST = [
	'::/128',
	'::1/128',
	'::ffff:0:0/96',
	'64:ff9b::/96',
	'64:ff9b:1::/48',
	'100::/64',
	'2001::/23',
	'2001:db8::/32',
	'2002::/16',
	'fc00::/7',
	'fe80::/10',
	'ff00::/8',
];

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

	if ( home_url() === $url || trailingslashit( home_url() ) === $url ) {
		return make_error( 'invalid_client_id', __( 'The client ID URL must not be this site\'s issuer.', 'oauth2' ), 400 );
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

	$ip  = false !== strpos( $ips[0], ':' ) ? '[' . $ips[0] . ']' : $ips[0];
	$pin = static function ( $handle, $args, $request_url ) use ( $url, $host, $port, $ip ) {
		if ( $request_url !== $url ) {
			return;
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.curl_curl_setopt -- Pins the connection to the vetted address.
		curl_setopt( $handle, CURLOPT_RESOLVE, [ "{$host}:{$port}:{$ip}" ] );
	};

	add_action( 'http_api_curl', $pin, 10, 3 );
	try {
		$response = wp_safe_remote_get(
			$url,
			[
				'timeout'             => 5,
				'redirection'         => 0,
				'limit_response_size' => MAX_DOCUMENT_BYTES + 1,
				'sslverify'           => true,
				'reject_unsafe_urls'  => true,
				'cookies'             => [],
				'headers'             => [ 'Accept' => 'application/json' ],
			]
		);
	} finally {
		remove_action( 'http_api_curl', $pin, 10 );
	}

	if ( is_wp_error( $response ) ) {
		return make_error( 'fetch_failed', __( 'The client metadata document could not be fetched.', 'oauth2' ), 503, true );
	}

	if ( 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
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
 * Check that a value is an array containing only strings.
 *
 * @param mixed $value Value to check.
 * @return bool
 */
function is_string_array( $value ) {
	return is_array( $value ) && array_filter( $value, 'is_string' ) === $value;
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
	if ( ! is_string_array( $redirect_uris ) || empty( $redirect_uris ) ) {
		return invalid_document( __( 'The redirect_uris must be a non-empty array of strings.', 'oauth2' ) );
	}

	foreach ( $redirect_uris as $redirect_uri ) {
		$parts = wp_parse_url( $redirect_uri );
		if ( ! is_array( $parts ) || empty( $parts['scheme'] ) || empty( $parts['host'] ) || false !== strpos( $redirect_uri, '#' ) ) {
			return invalid_document( __( 'Each redirect URI must be an absolute URL without a fragment.', 'oauth2' ) );
		}

		$is_https    = 'https' === $parts['scheme'];
		$is_loopback = 'http' === $parts['scheme'] && in_array( $parts['host'], [ 'localhost', '127.0.0.1', '[::1]' ], true );
		if ( ! $is_https && ! $is_loopback ) {
			return invalid_document( __( 'Each redirect URI must use https, or http on a loopback host.', 'oauth2' ) );
		}
	}

	$plural   = $document['token_endpoint_auth_methods_supported'] ?? null;
	$singular = $document['token_endpoint_auth_method'] ?? null;
	if ( is_string_array( $plural ) ) {
		$methods = $plural;
	} elseif ( is_string( $singular ) ) {
		$methods = [ $singular ];
	} else {
		$methods = [ 'none' ];
	}

	if ( is_string_array( $plural ) && is_string( $singular ) && ! in_array( $singular, $plural, true ) ) {
		return invalid_document( __( 'The token_endpoint_auth_method must be listed in token_endpoint_auth_methods_supported.', 'oauth2' ) );
	}

	if ( array_intersect( [ 'client_secret_basic', 'client_secret_post', 'client_secret_jwt' ], $methods ) ) {
		return invalid_document( __( 'Shared-secret client authentication methods are not allowed.', 'oauth2' ) );
	}

	if ( ! in_array( 'none', $methods, true ) ) {
		return invalid_document( __( 'The document must allow the none authentication method.', 'oauth2' ), 'unsupported_auth_method' );
	}

	if ( array_key_exists( 'jwks', $document ) && array_key_exists( 'jwks_uri', $document ) ) {
		return invalid_document( __( 'The document must not contain both jwks and jwks_uri.', 'oauth2' ) );
	}

	if ( isset( $document['jwks']['keys'] ) && is_array( $document['jwks']['keys'] ) ) {
		foreach ( $document['jwks']['keys'] as $key ) {
			if ( is_array( $key ) && array_key_exists( 'd', $key ) ) {
				return invalid_document( __( 'The jwks must not contain private keys.', 'oauth2' ) );
			}
		}
	}

	$grant_types = $document['grant_types'] ?? [ 'authorization_code' ];
	if ( ! is_string_array( $grant_types ) ) {
		return invalid_document( __( 'The grant_types must be an array of strings.', 'oauth2' ) );
	}

	$grant_types = array_values( array_intersect( [ 'authorization_code' ], $grant_types ) );
	if ( empty( $grant_types ) ) {
		return invalid_document( __( 'The grant_types must include authorization_code.', 'oauth2' ) );
	}

	$response_types = $document['response_types'] ?? [ 'code' ];
	if ( ! is_string_array( $response_types ) ) {
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
		'redirect_uris'              => array_values( $redirect_uris ),
		'grant_types'                => $grant_types,
		'response_types'             => $response_types,
		'token_endpoint_auth_method' => 'none',
	];
}
