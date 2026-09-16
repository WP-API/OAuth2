<?php
/**
 *
 * @package WordPress
 * @subpackage JSON API
 */

namespace WP\OAuth2\Well_Known;

use WP\OAuth2;
use WP_REST_Response;

/**
 * Register well-known discovery hooks.
 */
function bootstrap() {
	add_action( 'init', __NAMESPACE__ . '\\maybe_exempt_login_wall', 998 );
	add_action( 'parse_request', __NAMESPACE__ . '\\maybe_serve_document' );
	add_filter( 'rest_post_dispatch', __NAMESPACE__ . '\\add_www_authenticate_header' );
}

/**
 * Removes any configured login-wall callbacks from `.well-known/` requests,
 * so unauthenticated OAuth2 clients can reach the discovery documents.
 *
 * No-ops on sites that don't run one of the filtered plugins.
 */
function maybe_exempt_login_wall() {
	if ( strpos( $_SERVER['REQUEST_URI'] ?? '', '/.well-known/' ) !== 0 ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		return;
	}

	/**
	 * Filter the login-wall callbacks to remove for `.well-known/` requests.
	 *
	 * Sites that gate the whole site behind a login wall (via a plugin
	 * hooked to e.g. `init`) can use this to let unauthenticated OAuth2
	 * clients still reach the discovery documents. Empty by default.
	 *
	 * Each entry is a [ hook, function_to_remove, priority ] tuple passed to
	 * remove_action().
	 *
	 * @param array $exemptions Array of remove_action() argument tuples.
	 */
	$exemptions = apply_filters( 'oauth2.well_known_login_wall_exemptions', [] );

	foreach ( $exemptions as list( $hook, $function_to_remove, $priority ) ) {
		remove_action( $hook, $function_to_remove, $priority );
	}
}

/**
 * Intercepts `.well-known/` requests before WordPress tries to match a
 * post/page, and serves the matching discovery document.
 */
function maybe_serve_document() {
	$document = match_well_known_path( $_SERVER['REQUEST_URI'] ?? '' ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput

	if ( 'oauth-authorization-server' === $document ) {
		serve_authorization_server_metadata();
	}

	if ( 'oauth-protected-resource' === $document ) {
		serve_protected_resource_metadata();
	}
}

/**
 * Works out which discovery document, if any, a request URI is asking for.
 *
 * Tolerates a trailing slash: some hosts redirect extensionless GET paths to
 * their trailing-slash form before WordPress runs, and clients following
 * that redirect must still get the document.
 *
 * @param string $request_uri Raw request URI, as in `$_SERVER['REQUEST_URI']`.
 * @return string|null `oauth-authorization-server`, `oauth-protected-resource`, or null.
 */
function match_well_known_path( $request_uri ) {
	$path = untrailingslashit( (string) wp_parse_url( $request_uri, PHP_URL_PATH ) );

	if ( '/.well-known/oauth-authorization-server' === $path ) {
		return 'oauth-authorization-server';
	}

	if ( '/.well-known/oauth-protected-resource' === $path ) {
		return 'oauth-protected-resource';
	}

	return null;
}

/**
 * Outputs the RFC 8414 authorization server metadata document and exits.
 */
function serve_authorization_server_metadata() {
	$metadata = [
		'issuer'                                => home_url(),
		'authorization_endpoint'                => OAuth2\get_authorization_url(),
		'token_endpoint'                        => OAuth2\get_token_url(),
		'grant_types_supported'                 => get_grant_types_supported(),
		'response_types_supported'              => get_response_types_supported(),
		'token_endpoint_auth_methods_supported' => [ 'none', 'client_secret_post', 'client_secret_basic' ],
	];

	/**
	 * Filter the OAuth2 authorization server metadata returned at
	 * `/.well-known/oauth-authorization-server`.
	 *
	 * @param array $metadata RFC 8414 metadata document.
	 */
	$metadata = apply_filters( 'oauth2.well_known_authorization_server_metadata', $metadata );

	send_json_document( $metadata );
}

/**
 * Gets the grant types the token endpoint accepts.
 *
 * Combines the registered authorization grant type handlers with
 * `client_credentials`, which the token endpoint supports directly rather
 * than through the `oauth2.grant_types` filter.
 *
 * @return string[] Grant type identifiers.
 */
function get_grant_types_supported() {
	$grant_types   = array_keys( OAuth2\get_grant_types() );
	$grant_types[] = 'client_credentials';

	return array_values( array_unique( $grant_types ) );
}

/**
 * Gets the response types advertised by the registered grant type handlers.
 *
 * @return string[] Response type codes, e.g. `code`, `token`.
 */
function get_response_types_supported() {
	$response_types = [];

	foreach ( OAuth2\get_grant_types() as $handler ) {
		$response_types[] = $handler->get_response_type_code();
	}

	return array_values( array_unique( $response_types ) );
}

/**
 * Outputs the RFC 9728 protected resource metadata document and exits.
 */
function serve_protected_resource_metadata() {
	$metadata = [
		'resource'              => home_url(),
		'authorization_servers' => [ home_url() ],
	];

	/**
	 * Filter the OAuth2 protected resource metadata returned at
	 * `/.well-known/oauth-protected-resource`.
	 *
	 * @param array $metadata RFC 9728 metadata document.
	 */
	$metadata = apply_filters( 'oauth2.well_known_protected_resource_metadata', $metadata );

	send_json_document( $metadata );
}

/**
 * Sends a JSON discovery document and exits.
 *
 * @param array $document Data to encode as the response body.
 */
function send_json_document( $document ) {
	header( 'Content-Type: application/json' );
	header( 'Access-Control-Allow-Origin: *' );
	echo wp_json_encode( $document );
	exit;
}

/**
 * Adds a WWW-Authenticate header to 401 REST responses, so OAuth2 clients
 * can discover the protected resource metadata document after a failed or
 * missing bearer token challenge.
 *
 * Applies to any REST response, not just this plugin's own endpoints, since
 * a 401 on a bearer-protected route is exactly the case this document exists
 * to resolve.
 *
 * @param WP_REST_Response $response Result to send to the client.
 * @return WP_REST_Response
 */
function add_www_authenticate_header( WP_REST_Response $response ) {
	if ( $response->get_status() !== 401 ) {
		return $response;
	}

	$resource_metadata_url = home_url( '/.well-known/oauth-protected-resource' );
	$response->header( 'WWW-Authenticate', "Bearer resource_metadata=\"{$resource_metadata_url}\"" );

	return $response;
}
