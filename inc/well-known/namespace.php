<?php
/**
 *
 * @package WordPress
 * @subpackage JSON API
 */

namespace WP\OAuth2\Well_Known;

use WP\OAuth2;

const AUTHORIZATION_SERVER_DOCUMENT = 'oauth-authorization-server';
const AUTHORIZATION_SERVER_PATH     = '/.well-known/' . AUTHORIZATION_SERVER_DOCUMENT;

/**
 * Intercepts `.well-known/` requests before WordPress tries to match a
 * post/page, and serves the matching discovery document.
 */
function maybe_serve_document() {
	$document = match_well_known_path( $_SERVER['REQUEST_URI'] ?? '' ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput

	if ( AUTHORIZATION_SERVER_DOCUMENT === $document ) {
		serve_authorization_server_metadata();
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
 * @return string|null `oauth-authorization-server`, or null.
 */
function match_well_known_path( $request_uri ) {
	$path = untrailingslashit( (string) wp_parse_url( $request_uri, PHP_URL_PATH ) );

	if ( AUTHORIZATION_SERVER_PATH === $path ) {
		return AUTHORIZATION_SERVER_DOCUMENT;
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
