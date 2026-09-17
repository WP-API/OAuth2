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
	$site_path = match_well_known_path( $_SERVER['REQUEST_URI'] ?? '' ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput

	if ( null === $site_path ) {
		return;
	}

	$site_id = get_site_id_by_path( $site_path );

	if ( null === $site_id ) {
		return;
	}

	send_json_document( get_metadata_for_site( $site_id ) );
}

/**
 * Works out which site, if any, a request URI is asking for metadata about.
 *
 * RFC 8414 puts the well-known path in front of the site's own path, so a
 * site at `https://example.com/blog` publishes its metadata at
 * `https://example.com/.well-known/oauth-authorization-server/blog`. On a
 * subdirectory network that request lands on the root site, which then has
 * to answer for the subsite.
 *
 * The site's own path is matched too: that is the form OpenID Connect
 * clients ask for, and it is the only one a site in a subdirectory can
 * answer without owning the domain root.
 *
 * Tolerates a trailing slash: some hosts redirect extensionless GET paths to
 * their trailing-slash form before WordPress runs, and clients following
 * that redirect must still get the document.
 *
 * @param string $request_uri Raw request URI, as in `$_SERVER['REQUEST_URI']`.
 * @return string|null Path of the site being asked about, or null if this isn't a metadata request.
 */
function match_well_known_path( $request_uri ) {
	$path         = untrailingslashit( (string) wp_parse_url( $request_uri, PHP_URL_PATH ) );
	$current_path = get_current_site_path();

	if ( untrailingslashit( $current_path ) . AUTHORIZATION_SERVER_PATH === $path ) {
		return $current_path;
	}

	if ( strpos( $path, AUTHORIZATION_SERVER_PATH . '/' ) === 0 ) {
		return trailingslashit( substr( $path, strlen( AUTHORIZATION_SERVER_PATH ) ) );
	}

	return null;
}

/**
 * Gets the path the current site is served from, e.g. `/` or `/blog/`.
 *
 * @return string Site path, with a trailing slash.
 */
function get_current_site_path() {
	return (string) wp_parse_url( home_url( '/' ), PHP_URL_PATH );
}

/**
 * Finds the site served from a given path.
 *
 * @param string $site_path Site path, with a trailing slash.
 * @return int|null Site ID, or null if no site is served from that path.
 */
function get_site_id_by_path( $site_path ) {
	if ( ! is_multisite() ) {
		return get_current_site_path() === $site_path ? get_current_blog_id() : null;
	}

	$sites = get_sites(
		[
			'domain' => get_site()->domain,
			'path'   => $site_path,
			'number' => 1,
			'fields' => 'ids',
		]
	);

	if ( empty( $sites ) ) {
		return null;
	}

	return (int) $sites[0];
}

/**
 * Gets the metadata document describing a site on the network.
 *
 * @param int $site_id Site to describe.
 * @return array RFC 8414 metadata document.
 */
function get_metadata_for_site( $site_id ) {
	if ( ! is_multisite() || get_current_blog_id() === $site_id ) {
		return get_authorization_server_metadata();
	}

	switch_to_blog( $site_id );
	$metadata = get_authorization_server_metadata();
	restore_current_blog();

	return $metadata;
}

/**
 * Builds the RFC 8414 authorization server metadata document.
 *
 * @return array Metadata describing the current site.
 */
function get_authorization_server_metadata() {
	$metadata = [
		'issuer'                                => home_url(),
		'authorization_endpoint'                => OAuth2\get_authorization_url(),
		'token_endpoint'                        => OAuth2\get_token_url(),
		'grant_types_supported'                 => get_grant_types_supported(),
		'response_types_supported'              => get_response_types_supported(),
		'token_endpoint_auth_methods_supported' => [ 'none', 'client_secret_post', 'client_secret_basic' ],
	];

	/**
	 * Filter the OAuth2 authorization server metadata for a site.
	 *
	 * @param array $metadata RFC 8414 metadata document.
	 */
	return apply_filters( 'oauth2.well_known_authorization_server_metadata', $metadata );
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
