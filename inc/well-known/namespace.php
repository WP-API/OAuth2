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
const PROTECTED_RESOURCE_DOCUMENT   = 'oauth-protected-resource';
const PROTECTED_RESOURCE_PATH       = '/.well-known/' . PROTECTED_RESOURCE_DOCUMENT;

/**
 * Gets the discovery documents this plugin serves.
 *
 * Keys are well-known document names, values are handlers that receive the
 * matched request path and either send a document or return.
 *
 * @return callable[] Map of document name to handler.
 */
function get_documents() {
	$documents = [
		AUTHORIZATION_SERVER_DOCUMENT => __NAMESPACE__ . '\\serve_authorization_server_document',
		PROTECTED_RESOURCE_DOCUMENT   => __NAMESPACE__ . '\\serve_protected_resource_document',
	];

	/**
	 * Filter the well-known discovery documents this plugin serves.
	 *
	 * @param callable[] $documents Map of document name to handler.
	 */
	return apply_filters( 'oauth2.well_known_documents', $documents );
}

/**
 * Intercepts `.well-known/` requests before WordPress tries to match a
 * post/page, and serves the matching discovery document.
 *
 * The request only gets this far if the server sends unknown paths to
 * WordPress. Pretty permalinks arrange that on Apache; nginx setups usually
 * do it whatever the permalink setting is.
 */
function maybe_serve_document() {
	$request_uri = $_SERVER['REQUEST_URI'] ?? ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput

	foreach ( get_documents() as $document => $handler ) {
		$matched = match_well_known_path( $request_uri, '/.well-known/' . $document );

		if ( null === $matched ) {
			continue;
		}

		// Handlers exit once they have sent a document. Returning lets
		// WordPress carry on and 404 the request.
		$handler( $matched );
		return;
	}
}

/**
 * Serves the RFC 8414 authorization server metadata document.
 *
 * @param string $site_path Path of the site being asked about, with a trailing slash.
 */
function serve_authorization_server_document( $site_path ) {
	$site_id = get_site_id_by_path( $site_path );

	if ( null === $site_id ) {
		return;
	}

	send_json_document( get_metadata_for_site( $site_id ) );
}

/**
 * Works out which path, if any, a request URI is asking for metadata about.
 *
 * The well-known path goes in front of the path being described, so a site at
 * `https://example.com/blog` publishes its metadata at
 * `https://example.com/.well-known/oauth-authorization-server/blog`. On a
 * subdirectory network that request lands on the root site, which then has
 * to answer for the subsite.
 *
 * The site's own path is matched too: that is the form OpenID Connect
 * clients ask for, and it is the only one a site in a subdirectory can
 * answer without owning the domain root.
 *
 * The returned path is always measured from the domain root, whichever form
 * was used, so callers get the same answer either way. What that path means
 * depends on the document: RFC 8414 describes a site, RFC 9728 a resource.
 *
 * Tolerates a trailing slash: some hosts redirect extensionless GET paths to
 * their trailing-slash form before WordPress runs, and clients following
 * that redirect must still get the document.
 *
 * @param string $request_uri     Raw request URI, as in `$_SERVER['REQUEST_URI']`.
 * @param string $well_known_path Well-known path to match, e.g. `/.well-known/oauth-authorization-server`.
 * @return string|null Path being asked about, with a trailing slash, or null if this isn't a metadata request.
 */
function match_well_known_path( $request_uri, $well_known_path = AUTHORIZATION_SERVER_PATH ) {
	$path         = untrailingslashit( (string) wp_parse_url( $request_uri, PHP_URL_PATH ) );
	$current_path = get_current_site_path();
	$site_prefix  = untrailingslashit( $current_path ) . $well_known_path;

	// The site's own path, e.g. `/blog/.well-known/oauth-protected-resource`.
	if ( $site_prefix === $path ) {
		return $current_path;
	}

	if ( strpos( $path, $site_prefix . '/' ) === 0 ) {
		return trailingslashit( untrailingslashit( $current_path ) . substr( $path, strlen( $site_prefix ) ) );
	}

	// The domain root, e.g. `/.well-known/oauth-protected-resource/blog`.
	if ( strpos( $path, $well_known_path . '/' ) === 0 ) {
		return trailingslashit( substr( $path, strlen( $well_known_path ) ) );
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
		'code_challenge_methods_supported'      => OAuth2\PKCE::supported_methods(),
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
