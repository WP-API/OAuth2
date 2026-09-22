<?php
/**
 *
 * @package WordPress
 * @subpackage JSON API
 */

namespace WP\OAuth2\Well_Known;

/**
 * Longest resource path, in segments, that a site is looked up for.
 *
 * Bounds the lookup for deeply nested request paths.
 */
const MAX_PATH_SEGMENTS = 10;

/**
 * Serves the RFC 9728 protected resource metadata document.
 *
 * @param string $resource_path Path of the resource being asked about, with a trailing slash.
 */
function serve_protected_resource_document( $resource_path ) {
	$resource = split_resource_path( $resource_path );

	if ( null === $resource ) {
		return;
	}

	send_json_document( get_protected_resource_metadata_for_site( $resource['site_id'], $resource['sub_path'] ) );
}

/**
 * Splits a requested resource path into the site serving it and the rest.
 *
 * A resource path covers a site path and the path of the resource within that
 * site, e.g. `/blog/wp-json/mcp`. Only the site knows where its own REST API
 * lives, so the site has to be resolved first and the remainder checked
 * against it afterwards.
 *
 * Paths outside a site's REST API are rejected, apart from the site root
 * itself, so this doesn't answer for arbitrary URLs on the domain.
 *
 * @param string $resource_path Path of the resource being asked about.
 * @return array|null Site ID, site path and site-relative resource path, or null if nothing serves that path.
 */
function split_resource_path( $resource_path ) {
	$path = '/' . trim( (string) $resource_path, '/' );
	$site = resolve_site_by_path_prefix( get_ancestor_paths( $path ) );

	if ( null === $site ) {
		return null;
	}

	$sub_path = '/' . ltrim( substr( $path, strlen( untrailingslashit( $site['path'] ) ) ), '/' );

	if ( '/' !== $sub_path ) {
		$rest_base = get_rest_base_sub_path( $site['id'] );

		// Plain permalinks put the REST route in a query string, so there is
		// no REST path for a resource to sit under.
		if ( '' === $rest_base ) {
			return null;
		}

		// The REST base has to end on a path segment. Matching it as a bare
		// prefix would also accept `/wp-jsonx`.
		if ( $sub_path !== $rest_base && strpos( $sub_path, trailingslashit( $rest_base ) ) !== 0 ) {
			return null;
		}
	}

	return [
		'site_id'   => $site['id'],
		'site_path' => $site['path'],
		'sub_path'  => untrailingslashit( $sub_path ),
	];
}

/**
 * Lists a path and each of its parents, longest first.
 *
 * @param string $path Path to walk up from.
 * @return string[] Paths, each with a trailing slash, ending with `/`.
 */
function get_ancestor_paths( $path ) {
	$paths    = [];
	$segments = array_values( array_filter( explode( '/', trim( $path, '/' ) ), 'strlen' ) );
	$segments = array_slice( $segments, 0, MAX_PATH_SEGMENTS );

	while ( ! empty( $segments ) ) {
		$paths[] = '/' . implode( '/', $segments ) . '/';
		array_pop( $segments );
	}

	$paths[] = '/';

	return $paths;
}

/**
 * Finds the site serving the longest of the given paths.
 *
 * @param string[] $candidate_paths Paths to match, each with a trailing slash.
 * @return array|null Site ID and path, or null if no site serves any of them.
 */
function resolve_site_by_path_prefix( array $candidate_paths ) {
	if ( ! is_multisite() ) {
		$current_path = get_current_site_path();

		if ( ! in_array( $current_path, $candidate_paths, true ) ) {
			return null;
		}

		return [
			'id'   => get_current_blog_id(),
			'path' => $current_path,
		];
	}

	$sites = get_sites(
		[
			'domain'                 => get_site()->domain,
			'path__in'               => $candidate_paths,
			'number'                 => count( $candidate_paths ),
			'update_site_meta_cache' => false,
		]
	);

	if ( empty( $sites ) ) {
		return null;
	}

	usort(
		$sites,
		function ( $a, $b ) {
			return strlen( $b->path ) <=> strlen( $a->path );
		}
	);

	return [
		'id'   => (int) $sites[0]->blog_id,
		'path' => $sites[0]->path,
	];
}

/**
 * Gets where a site's REST API sits within that site.
 *
 * A site without pretty permalinks has no REST path at all, so only its root
 * can be described as a resource.
 *
 * @param int $site_id Site to look up.
 * @return string Site-relative REST path, e.g. `/wp-json`, or an empty string when the site has no REST path.
 */
function get_rest_base_sub_path( $site_id ) {
	$switched = false;

	if ( is_multisite() && get_current_blog_id() !== (int) $site_id ) {
		switch_to_blog( $site_id );
		$switched = true;
	}

	$rest_url  = rest_url( '/' );
	$home_path = untrailingslashit( (string) wp_parse_url( home_url( '/' ), PHP_URL_PATH ) );

	if ( $switched ) {
		restore_current_blog();
	}

	// Plain permalinks address routes with a query argument, e.g.
	// `?rest_route=/`, leaving no path to describe a resource with.
	if ( ! empty( wp_parse_url( $rest_url, PHP_URL_QUERY ) ) ) {
		return '';
	}

	$rest_path = untrailingslashit( (string) wp_parse_url( $rest_url, PHP_URL_PATH ) );

	return substr( $rest_path, strlen( $home_path ) );
}

/**
 * Gets the metadata document describing a resource on a site.
 *
 * @param int    $site_id  Site serving the resource.
 * @param string $sub_path Site-relative path of the resource.
 * @return array RFC 9728 metadata document.
 */
function get_protected_resource_metadata_for_site( $site_id, $sub_path = '' ) {
	if ( ! is_multisite() || get_current_blog_id() === (int) $site_id ) {
		return get_protected_resource_metadata( $sub_path );
	}

	switch_to_blog( $site_id );
	$metadata = get_protected_resource_metadata( $sub_path );
	restore_current_blog();

	return $metadata;
}

/**
 * Builds the RFC 9728 protected resource metadata document.
 *
 * @param string $sub_path Site-relative path of the resource, e.g. `/wp-json`.
 * @return array Metadata describing the resource.
 */
function get_protected_resource_metadata( $sub_path = '' ) {
	$metadata = [
		'resource'                 => untrailingslashit( home_url( $sub_path ) ),
		'authorization_servers'    => [ home_url() ],
		'bearer_methods_supported' => get_bearer_methods_supported(),
	];

	// The stored name is HTML-escaped, and display mode would texturise it on
	// top. This document is JSON, so decode it the way core does for other
	// non-HTML output.
	$name = wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES );

	if ( ! empty( $name ) ) {
		$metadata['resource_name'] = $name;
	}

	/**
	 * Filter the OAuth2 protected resource metadata for a resource.
	 *
	 * @param array  $metadata RFC 9728 metadata document.
	 * @param string $sub_path Site-relative path of the resource being described.
	 */
	return apply_filters( 'oauth2.well_known_protected_resource_metadata', $metadata, $sub_path );
}

/**
 * Gets the ways a client can present an access token.
 *
 * Tokens are read from the `Authorization` header and the `access_token`
 * query argument. Form bodies are not checked, so `body` is not advertised.
 *
 * @return string[] Bearer token methods, as defined by RFC 6750.
 */
function get_bearer_methods_supported() {
	return [ 'header', 'query' ];
}

/**
 * Builds the URL a resource's metadata document is published at.
 *
 * The URL sits under the site rather than the domain root, so it is reachable
 * whether or not WordPress owns the domain root. Both forms are served, and
 * they are the same URL for a site at the domain root.
 *
 * @param string|null $sub_path Site-relative resource path, or null for the site's REST API root.
 * @return string Metadata document URL.
 */
function get_protected_resource_metadata_url( $sub_path = null ) {
	if ( null === $sub_path ) {
		$sub_path = get_rest_base_sub_path( get_current_blog_id() );
	}

	return untrailingslashit( home_url( PROTECTED_RESOURCE_PATH . $sub_path ) );
}
