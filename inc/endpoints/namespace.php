<?php
/**
 *
 * @package WordPress
 * @subpackage JSON API
 */

namespace WP\OAuth2\Endpoints;

use WP\OAuth2;
use WP_REST_Request;
use WP_REST_Response;

/**
 * Register OAuth-specific endpoints.
 */
function register() {
	$token_endpoint = new Token();
	$token_endpoint->register_routes();

	// Register convenience URL.
	register_rest_route(
		'oauth2',
		'/authorize',
		[
			'methods'  => 'GET',
			'callback' => __NAMESPACE__ . '\\redirect_to_authorize',
		]
	);
}

/**
 * Handle authorize endpoint request.
 *
 * This endpoint exists as a convenience URL to avoid clients needing to find
 * wp-login.php.
 *
 * @param WP_REST_Request $request Request object.
 * @return WP_REST_Response Response object.
 */
function redirect_to_authorize( WP_REST_Request $request ) {
	$url = OAuth2\get_authorization_url();

	$query = $request->get_query_params();
	if ( ! empty( $query ) ) {
		// Pass query arguments along.
		$url = add_query_arg(
			urlencode_deep( $query ),
			$url
		);
	}

	return new WP_REST_Response( [ 'url' => $url ], 302, [ 'Location' => $url ] );
}
