<?php
/**
 * Plugin Name: OAuth 2 for WordPress
 * Description: Connect apps to your site using OAuth 2.
 * Version: 0.1.0
 * Author: WordPress Core Contributors (REST API Focus)
 * Author URI: https://make.wordpress.org/core/
 */

namespace WP\OAuth2;

use WP_REST_Response;

bootstrap();

function bootstrap() {
	load();

	// Core authentication hooks.
	add_filter( 'determine_current_user', __NAMESPACE__ . '\\Authentication\\attempt_authentication', 11 );
	add_filter( 'rest_authentication_errors', __NAMESPACE__ . '\\Authentication\\maybe_report_errors' );

	// Internal default hooks.
	add_filter( 'oauth2.grant_types', __NAMESPACE__ . '\\register_grant_types', 0 );

	// Admin-related.
	add_action( 'init', __NAMESPACE__ . '\\rest_oauth2_load_authorize_page' );
	add_action( 'admin_menu', array( __NAMESPACE__ . '\\admin\\Admin', 'register' ) );
}

function load() {
	require __DIR__ . '/inc/class-client.php';
	require __DIR__ . '/inc/class-scopes.php';
	require __DIR__ . '/inc/authentication/namespace.php';
	require __DIR__ . '/inc/endpoints/class-authorization.php';
	require __DIR__ . '/inc/tokens/namespace.php';
	require __DIR__ . '/inc/tokens/class-token.php';
	require __DIR__ . '/inc/tokens/class-access-token.php';
	require __DIR__ . '/inc/types/class-type.php';
	require __DIR__ . '/inc/types/class-base.php';
	require __DIR__ . '/inc/types/class-authorization-code.php';
	require __DIR__ . '/inc/types/class-implicit.php';
	require __DIR__ . '/inc/admin/class-admin.php';
}

/**
 * Register the authorization page
 *
 * Alas, login_init is too late to register pages, as the action is already
 * sanitized before this.
 */
function rest_oauth2_load_authorize_page() {
	$authorizer = new Endpoints\Authorization();
	$authorizer->register_hooks();
}

/**
 * Get valid grant types.
 *
 * @return array Map of grant type to handler object.
 */
function get_grant_types() {
	/**
	 * Filter valid grant types.
	 *
	 * Default supported grant types are added in register_grant_types().
	 * Note that additional grant types must follow the extension policy in the
	 * OAuth 2 specification.
	 *
	 * @param array $grant_types Map of grant type to handler object.
	 */
	return apply_filters( 'oauth2.grant_types', array() );
}

/**
 * Register default grant types.
 *
 * Callback for the oauth2.grant_types hook.
 *
 * @param array Existing grant types.
 * @return array Grant types with additional types registered.
 */
function register_grant_types( $types ) {
	$types['authorization_code'] = new Types\AuthorizationCode();
	$types['implicit'] = new Types\Implicit();

	return $types;
}

/**
 * Register the OAuth 2 authentication scheme in the API index.
 *
 * @param WP_REST_Response $response Index response object.
 * @return WP_REST_Response Update index repsonse object.
 */
function register_in_index( WP_REST_Response $response ) {
	$data = $response->get_data();

	$data['authentication']['oauth2'] = array(
		'endpoints' => array(
			'authorization' => get_authorization_url(),
			'token' => get_token_url(),
		),
		'grant_types' => array_keys( get_grant_types() ),
	);

	$response->set_data( $data );
	return $response;
}

/**
 * Get the authorization endpoint URL.
 *
 * @return string URL for the OAuth 2 authorization endpoint.
 */
function get_authorization_url() {
	$url = wp_login_url();
	$url = add_query_arg( 'action', 'oauth2_authorize', $url );

	/**
	 * Filter the authorization URL.
	 *
	 * @param string $url URL for the OAuth 2 authorization endpoint.
	 */
	return apply_filters( 'oauth2.get_authorization_url', $url );
}

/**
 * Get the token endpoint URL.
 *
 * @return string URL for the OAuth 2 token endpoint.
 */
function get_token_url() {
	$url = rest_url( 'oauth2/token' );

	/**
	 * Filter the token URL.
	 *
	 * @param string $url URL for the OAuth 2 token endpoint.
	 */
	return apply_filters( 'oauth2.get_token_url', $url );
}
