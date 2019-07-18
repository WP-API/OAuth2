<?php
/**
 *
 * @package    WordPress
 * @subpackage JSON API
 */

namespace WP\OAuth2;

use WP\OAuth2\Types\Type;
use WP_REST_Response;

function bootstrap() {
	// Core authentication hooks.
	add_action( 'init', __NAMESPACE__ . '\\Client::register_type' );
	add_filter( 'determine_current_user', __NAMESPACE__ . '\\Authentication\\attempt_authentication', 11 );

	// REST API integration.
	add_filter( 'rest_authentication_errors', __NAMESPACE__ . '\\Authentication\\maybe_report_errors' );
	add_filter( 'rest_index', __NAMESPACE__ . '\\register_in_index' );
	add_action( 'rest_api_init', __NAMESPACE__ . '\\Endpoints\\register' );

	// Internal default hooks.
	add_filter( 'oauth2.grant_types', __NAMESPACE__ . '\\register_grant_types', 0 );

	// Admin-related.
	add_action( 'init', __NAMESPACE__ . '\\rest_oauth2_load_authorize_page' );
	add_action( 'admin_menu', __NAMESPACE__ . '\\Admin\\register' );
	Admin\Profile\bootstrap();
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
 * @return Type[] Map of grant type to handler object.
 */
function get_grant_types() {

	/**
	 * Filter valid grant types.
	 *
	 * Default supported grant types are added in register_grant_types().
	 * Note that additional grant types must follow the extension policy in the
	 * OAuth 2 specification.
	 *
	 * @param Type[] $grant_types Map of grant type to handler object.
	 */
	$grant_types = apply_filters( 'oauth2.grant_types', [] );

	foreach ( $grant_types as $type => $handler ) {
		if ( ! $handler instanceof Type ) {
			/* translators: 1: Grant type name, 2: Grant type interface */
			$message = esc_html__( 'Skipping invalid grant type "%1$s". Required interface "%1$s" not implemented.', 'oauth2' );
			_doing_it_wrong( __FUNCTION__, sprintf( esc_html( $message ), esc_html( $type ), 'WP\\OAuth2\\Types\\Type' ), '0.1.0' );
			unset( $grant_types[ $type ] );
		}
	}

	return $grant_types;
}

/**
 * Register default grant types.
 *
 * Callback for the oauth2.grant_types hook.
 *
 * @param array $types Existing grant types.
 *
 * @return array Grant types with additional types registered.
 */
function register_grant_types( $types ) {
	$types['authorization_code'] = new Types\Authorization_Code();
	$types['implicit']           = new Types\Implicit();

	return $types;
}

/**
 * Register the OAuth 2 authentication scheme in the API index.
 *
 * @param WP_REST_Response $response Index response object.
 *
 * @return WP_REST_Response Update index repsonse object.
 */
function register_in_index( WP_REST_Response $response ) {
	$data = $response->get_data();

	$data['authentication']['oauth2'] = [
		'endpoints'   => [
			'authorization' => get_authorization_url(),
			'token'         => get_token_url(),
		],
		'grant_types' => array_keys( get_grant_types() ),
	];

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
	$url = rest_url( 'oauth2/access_token' );

	/**
	 * Filter the token URL.
	 *
	 * @param string $url URL for the OAuth 2 token endpoint.
	 */
	return apply_filters( 'oauth2.get_token_url', $url );
}

/**
 * Get a client by ID.
 *
 * @param string $id ID for the client.
 *
 * @return ClientInterface Client instance.
 */
function get_client( $id ) {
	if ( PersonalClient::ID === $id ) {
		return PersonalClient::get_instance();
	}

	return Client::get_by_id( $id );
}
