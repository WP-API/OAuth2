<?php
/**
 *
 * @package WordPress
 * @subpackage JSON API
 */

namespace WP\OAuth2\Endpoints;

use WP_Error;
use WP_Http;
use WP\OAuth2;
use WP_REST_Request;

/**
 * Token endpoint handler.
 */
class Token {
	public function register_routes() {
		register_rest_route(
			'oauth2',
			'/access_token',
			[
				'methods'  => 'POST',
				'callback' => [ $this, 'exchange_token' ],
				'args'     => [
					'grant_type' => [
						'required'          => true,
						'type'              => 'string',
						'validate_callback' => [ $this, 'validate_grant_type' ],
					],
					'client_id'  => [
						'required'          => true,
						'type'              => 'string',
						'validate_callback' => 'rest_validate_request_arg',
					],
					'code'       => [
						'required'          => true,
						'type'              => 'string',
						'validate_callback' => 'rest_validate_request_arg',
					],
				],
			]
		);
	}

	/**
	 * Validates the given grant type.
	 *
	 * @param string $type Grant type.
	 *
	 * @return bool Whether or not the grant type is valid.
	 */
	public function validate_grant_type( $type ) {
		return 'authorization_code' === $type;
	}

	/**
	 * Validates the token given in the request, and issues a new token for the user.
	 *
	 * @param WP_REST_Request $request Request object.
	 *
	 * @return array|WP_Error Token data on success, or error on failure.
	 */
	public function exchange_token( WP_REST_Request $request ) {
		$client = OAuth2\get_client( $request['client_id'] );
		if ( empty( $client ) ) {
			return new WP_Error(
				'oauth2.endpoints.token.exchange_token.invalid_client',
				/* translators: %s: client ID */
				sprintf( __( 'Client ID %s is invalid.', 'oauth2' ), $request['client_id'] ),
				[
					'status'    => WP_Http::BAD_REQUEST,
					'client_id' => $request['client_id'],
				]
			);
		}

		$auth_code = $client->get_authorization_code( $request['code'] );
		if ( is_wp_error( $auth_code ) ) {
			return $auth_code;
		}

		$is_valid = $auth_code->validate();
		if ( is_wp_error( $is_valid ) ) {
			// Invalid request, but code itself exists, so we should delete
			// (and silently ignore errors).
			$auth_code->delete();

			return $is_valid;
		}

		// Looks valid, delete the code and issue a token.
		$user = $auth_code->get_user();
		if ( is_wp_error( $user ) ) {
			return $user;
		}

		$did_delete = $auth_code->delete();
		if ( is_wp_error( $did_delete ) ) {
			return $did_delete;
		}

		$token = $client->issue_token( $user );
		if ( is_wp_error( $token ) ) {
			return $token;
		}

		$data = [
			'access_token' => $token->get_key(),
			'token_type'   => 'bearer',
		];
		return $data;
	}
}
