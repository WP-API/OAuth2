<?php

namespace WP\OAuth2\Endpoints;

use WP_Error;
use WP_Http;
use WP\OAuth2\Client;
use WP_REST_Request;

/**
 * Token endpoint handler.
 */
class Token {
	public function register_routes() {
		register_rest_route( 'oauth2', '/access_token', array(
			'methods' => 'POST',
			'callback' => array( $this, 'exchange_token' ),
			'args' => array(
				'grant_type' => array(
					'required' => true,
					'type' => 'string',
					'validate_callback' => array( $this, 'validate_grant_type' ),
				),
				'client_id' => array(
					'required' => true,
					'type' => 'string',
					'validate_callback' => 'rest_validate_request_arg',
				),
				'code' => array(
					'required' => true,
					'type' => 'string',
					'validate_callback' => 'rest_validate_request_arg',
				),
			),
		));
	}

	/**
	 * Validates the given grant type.
	 *
	 * @param string $type Grant type.
	 *
	 * @return bool Whether or not the grant type is valid.
	 */
	public function validate_grant_type( $type ) {
		return $type === 'authorization_code';
	}

	/**
	 * Validates the token given in the request, and issues a new token for the user.
	 *
	 * @param WP_REST_Request $request Request object.
	 *
	 * @return array|WP_Error Token data on success, or error on failure.
	 */
	public function exchange_token( WP_REST_Request $request ) {
		// Check headers for client authentication.
		// https://tools.ietf.org/html/rfc6749#section-2.3.1
		if ( isset( $_SERVER['PHP_AUTH_USER'] ) ) {
			$client_id = $_SERVER['PHP_AUTH_USER'];
			$client_secret = $_SERVER['PHP_AUTH_PW'];
		} else {
			$client_id = $request['client_id'];
			$client_secret = $request['client_secret'];
		}

		if ( empty( $client_id ) ) {
			// invalid_client
			return new WP_Error(
				'oauth2.endpoints.token.exchange_token.no_client_id',
				__( 'Missing client ID.'),
				array(
					'status' => WP_Http::UNAUTHORIZED,
				)
			);
		}

		$client = Client::get_by_id( $client_id );
		if ( empty( $client ) ) {
			return new WP_Error(
				'oauth2.endpoints.token.exchange_token.invalid_client',
				sprintf( __( 'Client ID %s is invalid.', 'oauth2' ), $client_id ),
				array(
					'status' => WP_Http::BAD_REQUEST,
					'client_id' => $client_id,
				)
			);
		}

		if ( $client->requires_secret() ) {
			// Confidential client, secret must be verified.
			if ( empty( $client_secret ) ) {
				// invalid_request
				return new WP_Error(
					'oauth2.endpoints.token.exchange_token.secret_required',
					__( 'Secret is required for confidential clients.', 'oauth2' ),
					array(
						'status' => WP_Http::UNAUTHORIZED
					)
				);
			}
			if ( ! $client->check_secret( $client_secret ) ) {
				return new WP_Error(
					'oauth2.endpoints.token.exchange_token.invalid_secret',
					__( 'Supplied secret is not valid for the client.', 'oauth2' ),
					array(
						'status' => WP_Http::UNAUTHORIZED
					)
				);
			}
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

		$data = array(
			'access_token' => $token->get_key(),
			'token_type'   => 'bearer',
		);
		return $data;
	}
}
