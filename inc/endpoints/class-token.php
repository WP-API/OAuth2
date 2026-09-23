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
use WP_REST_Response;
/**
 * Token endpoint handler.
 */
class Token {
	public function register_routes() {
		register_rest_route(
			'oauth2',
			'/access_token',
			[
				'methods'             => 'POST',
				'callback'            => [ $this, 'exchange_token' ],
				'permission_callback' => '__return_true',
				'args'                => [
					'grant_type'    => [
						'required'          => true,
						'type'              => 'string',
						'validate_callback' => [ $this, 'validate_grant_type' ],
					],
					'client_id'     => [
						'required'          => false,
						'type'              => 'string',
						'validate_callback' => 'rest_validate_request_arg',
					],
					'code'          => [
						'required'          => false,
						'type'              => 'string',
						'validate_callback' => 'rest_validate_request_arg',
					],
					'client_secret' => [
						'required'          => false,
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
		return in_array( $type, [ 'authorization_code', 'client_credentials' ], true );
	}

	/**
	 * Validates the token given in the request, and issues a new token for the user.
	 *
	 * @param WP_REST_Request $request Request object.
	 *
	 * @return array|WP_Error Token data on success, or error on failure.
	 */
	public function exchange_token( WP_REST_Request $request ) {
		if ( 'client_credentials' === $request['grant_type'] ) {
			return $this->handle_client_credentials( $request );
		}

		// RFC 6749 section 2.3.1: a client may authenticate with HTTP Basic
		// instead of body parameters. Body parameters take precedence.
		$basic = $this->get_basic_auth_credentials( $request );
		if ( is_wp_error( $basic ) ) {
			return $basic;
		}
		if ( null !== $basic ) {
			if ( $this->is_param_empty( $request, 'client_id' ) ) {
				$request->set_param( 'client_id', $basic[0] );
			}

			// Only accept the header secret for the client it names, so a body
			// client_id can still be paired with a Basic secret.
			if ( $this->is_param_empty( $request, 'client_secret' ) && $basic[0] === $request->get_param( 'client_id' ) ) {
				$request->set_param( 'client_secret', $basic[1] );
			}
		}

		// The authorization_code grant requires `client_id` and `code`.
		// These are declared optional at the schema level so they don't
		// apply to client_credentials, so validate presence here. The error
		// shape matches what WP REST API would produce at the schema layer.
		$missing = [];
		foreach ( [ 'client_id', 'code' ] as $required_param ) {
			if ( $this->is_param_empty( $request, $required_param ) ) {
				$missing[] = $required_param;
			}
		}
		if ( ! empty( $missing ) ) {
			return new WP_Error(
				'rest_missing_callback_param',
				/* translators: %s: comma-separated list of missing parameter names. */
				sprintf( __( 'Missing parameter(s): %s', 'oauth2' ), implode( ', ', $missing ) ),
				[
					'status' => WP_Http::BAD_REQUEST,
					'params' => $missing,
				]
			);
		}

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

		// RFC 6749 section 4.1.3: the server must authenticate the client when
		// the client is confidential. Public clients have no secret to check.
		if ( $client->requires_secret() ) {
			$client_secret = (string) $request->get_param( 'client_secret' );
			if ( '' === $client_secret || ! $client->check_secret( $client_secret ) ) {
				return $this->client_authentication_failed( $request );
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

		$data = [
			'access_token' => $token->get_key(),
			'token_type'   => 'bearer',
		];
		return $data;
	}

	/**
	 * Handle client credentials grant type.
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return array|WP_Error Token data on success, or error on failure.
	 */
	private function handle_client_credentials( WP_REST_Request $request ) {
		$credentials = $this->extract_client_credentials( $request );
		if ( is_wp_error( $credentials ) ) {
			return $credentials;
		}

		list( $client_id, $client_secret ) = $credentials;

		// Collapse "client not found", "wrong secret", and "grant disabled"
		// into a single failure path. Distinguishing them in the response
		// would let an attacker confirm a valid client_id/secret pair even
		// when the grant happens to be disabled.
		$client   = OAuth2\get_client( $client_id );
		$creds_ok = $client && $client->check_secret( $client_secret );
		$grant_ok = $client && $client->is_client_credentials_enabled();

		if ( ! $creds_ok || ! $grant_ok ) {
			return $this->client_authentication_failed( $request );
		}

		$token = OAuth2\Tokens\Access_Token::create_for_client( $client );
		if ( is_wp_error( $token ) ) {
			return $token;
		}

		$data = [
			'access_token' => $token->get_key(),
			'token_type'   => 'bearer',
		];

		$expires = $token->get_expiration_time();
		if ( null !== $expires ) {
			$data['expires_in'] = $expires - time();
		}

		return $data;
	}

	/**
	 * Extract client credentials from Authorization header or request body.
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return array|WP_Error Array with client_id and client_secret, or error.
	 */
	private function extract_client_credentials( WP_REST_Request $request ) {
		// Try from request body first (avoids conflict with proxy/HTTP basic auth headers)
		$client_id     = $request->get_param( 'client_id' );
		$client_secret = $request->get_param( 'client_secret' );

		if ( ! empty( $client_id ) && ! empty( $client_secret ) ) {
			return [ $client_id, $client_secret ];
		}

		// Fall back to Basic authentication from Authorization header
		$basic = $this->get_basic_auth_credentials( $request );
		if ( null !== $basic ) {
			return $basic;
		}

		return new WP_Error(
			'oauth2.endpoints.token.invalid_request',
			__( 'Client credentials not provided.', 'oauth2' ),
			[ 'status' => WP_Http::BAD_REQUEST ]
		);
	}

	/**
	 * Check whether a request parameter is missing or empty.
	 *
	 * @param WP_REST_Request $request Request object.
	 * @param string          $param   Parameter name.
	 *
	 * @return bool True if the parameter has no usable value.
	 */
	private function is_param_empty( WP_REST_Request $request, $param ) {
		$value = $request->get_param( $param );

		return null === $value || '' === $value;
	}

	/**
	 * Build the response for a failed client authentication.
	 *
	 * The reason is never given: telling "unknown client" apart from "wrong
	 * secret" would confirm a valid client ID and secret pair.
	 *
	 * @param WP_REST_Request $request Request object.
	 *
	 * @return WP_Error|WP_REST_Response Error, or a response carrying a Basic challenge.
	 */
	private function client_authentication_failed( WP_REST_Request $request ) {
		$error = new WP_Error(
			'oauth2.endpoints.token.invalid_client',
			__( 'Client authentication failed.', 'oauth2' ),
			[ 'status' => WP_Http::UNAUTHORIZED ]
		);

		if ( ! $this->has_basic_auth_header( $request ) ) {
			return $error;
		}

		// RFC 6749 section 5.2: a client that authenticated with the
		// Authorization header must get a matching challenge back.
		$response = rest_convert_error_to_response( $error );
		$response->header( 'WWW-Authenticate', 'Basic realm="OAuth2 token endpoint"' );

		return $response;
	}

	/**
	 * Check whether the request carries an HTTP Basic Authorization header.
	 *
	 * @param WP_REST_Request $request Request object.
	 *
	 * @return bool True if a Basic header is present.
	 */
	private function has_basic_auth_header( WP_REST_Request $request ) {
		$auth_header = $request->get_header( 'authorization' );

		return ! empty( $auth_header ) && stripos( $auth_header, 'Basic ' ) === 0;
	}

	/**
	 * Read client credentials from an HTTP Basic Authorization header.
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return array|WP_Error|null Array with client_id and client_secret, error if the
	 *                             header is malformed, or null if there is no Basic header.
	 */
	private function get_basic_auth_credentials( WP_REST_Request $request ) {
		if ( ! $this->has_basic_auth_header( $request ) ) {
			return null;
		}

		$encoded = substr( $request->get_header( 'authorization' ), 6 );
		$decoded = base64_decode( $encoded, true );

		if ( false === $decoded ) {
			return new WP_Error(
				'oauth2.endpoints.token.invalid_request',
				__( 'Invalid Authorization header.', 'oauth2' ),
				[ 'status' => WP_Http::BAD_REQUEST ]
			);
		}

		$parts = explode( ':', $decoded, 2 );
		if ( count( $parts ) !== 2 ) {
			return new WP_Error(
				'oauth2.endpoints.token.invalid_request',
				__( 'Invalid Authorization header format.', 'oauth2' ),
				[ 'status' => WP_Http::BAD_REQUEST ]
			);
		}

		// RFC 6749 section 2.3.1: both values are form-encoded before they go
		// into the header, so decode them on the way back out.
		return [ urldecode( trim( $parts[0] ) ), urldecode( trim( $parts[1] ) ) ];
	}
}
