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
	const ROUTE = '/oauth2/access_token';

	/**
	 * RFC 6749 section 5.2 error codes for the errors this endpoint returns.
	 */
	const OAUTH_ERRORS = [
		'rest_missing_callback_param'            => 'invalid_request',
		'rest_invalid_param'                     => 'invalid_request',
		'oauth2.endpoints.token.invalid_request' => 'invalid_request',
		'oauth2.endpoints.token.exchange_token.invalid_client' => 'invalid_client',
		'oauth2.endpoints.token.invalid_client'  => 'invalid_client',
		'oauth2.client.check_authorization_code.invalid_code' => 'invalid_grant',
		'oauth2.tokens.authorization_code.validate.expired' => 'invalid_grant',
		'oauth2.tokens.authorization_code.get_user.invalid_data' => 'invalid_grant',
	];

	public function register_hooks() {
		add_filter( 'rest_request_after_callbacks', [ $this, 'format_error_response' ], 10, 3 );
	}

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
	 * Add the RFC 6749 section 5.2 error fields to a token endpoint error.
	 *
	 * The WordPress `code`, `message` and `data` fields are kept alongside
	 * `error` and `error_description`.
	 *
	 * @param WP_REST_Response|WP_Error|mixed $response Result of the request.
	 * @param array                           $handler Route handler.
	 * @param WP_REST_Request                 $request Request object.
	 * @return WP_REST_Response|mixed Formatted error response, or the original response.
	 */
	public function format_error_response( $response, $handler, $request ) {
		if ( ! is_wp_error( $response ) || ! $request instanceof WP_REST_Request || static::ROUTE !== $request->get_route() ) {
			return $response;
		}

		$error      = $this->get_oauth_error( $response );
		$error_data = $response->get_error_data();
		$status     = is_array( $error_data ) && isset( $error_data['status'] ) ? (int) $error_data['status'] : WP_Http::INTERNAL_SERVER_ERROR;

		if ( 'server_error' === $error ) {
			$status = WP_Http::INTERNAL_SERVER_ERROR;
		} elseif ( ! ( 'invalid_client' === $error && WP_Http::UNAUTHORIZED === $status ) ) {
			$status = WP_Http::BAD_REQUEST;
		}

		$formatted = rest_convert_error_to_response( $response );
		$data      = $formatted->get_data();

		$data['error']             = $error;
		$data['error_description'] = $response->get_error_message();

		$formatted->set_data( $data );
		$formatted->set_status( $status );

		if ( WP_Http::UNAUTHORIZED === $status ) {
			$formatted->header( 'WWW-Authenticate', 'Basic realm="oauth2"' );
		}

		return $formatted;
	}

	/**
	 * Get the RFC 6749 section 5.2 error code for an error.
	 *
	 * An `error` key in the error data wins over the built-in map. Unknown
	 * errors become `invalid_request` if they carry a 4xx status, or
	 * `server_error` otherwise.
	 *
	 * @param WP_Error $error Error returned by the endpoint.
	 * @return string OAuth error code.
	 */
	protected function get_oauth_error( WP_Error $error ) {
		$data = $error->get_error_data();
		if ( is_array( $data ) && ! empty( $data['error'] ) && is_string( $data['error'] ) ) {
			return $data['error'];
		}

		$code = $error->get_error_code();
		if ( 'rest_invalid_param' === $code && isset( $data['params']['grant_type'] ) ) {
			return 'unsupported_grant_type';
		}

		if ( isset( static::OAUTH_ERRORS[ $code ] ) ) {
			return static::OAUTH_ERRORS[ $code ];
		}

		$status = is_array( $data ) && isset( $data['status'] ) ? (int) $data['status'] : WP_Http::INTERNAL_SERVER_ERROR;

		return $status >= 400 && $status < 500 ? 'invalid_request' : 'server_error';
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
		if ( $request->get_param( 'client_id' ) === null || $request->get_param( 'client_id' ) === '' ) {
			$basic = $this->get_basic_auth_credentials( $request );
			if ( is_wp_error( $basic ) ) {
				return $basic;
			}
			if ( null !== $basic ) {
				$request->set_param( 'client_id', $basic[0] );
				if ( $request->get_param( 'client_secret' ) === null || $request->get_param( 'client_secret' ) === '' ) {
					$request->set_param( 'client_secret', $basic[1] );
				}
			}
		}

		// The authorization_code grant requires `client_id` and `code`.
		// These are declared optional at the schema level so they don't
		// apply to client_credentials, so validate presence here. The error
		// shape matches what WP REST API would produce at the schema layer.
		$missing = [];
		foreach ( [ 'client_id', 'code' ] as $required_param ) {
			if ( $request->get_param( $required_param ) === null || $request->get_param( $required_param ) === '' ) {
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
			return new WP_Error(
				'oauth2.endpoints.token.invalid_client',
				__( 'Client authentication failed.', 'oauth2' ),
				[ 'status' => WP_Http::UNAUTHORIZED ]
			);
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
	 * Read client credentials from an HTTP Basic Authorization header.
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return array|WP_Error|null Array with client_id and client_secret, error if the
	 *                             header is malformed, or null if there is no Basic header.
	 */
	private function get_basic_auth_credentials( WP_REST_Request $request ) {
		$auth_header = $request->get_header( 'authorization' );

		if ( empty( $auth_header ) || stripos( $auth_header, 'Basic ' ) !== 0 ) {
			return null;
		}

		$encoded = substr( $auth_header, 6 );
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
