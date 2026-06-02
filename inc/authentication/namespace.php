<?php
/**
 *
 * @package WordPress
 * @subpackage JSON API
 */

namespace WP\OAuth2\Authentication;

use WP_Error;
use WP_User;
use WP\OAuth2\Tokens;

/**
 * Get a request header by name, case-insensitively.
 *
 * On certain systems and configurations, the Authorization header will be
 * stripped out by the server or PHP. Typically this is then used to
 * generate `PHP_AUTH_USER`/`PHP_AUTH_PASS` but not passed on. We use
 * `getallheaders` here to try and grab it out instead.
 *
 * @param string $name Header name. Default 'authorization'.
 *
 * @return string|null Header value if set, null otherwise.
 */
function get_authorization_header( $name = 'authorization' ) {
	$server_key = 'HTTP_' . strtoupper( str_replace( '-', '_', $name ) );
	if ( ! empty( $_SERVER[ $server_key ] ) ) {
		return wp_unslash( $_SERVER[ $server_key ] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
	}

	if ( function_exists( 'getallheaders' ) ) {
		$headers = getallheaders();
		foreach ( $headers as $key => $value ) {
			if ( strtolower( $key ) === strtolower( $name ) ) {
				return $value;
			}
		}
	}

	return null;
}

/**
 * Extracts the token from the authorization header or the current request.
 *
 * @return string|null Token on success, null on failure.
 */
function get_provided_token() {
	/**
	 * Filter the authorization header name used to extract the bearer token.
	 *
	 * Override when the standard Authorization header is consumed by a proxy
	 * (e.g. Imperva HTTP Basic Auth) and the token is forwarded under a
	 * different name such as X-Authorization.
	 *
	 * @param string $name Header name. Default 'authorization'.
	 */
	$header = get_authorization_header( apply_filters( 'oauth2.authentication.authorization_header', 'authorization' ) );
	if ( $header ) {
		$token = get_token_from_bearer_header( $header );
		if ( $token ) {
			return $token;
		}
	}

	$token = get_token_from_request();
	if ( $token ) {
		return $token;
	}

	return null;
}

/**
 * Extracts the token from the given authorization header.
 *
 * @param string $header Authorization header.
 *
 * @return string|null Token on succes, null on failure.
 */
function get_token_from_bearer_header( $header ) {
	if ( is_string( $header ) && preg_match( '/Bearer ([a-zA-Z0-9\-._~\+\/=]+)/', trim( $header ), $matches ) ) {
		return $matches[1];
	}

	return null;
}

/**
 * Extracts the token from the current request.
 *
 * @return string|null Token on succes, null on failure.
 */
function get_token_from_request() {
	if ( empty( $_GET['access_token'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		return null;
	}

	$token = $_GET['access_token']; // phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput
	if ( is_string( $token ) ) {
		return $token;
	}

	// Got a token, but it's not valid.
	global $oauth2_error;
	$oauth2_error = create_invalid_token_error( $token );
	return null;
}

/**
 * Try to authenticate if possible.
 *
 * @param WP_User|null $user Existing authenticated user.
 *
 * @return WP_User|int|WP_Error
 */
function attempt_authentication( $user = null ) {
	// Lock against infinite loops when querying the token itself.
	static $is_querying_token = false;
	global $oauth2_error, $oauth2_client_credentials;
	$oauth2_error              = null;
	$oauth2_client_credentials = null;

	if ( ! empty( $user ) || $is_querying_token ) {
		return $user;
	}

	// Were we given a token?
	$token_value = get_provided_token();
	if ( empty( $token_value ) ) {
		// No data provided, pass.
		return $user;
	}

	// Attempt to find the token.
	$is_querying_token = true;
	$token             = Tokens\get_by_id( $token_value );
	if ( empty( $token ) ) {
		$is_querying_token = false;
		$oauth2_error      = create_invalid_token_error( $token_value );
		return $user;
	}

	$client            = $token->get_client();
	$is_querying_token = false;

	if ( empty( $token ) || empty( $client ) ) {
		$oauth2_error = create_invalid_token_error( $token_value );
		return $user;
	}

	// Check if this is a client credentials token (no user)
	if ( $token->is_client_token() ) {
		if ( ! $client->is_client_credentials_enabled() ) {
			$oauth2_error = new WP_Error(
				'oauth2.authentication.client_credentials_disabled',
				__( 'Client credentials authentication is not enabled for this client.', 'oauth2' ),
				[
					'status' => \WP_Http::FORBIDDEN,
				]
			);
			return $user;
		}

		// Set global variable for client credentials authentication
		$oauth2_client_credentials = [
			'authenticated' => true,
			'client_id'     => $client->get_id(),
			'client'        => $client,
			'token'         => $token,
		];
		// Return 0 to indicate no user but authentication is valid
		return 0;
	}

	// Token found, authenticate as the user.
	return $token->get_user_id();
}

/**
 * Report our errors, if we have any.
 *
 * Attached to the rest_authentication_errors filter. Passes through existing
 * errors registered on the filter.
 *
 * @param WP_Error|null Current error, or null.
 *
 * @return WP_Error|null Error if one is set, otherwise null.
 */
function maybe_report_errors( $error = null ) {
	if ( ! empty( $error ) ) {
		return $error;
	}

	global $oauth2_error;
	return $oauth2_error;
}

/**
 * Creates an error object for the given invalid token.
 *
 * @param mixed $token Invalid token.
 *
 * @return WP_Error
 */
function create_invalid_token_error( $token ) {
	return new WP_Error(
		'oauth2.authentication.attempt_authentication.invalid_token',
		__( 'Supplied token is invalid.', 'oauth2' ),
		[
			'status' => \WP_Http::FORBIDDEN,
			'token'  => $token,
		]
	);
}
