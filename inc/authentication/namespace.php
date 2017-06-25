<?php

namespace WP\OAuth2\Authentication;

use WP\OAuth2\Tokens;

/**
 * Get the authorization header
 *
 * On certain systems and configurations, the Authorization header will be
 * stripped out by the server or PHP. Typically this is then used to
 * generate `PHP_AUTH_USER`/`PHP_AUTH_PASS` but not passed on. We use
 * `getallheaders` here to try and grab it out instead.
 *
 * @return string|null Authorization header if set, null otherwise
 */
function get_authorization_header() {
	if ( ! empty( $_SERVER['HTTP_AUTHORIZATION'] ) ) {
		return wp_unslash( $_SERVER['HTTP_AUTHORIZATION'] );
	}

	if ( function_exists( 'getallheaders' ) ) {
		$headers = getallheaders();

		// Check for the authorization header case-insensitively
		foreach ( $headers as $key => $value ) {
			if ( strtolower( $key ) === 'authorization' ) {
				return $value;
			}
		}
	}

	return null;
}

function get_provided_token() {
	$header = get_authorization_header();
	if ( $header ) {
		return get_token_from_bearer_header( $header );
	}

	$token = get_token_from_request();
	if ( $token ) {
		return $token;
	}

	return null;
}

function get_token_from_bearer_header( $header ) {
	if ( is_string( $header ) && preg_match( '/Bearer ([a-zA-Z0-9\-._~\+\/=]+)/', trim( $header ), $matches ) ) {
		return $matches[1];
	}

	return null;
}

function get_token_from_request() {
	if ( empty( $_GET['access_token'] ) ) {
		return null;
	}

	$token = $_GET['access_token'];
	if ( is_string( $token ) ) {
		return $token;
	}

	// Please note that the following includes PHP 5.3+ code. Ryan said it would be fine, soon. ;)
	add_filter( 'rest_authentication_errors', function ( $error ) use ( $token ) {
		return null === $error ? create_invalid_token_error( $token ) : null;
	} );

	return null;
}

/**
 * Try to authenticate if possible.
 *
 * @param \WP_User|null $user Existing authenticated user.
 *
 * @return \WP_User|int|\WP_Error
 */
function attempt_authentication( $user = null ) {
	// Lock against infinite loops when querying the token itself.
	static $is_querying_token = false;

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
	$token = Tokens\get_by_id( $token_value );
	$is_querying_token = false;

	if ( empty( $token ) ) {
		return create_invalid_token_error( $token );
	}

	// Token found, authenticate as the user.
	return $token->get_user_id();
}

function create_invalid_token_error( $token ) {
	return new \WP_Error(
		'oauth2.authentication.attempt_authentication.invalid_token',
		__( 'Supplied token is invalid.', 'oauth2' ),
		array(
			'status' => \WP_Http::FORBIDDEN,
			'token'  => $token,
		)
	);
}
