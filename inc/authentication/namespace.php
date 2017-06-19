<?php

namespace WP\OAuth2\Authentication;

use WP_Http;
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

		// Check for the authoization header case-insensitively
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
	if ( empty( $header ) || ! is_string( $header ) ) {
		return null;
	}

	// Attempt to parse as a Bearer header.
	$is_valid = preg_match( '/Bearer ([a-zA-Z0-9=.~\-\+\/]+)/', trim( $header ), $matches );
	if ( ! $is_valid ) {
		return null;
	}

	return $matches[1];
}

/**
 * Try to authenticate if possible.
 *
 * @param WP_User|null $user Existing authenticated user.
 */
function attempt_authentication( $user = null ) {
	if ( ! empty( $user ) ) {
		return $user;
	}

	// Were we given an token?
	$token_value = get_provided_token();
	if ( empty( $token_value ) ) {
		// No data provided, pass.
		return $user;
	}

	// Attempt to find the token.
	$token = Tokens\get_by_id( $token_value );
	if ( empty( $token ) ) {
		return new WP_Error(
			'oauth2.authentication.attempt_authentication.invalid_token',
			__( 'Supplied token is invalid.', 'oauth2' ),
			array(
				'status' => WP_Http::FORBIDDEN,
				'token' => $token_value,
			)
		);
	}

	// Token found, authenticate as the user.
	return $token->get_user_id();
}