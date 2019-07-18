<?php
/**
 *
 * @package WordPress
 * @subpackage JSON API
 */

namespace WP\OAuth2\Endpoints;

use WP_Error;
use WP\OAuth2;
use WP\OAuth2\Types\Type;

class Authorization {
	const LOGIN_ACTION = 'oauth2_authorize';

	/**
	 * Register required actions and filters
	 */
	public function register_hooks() {
		add_action( 'login_form_' . static::LOGIN_ACTION, [ $this, 'handle_request' ] );
	}

	public function handle_request() {
		// If the form hasn't been submitted, show it.
		if ( isset( $_GET['response_type'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$type = wp_unslash( $_GET['response_type'] ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		} else {
			$type = null;
		}

		// Match type to a handler.
		$grant_types = OAuth2\get_grant_types();
		if ( $grant_types ) {
			/** @var Type $type_handler */
			foreach ( array_reverse( $grant_types ) as $type_handler ) {
				if ( $type_handler->get_response_type_code() === $type ) {
					$handler = $type_handler;
					break;
				}
			}
		}

		if ( empty( $handler ) ) {
			$result = new WP_Error(
				'oauth2.endpoints.authorization.handle_request.invalid_type',
				__( 'Invalid response type specified.', 'oauth2' )
			);
		} else {
			$result = $handler->handle_authorisation();
		}

		if ( is_wp_error( $result ) ) {
			// TODO: Handle it.
			wp_die( esc_html( $result->get_error_message() ) );
		}
		exit;
	}
}
