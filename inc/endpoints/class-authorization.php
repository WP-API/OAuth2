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
			$this->render_error( $result );
		}
		exit;
	}

	/**
	 * Get the HTTP status for an error.
	 *
	 * @param WP_Error $error Error to read the `status` error data from.
	 * @return int Status code, 400 if the error does not set one.
	 */
	public function get_error_status( WP_Error $error ) {
		$data = $error->get_error_data();

		return is_array( $data ) && ! empty( $data['status'] ) ? (int) $data['status'] : 400;
	}

	/**
	 * Render an authorization error on the login screen, then exit.
	 *
	 * @param WP_Error $error Error to display. The `status` error data sets the HTTP status.
	 */
	protected function render_error( WP_Error $error ) {
		// login_header() prints error messages as HTML, so escape them first.
		$escaped = new WP_Error();
		foreach ( $error->get_error_codes() as $code ) {
			foreach ( $error->get_error_messages( $code ) as $message ) {
				$escaped->add( $code, esc_html( $message ) );
			}
		}

		status_header( $this->get_error_status( $error ) );
		login_header( __( 'Authorization error', 'oauth2' ), '', $escaped );
		login_footer();
		exit;
	}
}
