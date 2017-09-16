<?php

namespace WP\OAuth2\Types;

use WP_Error;
use WP_Http;
use WP\OAuth2\Client;

abstract class Base implements Type {
	/**
	 * Handle submission of authorisation page.
	 *
	 * @param string $submit Value of the selected button.
	 * @param Client $client Client being authorised.
	 * @param array $data Data gathered for the request. {
	 *     @var string $redirect_uri Specified redirection URI.
	 *     @var string $scope Requested scope.
	 *     @var string $state State parameter from the client.
	 * }
	 * @return WP_Error|void Method should output form and exit, or return encountered error.
	 */
	abstract protected function handle_authorization_submission( $submit, Client $client, $data );

	/**
	 * Handle authorisation page.
	 */
	public function handle_authorisation() {

		if ( empty( $_GET['client_id'] ) ) {
			return new WP_Error(
				'oauth2.types.authorization_code.handle_authorisation.missing_client_id',
				sprintf( __( 'Missing %s parameter.', 'oauth2' ), 'client_id' )
			);
		}

		// Gather parameters.
		$client_id    = wp_unslash( $_GET['client_id'] );
		$redirect_uri = isset( $_GET['redirect_uri'] ) ? wp_unslash( $_GET['redirect_uri'] ) : null;
		$scope        = isset( $_GET['scope'] ) ? wp_unslash( $_GET['scope'] ) : null;
		$state        = isset( $_GET['state'] ) ? wp_unslash( $_GET['state'] ) : null;

		$client = Client::get_by_id( $client_id );
		if ( empty( $client ) ) {
			return new WP_Error(
				'oauth2.types.authorization_code.handle_authorisation.invalid_client_id',
				sprintf( __( 'Client ID %s is invalid.', 'oauth2' ), $client_id ),
				[
					'status' => WP_Http::BAD_REQUEST,
					'client_id' => $client_id,
				]
			);
		}

		// Validate the redirection URI.
		if ( ! empty( $redirect_uri ) ) {
			$redirect_uri = $this->validate_redirect_uri( $client, $redirect_uri );

			if ( is_wp_error( $redirect_uri ) ) {
				return $redirect_uri;
			}
		}

		// Valid parameters, ensure the user is logged in.
		if ( ! is_user_logged_in() ) {
			$url = wp_login_url( $_SERVER['REQUEST_URI'] );
			wp_safe_redirect( $url );
			exit;
		}

		if ( empty( $_POST['_wpnonce'] ) ) {
			return $this->render_form( $client );
		}

		// Check nonce.
		if ( ! wp_verify_nonce( wp_unslash( $_POST['_wpnonce'] ), $this->get_nonce_action( $client ) ) ) {
			return new WP_Error(
				'oauth2.types.authorization_code.handle_authorisation.invalid_nonce',
				__( 'Invalid nonce.', 'oauth2' )
			);
		}

		if ( empty( $_POST['wp-submit'] ) ) {
			// Submitted, but button not selected...
			$error = new WP_Error(
				'oauth2.types.authorization_code.handle_authorisation.invalid_submit',
				sprintf(
					/** translators: %1$s is the translated "Authorize" button, %2$s is the translated "Cancel" button */
					__( 'Select either %1$s or %2$s to continue.', 'oauth2' ),
					__( 'Authorize', 'oauth2' ),
					__( 'Cancel', 'oauth2' )
				)
			);
			return $this->render_form( $client, $error );
		}

		$submit = wp_unslash( $_POST['wp-submit'] );

		$data = compact( 'redirect_uri', 'scope', 'state' );
		return $this->handle_authorization_submission( $submit, $client, $data );
	}

	/**
	 * Validate the supplied redirect URI.
	 *
	 * @param Client $client Client to validate against.
	 * @param string|null $redirect_uri Redirect URI, if supplied.
	 * @return string|WP_Error Valid redirect URI on success, error otherwise.
	 */
	protected function validate_redirect_uri( Client $client, $redirect_uri = null ) {
		if ( ! $client->check_redirect_uri( $redirect_uri ) ) {
			return new WP_Error(
				'oauth2.types.authorization_code.handle_authorisation.invalid_redirect_uri',
				__( 'Specified redirect URI is not valid for this client.', 'oauth2' )
			);
		}

		return $redirect_uri;
	}

	/**
	 * Render the authorisation form.
	 *
	 * @param Client $client Client being authorised.
	 * @param WP_Error $errors Errors to display, if any.
	 */
	protected function render_form( Client $client, WP_Error $errors = null ) {
		$file = locate_template( 'oauth2-authorize.php' );
		if ( empty( $file ) ) {
			$file = dirname( dirname( __DIR__ ) ) . '/theme/oauth2-authorize.php';
		}

		include $file;
	}

	/**
	 * Get the nonce action for a client.
	 *
	 * @param Client $client Client to generate nonce for.
	 * @return string Nonce action for given client.
	 */
	protected function get_nonce_action( Client $client ) {
		return sprintf( 'oauth2_authorize:%s', $client->get_id() );
	}
}
