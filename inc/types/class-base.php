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
		// Should probably keep this as an option in the application (e.g. force PKCE)
		$pkce = true;

		if ( empty( $_GET['client_id'] ) ) {
			return new WP_Error(
				'oauth2.types.authorization_code.handle_authorisation.missing_client_id',
				sprintf( __( 'Missing %s parameter.', 'oauth2' ), 'client_id' )
			);
		}

		// Gather parameters.
		$client_id    			= wp_unslash( $_GET['client_id'] );
		$redirect_uri 			= isset( $_GET['redirect_uri'] ) ? wp_unslash( $_GET['redirect_uri'] ) : null;
		$scope        			= isset( $_GET['scope'] ) ? wp_unslash( $_GET['scope'] ) : null;
		$state        			= isset( $_GET['state'] ) ? wp_unslash( $_GET['state'] ) : null;

		if ( $pkce ) {
			$pkce_data = $this->handle_pkce();
			if ( is_wp_error( $pkce_data ) ) {
				return $pkce_data;
			}

			$code_challenge = $pkce_data['code_challenge'];
			$code_challenge_method = $pkce_data['code_challenge_method'];
		}

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
		$redirect_uri = $this->validate_redirect_uri( $client, $redirect_uri );
		if ( is_wp_error( $redirect_uri ) ) {
			return $redirect_uri;
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
		$nonce_action = $this->get_nonce_action( $client );
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

		$data = compact( 'redirect_uri', 'scope', 'state', 'code_challenge', 'code_challenge_method' );
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
		if ( empty( $redirect_uri ) ) {
			$registered = $client->get_redirect_uris();
			if ( count( $registered ) !== 1 ) {
				// Either none registered, or more than one, so error.
				return new WP_Error(
					'oauth2.types.authorization_code.handle_authorisation.missing_redirect_uri',
					__( 'Redirect URI was required, but not found.', 'oauth2' )
				);
			}

			$redirect_uri = $registered[0];
		} else {
			if ( ! $client->check_redirect_uri( $redirect_uri ) ) {
				return new WP_Error(
					'oauth2.types.authorization_code.handle_authorisation.invalid_redirect_uri',
					__( 'Specified redirect URI is not valid for this client.', 'oauth2' )
				);
			}
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

	/**
	 * Get and validate PKCE parameters from a request.
	 *
	 * @return string[] code_challenge and code_challenge_method
	 */
	private function handle_pkce() {
		$code_challenge        	= isset( $_GET['code_challenge'] ) ? wp_unslash( $_GET['code_challenge'] ) : null;
		$code_challenge_method 	= isset( $_GET['code_challenge_method'] ) ? wp_unslash( $_GET['code_challenge_method'] ) : null;

		if ( ! is_null( $code_challenge ) ) {
			if ( '' === \trim( $code_challenge ) ) {
				return new WP_Error(
					'oauth2.types.authorization_code.handle_authorisation.code_challenge_empty',
					sprintf( __( 'Code challenge cannot be empty', 'oauth2' ), $client_id ),
					[
						'status' => WP_Http::BAD_REQUEST,
						'client_id' => $client_id,
					]
				);
			}

			$code_challenge_method = is_null( $code_challenge_method ) ? 'plain' : $code_challenge_method;

			if ( ! \in_array( \strtolower( $code_challenge_method ), [ 'plain', 's256' ], true ) ) {
				return new WP_Error(
					'oauth2.types.authorization_code.handle_authorisation.wrong_challenge_method',
					sprintf( __( 'Challenge method must be S256 or plain', 'oauth2' ), $client_id ),
					[
						'status' => WP_Http::BAD_REQUEST,
						'client_id' => $client_id,
					]
				);
			}

			return [ 'code_challenge' => $code_challenge, 'code_challenge_method' => $code_challenge_method ];
		}

		return false;
	}
}
