<?php

namespace WP\OAuth2\Types;

use WP_Error;
use WP\OAuth2\Client;

abstract class Base implements Type {
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
				array(
					'status' => WP_Http::BAD_REQUEST,
					'client_id' => $client_id,
				)
			);
		}

		// Validate the redirection URI.
		$redirect_uri = $this->validate_redirect_uri( $client, $redirect_uri );
		if ( is_wp_error( $redirect_uri ) ) {
			return $redirect_uri;
		}

		if ( empty( $_POST['_wpnonce'] ) ) {
			return $this->render_form( $client );
		}

		// Check nonce.
		$nonce = wp_unslash( $_POST['_wpnonce'] );
		if ( ! wp_verify_nonce( $nonce, $this->get_nonce_action( $client ) ) ) {
			return new WP_Error(
				'oauth2.types.authorization_code.handle_authorisation.invalid_nonce',
				__( 'Invalid nonce.', 'oauth2' )
			);
		}

		$submit = wp_unslash( $_POST['wp-submit'] );
		if ( empty( $submit ) ) {
			return new WP_Error();
		}

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
	 */
	public function render_form( Client $client ) {
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
	 */
	protected function get_nonce_action( Client $client ) {
		// return sprintf( 'oauth2_authorize:%s', $client->get_post_id() );
		return 'json_oauth2_authorize';
	}
}
