<?php
/**
 *
 * @package WordPress
 * @subpackage JSON API
 */

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
	 * @param array  $data Data gathered for the request. {
	 *     @var string $redirect_uri Specified redirection URI.
	 *     @var string $scope Requested scope.
	 *     @var string $state State parameter from the client.
	 *     @var string $code_challenge PKCE code challenge, if supplied. Grant-type specific.
	 *     @var string $code_challenge_method PKCE code challenge method, if supplied. Grant-type specific.
	 * }
	 * @return WP_Error|void Method should output form and exit, or return encountered error.
	 */
	abstract protected function handle_authorization_submission( $submit, Client $client, $data );

	/**
	 * Handle authorisation page.
	 *
	 * @return string|void|WP_Error|null
	 */
	public function handle_authorisation() {
		if ( empty( $_GET['client_id'] ) ) {
			return new WP_Error(
				'oauth2.types.authorization_code.handle_authorisation.missing_client_id',
				/* translators: %s: parameter name */
				sprintf( __( 'Missing %s parameter.', 'oauth2' ), 'client_id' )
			);
		}

		// Gather parameters.
		$client_id    = sanitize_text_field( wp_unslash( $_GET['client_id'] ) );
		$redirect_uri = isset( $_GET['redirect_uri'] ) ? sanitize_text_field( wp_unslash( $_GET['redirect_uri'] ) ) : null;
		$scope        = isset( $_GET['scope'] ) ? sanitize_text_field( wp_unslash( $_GET['scope'] ) ) : null;
		$state        = isset( $_GET['state'] ) ? sanitize_text_field( wp_unslash( $_GET['state'] ) ) : null;

		$client = Client::get_by_id( $client_id );
		if ( empty( $client ) ) {
			return new WP_Error(
				'oauth2.types.authorization_code.handle_authorisation.invalid_client_id',
				/* translators: %s: client ID */
				sprintf( __( 'Client ID %s is invalid.', 'oauth2' ), $client_id ),
				[
					'status'    => WP_Http::BAD_REQUEST,
					'client_id' => $client_id,
				]
			);
		}

		// Validate the redirection URI.
		$redirect_uri = $this->validate_redirect_uri( $client, $redirect_uri );
		if ( is_wp_error( $redirect_uri ) ) {
			return $redirect_uri;
		}

		// Gather and validate any grant-type-specific parameters (e.g. PKCE).
		// This runs after the redirect URI is known to be valid, and before the
		// login redirect, so a malformed request fails fast and can be reported
		// back to the client rather than dying with an HTML error page.
		$extra_params = $this->gather_extra_params( $client, wp_unslash( $_GET ) );
		if ( is_wp_error( $extra_params ) ) {
			$error_data = $extra_params->get_error_data();
			$error_code = ! empty( $error_data['error'] ) ? $error_data['error'] : 'invalid_request';
			wp_safe_redirect( $this->get_error_redirect_url( $redirect_uri, $error_code, $extra_params->get_error_message(), $state ) );
			exit;
		}

		// Valid parameters, ensure the user is logged in.
		if ( ! is_user_logged_in() ) {
			$redirect = '';
			if ( isset( $_SERVER['REQUEST_URI'] ) ) {
				$redirect = $_SERVER['REQUEST_URI']; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
			}
			$url = wp_login_url( $redirect );
			wp_safe_redirect( $url );
			exit;
		}

		if ( empty( $_POST['_wpnonce'] ) ) {
			return $this->render_form( $client );
		}

		// Check nonce.
		$nonce_action = $this->get_nonce_action( $client );
		if ( ! wp_verify_nonce( wp_unslash( $_POST['_wpnonce'] ), $nonce_action ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
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
					/* translators: %1$s is the translated "Authorize" button, %2$s is the translated "Cancel" button */
					__( 'Select either %1$s or %2$s to continue.', 'oauth2' ),
					__( 'Authorize', 'oauth2' ),
					__( 'Cancel', 'oauth2' )
				)
			);
			return $this->render_form( $client, $error );
		}

		$submit = sanitize_text_field( wp_unslash( $_POST['wp-submit'] ) );

		$data = array_merge( compact( 'redirect_uri', 'scope', 'state' ), $extra_params );
		return $this->handle_authorization_submission( $submit, $client, $data );
	}

	/**
	 * Gather and validate any grant-type-specific parameters from the request.
	 *
	 * Runs on both the initial GET and the consent-form POST, since the
	 * authorisation form posts back to the original request URI, so $_GET is
	 * populated on both passes. The default implementation adds nothing;
	 * override to add grant-type-specific request parameters (e.g. PKCE's
	 * code_challenge for the authorization_code grant).
	 *
	 * @param Client $client Client being authorised.
	 * @param array  $request Unslashed request parameters, from $_GET.
	 * @return array|WP_Error Extra data to merge into the $data passed to
	 *                        handle_authorization_submission(), or an error.
	 */
	protected function gather_extra_params( Client $client, array $request ) {
		return [];
	}

	/**
	 * Build a URL for reporting an authorisation error back to the client.
	 *
	 * @param string      $redirect_uri Validated redirect URI for the client.
	 * @param string      $error Error code, e.g. `invalid_request`.
	 * @param string      $description Human-readable error description.
	 * @param string|null $state State parameter from the original request, if any.
	 * @return string URL to redirect the client to.
	 */
	protected function get_error_redirect_url( $redirect_uri, $error, $description, $state = null ) {
		$args = [
			'error'             => $error,
			'error_description' => $description,
		];
		if ( ! empty( $state ) ) {
			$args['state'] = $state;
		}

		return add_query_arg( urlencode_deep( $args ), $redirect_uri );
	}

	/**
	 * Validate the supplied redirect URI.
	 *
	 * @param Client      $client Client to validate against.
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
		} elseif ( ! $client->check_redirect_uri( $redirect_uri ) ) {
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
	 * @param Client   $client Client being authorised.
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
	 * Filter the redirection args.
	 *
	 * @param array   $redirect_args Redirect args.
	 * @param boolean $authorized True if authorized, false otherwise.
	 * @param Client  $client Client being authorised.
	 * @param array   $data Data for the request. May include PKCE's
	 *                      `code_challenge`/`code_challenge_method` for the
	 *                      authorization_code grant; never `code_verifier`,
	 *                      which is only ever supplied at the token endpoint.
	 */
	protected function filter_redirect_args( $redirect_args, $authorized, Client $client, $data ) {
		if ( ! $authorized ) {
			/**
			 * Filter the redirect args when the user has cancelled.
			 *
			 * @param array $redirect_args Redirect args.
			 * @param Client $client Client being authorised.
			 * @param array $data Data for the request. See filter_redirect_args().
			 */
			return apply_filters( 'oauth2.redirect_args.cancelled', $redirect_args, $client, $data );
		}

		/**
		 * Filter the redirect args when the user has authorized.
		 *
		 * @param array $redirect_args Redirect args.
		 * @param Client $client Client being authorised.
		 * @param array $data Data for the request. See filter_redirect_args().
		 */
		return apply_filters( 'oauth2.redirect_args.authorized', $redirect_args, $client, $data );
	}
}
