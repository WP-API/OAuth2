<?php
/**
 * Authorization page handler
 *
 * Takes care of UI and related elements for the authorization step of OAuth.
 *
 * @package WordPress
 * @subpackage JSON API
 */

class WP_REST_OAuth2_UI {
	/**
	 * Request token for the current authorization request
	 *
	 * @var array
	 */
	protected $token;

	/**
	 * Consumer post object for the current authorization request
	 *
	 * @var WP_Post
	 */
	protected $consumer;

	/**
	 * Register required actions and filters
	 */
	public function register_hooks() {
		add_action( 'login_form_oauth2_authorize', array( $this, 'handle_request' ) );
		// add_action( 'oauth2_authorize_form', array( $this, 'page_fields' ) );
	}

	/**
	 * Handle request to authorization page
	 *
	 * Handles response from {@see render_page}, then exits to avoid output from
	 * default wp-login handlers.
	 */
	public function handle_request() {
		if ( ! is_user_logged_in() ) {
			wp_safe_redirect( wp_login_url( $_SERVER['REQUEST_URI'] ) );
			exit;
		}

		$auth_code = new \WP\OAuth2\Types\AuthorizationCode();

		$auth_code->handle_authorisation();
		exit;
	}

	/**
	 * Render authorization page
	 *
	 * @return null|WP_Error Null on success, error otherwise
	 */
	public function render_page() {
		$auth_code = new \WP\OAuth2\Types\AuthorizationCode();
		$auth_code->handle_authorisation();
	}

	/**
	 * Output required hidden fields
	 *
	 * Outputs the required hidden fields for the authorization page, including
	 * nonce field.
	 */
	public function page_fields() {
		wp_nonce_field( sprintf( 'oauth2_authorize:%s', $this->client->get_post_id() ) );
	}

	/**
	 * Handle redirecting the user after authorization
	 *
	 * @param string $verifier Verification code
	 * @return null|WP_Error Null on success, error otherwise
	 */
	/*public function handle_callback_redirect( $verifier ) {
		if ( empty( $this->token['callback'] ) || $this->token['callback'] === 'oob' ) {
			// No callback registered, display verification code to the user
			login_header( __( 'Access Token', 'rest_oauth1' ) );
			echo '<p>' . sprintf( __( 'Your verification token is <code>%s</code>', 'rest_oauth1' ), $verifier ) . '</p>';
			login_footer();

			return null;
		}

		$callback = $this->token['callback'];

		// Ensure the URL is safe to access
		$authenticator = new WP_REST_OAuth1();
		if ( ! $authenticator->check_callback( $callback, $this->token['consumer'] ) ) {
			return new WP_Error( 'json_oauth1_invalid_callback', __( 'The callback URL is invalid', 'rest_oauth1' ), array( 'status' => 400 ) );
		}

		$args = array(
			'oauth_token' => $this->token['key'],
			'oauth_verifier' => $verifier,
			'wp_scope' => '*',
		);
		$args = apply_filters( 'json_oauth2_callback_args', $args, $this->token );
		$args = urlencode_deep( $args );
		$callback = add_query_arg( $args, $callback );

		// Offsite, so skip safety check
		wp_redirect( $callback );

		return null;
	}*/

	/**
	 * Display an error using login page wrapper
	 *
	 * @param WP_Error $error Error object
	 */
	public function display_error( WP_Error $error ) {
		login_header( __( 'Error', 'rest_oauth2' ), '', $error );
		login_footer();
	}
}
