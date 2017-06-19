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
	 * Display an error using login page wrapper
	 *
	 * @param WP_Error $error Error object
	 */
	public function display_error( WP_Error $error ) {
		login_header( __( 'Error', 'rest_oauth2' ), '', $error );
		login_footer();
	}
}
