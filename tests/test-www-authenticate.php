<?php
/**
 * Tests for the RFC 9728 WWW-Authenticate challenge.
 *
 * @package WP\OAuth2\Tests
 */

namespace WP\OAuth2\Tests;

require_once __DIR__ . '/class-test-case.php';

use WP\OAuth2\Tokens\Access_Token;
use WP_REST_Request;
use WP_REST_Response;
use WP_REST_Server;

use function WP\OAuth2\Authentication\add_www_authenticate_header;
use function WP\OAuth2\Authentication\attempt_authentication;
use function WP\OAuth2\Authentication\build_authenticate_challenge;
use function WP\OAuth2\Authentication\expose_authenticate_header;
use function WP\OAuth2\Well_Known\get_protected_resource_metadata_url;

/**
 * Test cases for the WWW-Authenticate challenge on unauthorized responses.
 */
class Test_WWW_Authenticate extends Test_Case {

	/**
	 * @var WP_REST_Server
	 */
	protected $server;

	public function set_up() {
		parent::set_up();

		$this->set_permalink_structure( '/%postname%/' );

		global $wp_rest_server;
		$this->server = new WP_REST_Server();
		$wp_rest_server = $this->server;
		do_action( 'rest_api_init', $this->server );
	}

	public function tear_down() {
		global $wp_rest_server, $oauth2_error;
		$wp_rest_server = null;
		$oauth2_error   = null;
		unset( $_SERVER['HTTP_AUTHORIZATION'] );

		parent::tear_down();
	}

	/**
	 * Dispatch a request the way serve_request() would, so the challenge
	 * filter runs. WP_REST_Server::dispatch() does not apply it on its own.
	 *
	 * @param WP_REST_Request $request Request to dispatch.
	 *
	 * @return WP_REST_Response Filtered response.
	 */
	protected function dispatch( WP_REST_Request $request ) {
		return apply_filters( 'rest_post_dispatch', $this->server->dispatch( $request ), $this->server, $request );
	}

	/**
	 * Get the challenge from a response, or null when there isn't one.
	 *
	 * @param WP_REST_Response $response Response to read.
	 *
	 * @return string|null Challenge header value.
	 */
	protected function get_challenge( WP_REST_Response $response ) {
		$headers = $response->get_headers();

		return $headers['WWW-Authenticate'] ?? null;
	}

	// -------------------------------------------------------------------------
	// Which responses get a challenge
	// -------------------------------------------------------------------------

	/**
	 * Core answers an anonymous request to a protected route with a 401, so
	 * routes this plugin knows nothing about are covered too.
	 */
	public function test_challenge_is_added_to_a_core_unauthorized_response() {
		$response = $this->dispatch( new WP_REST_Request( 'GET', '/wp/v2/settings' ) );

		$this->assertEquals( 401, $response->get_status() );
		$this->assertStringStartsWith( 'Bearer ', $this->get_challenge( $response ) );
	}

	public function test_challenge_is_not_added_to_a_successful_response() {
		$response = $this->dispatch( new WP_REST_Request( 'GET', '/' ) );

		$this->assertEquals( 200, $response->get_status() );
		$this->assertNull( $this->get_challenge( $response ) );
	}

	/**
	 * A logged-in user without the capability gets a 403, which is an
	 * authorization failure. Re-authenticating would not help.
	 */
	public function test_challenge_is_not_added_to_a_forbidden_response() {
		wp_set_current_user( $this->factory->user->create( [ 'role' => 'subscriber' ] ) );

		$response = $this->dispatch( new WP_REST_Request( 'GET', '/wp/v2/settings' ) );

		$this->assertEquals( 403, $response->get_status() );
		$this->assertNull( $this->get_challenge( $response ) );
	}

	/**
	 * The token endpoint is the authorization server, not a resource it
	 * protects, so it must not point clients back at resource metadata.
	 */
	public function test_challenge_is_not_added_to_the_token_endpoint() {
		$request = new WP_REST_Request( 'POST', '/oauth2/access_token' );
		$request->set_param( 'grant_type', 'client_credentials' );
		$request->set_param( 'client_id', 'nonexistent' );
		$request->set_param( 'client_secret', 'wrong' );

		$response = $this->dispatch( $request );

		$this->assertEquals( 401, $response->get_status() );
		$this->assertNull( $this->get_challenge( $response ) );
	}

	public function test_an_existing_challenge_is_not_overwritten() {
		$response = new WP_REST_Response( null, 401 );
		$response->header( 'WWW-Authenticate', 'Basic realm="example"' );

		$filtered = add_www_authenticate_header( $response, $this->server, new WP_REST_Request( 'GET', '/wp/v2/settings' ) );

		$this->assertEquals( 'Basic realm="example"', $this->get_challenge( $filtered ) );
	}

	/**
	 * Embedded responses run the filter again, so it has to be safe to repeat.
	 */
	public function test_adding_the_challenge_twice_leaves_one_header() {
		$request  = new WP_REST_Request( 'GET', '/wp/v2/settings' );
		$response = new WP_REST_Response( null, 401 );

		add_www_authenticate_header( $response, $this->server, $request );
		add_www_authenticate_header( $response, $this->server, $request );

		$this->assertIsString( $this->get_challenge( $response ) );
	}

	// -------------------------------------------------------------------------
	// Challenge contents
	// -------------------------------------------------------------------------

	public function test_challenge_points_at_the_resource_metadata_document() {
		$this->assertStringContainsString(
			sprintf( 'resource_metadata="%s"', get_protected_resource_metadata_url() ),
			build_authenticate_challenge()
		);
	}

	/**
	 * RFC 6750 section 3 leaves the error out when the client sent nothing to
	 * be wrong about.
	 */
	public function test_challenge_is_bare_when_no_credentials_were_supplied() {
		$this->assertStringNotContainsString( 'error=', build_authenticate_challenge() );
	}

	public function test_challenge_reports_a_rejected_token() {
		$_SERVER['HTTP_AUTHORIZATION'] = 'Bearer invalidtokenxyz';
		attempt_authentication();

		$challenge = build_authenticate_challenge();

		$this->assertStringContainsString( 'error="invalid_token"', $challenge );
		$this->assertStringContainsString( 'error_description="Supplied token is invalid."', $challenge );
	}

	public function test_challenge_is_bare_for_a_valid_token() {
		$client = $this->create_client();
		$token  = Access_Token::create( $client, $this->factory->user->create_and_get() );

		$_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $token->get_key();
		attempt_authentication();

		$this->assertStringNotContainsString( 'error=', build_authenticate_challenge() );
	}

	public function test_challenge_is_filterable() {
		add_filter(
			'oauth2.www_authenticate_challenge',
			function () {
				return 'Bearer realm="custom"';
			}
		);

		$this->assertEquals( 'Bearer realm="custom"', build_authenticate_challenge() );
	}

	// -------------------------------------------------------------------------
	// Invalid token status
	// -------------------------------------------------------------------------

	/**
	 * RFC 6750 section 3.1 requires 401 for an invalid token, and a challenge
	 * on a 403 would be ignored by clients.
	 */
	public function test_an_invalid_token_is_unauthorized_not_forbidden() {
		global $oauth2_error;
		$_SERVER['HTTP_AUTHORIZATION'] = 'Bearer invalidtokenxyz';

		attempt_authentication();

		$this->assertEquals( 401, $oauth2_error->get_error_data()['status'] );
	}

	// -------------------------------------------------------------------------
	// CORS
	// -------------------------------------------------------------------------

	public function test_challenge_header_is_exposed_to_cors_requests() {
		$this->assertContains( 'WWW-Authenticate', expose_authenticate_header( [ 'Link' ] ) );
	}

	// -------------------------------------------------------------------------
	// Multisite
	// -------------------------------------------------------------------------

	public function test_challenge_names_the_subsite_it_was_sent_from() {
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Requires a multisite install.' );
		}

		$site_id = $this->factory->blog->create( [ 'path' => '/blog/' ] );

		switch_to_blog( $site_id );
		update_option( 'permalink_structure', '/%postname%/' );
		$challenge = build_authenticate_challenge();
		restore_current_blog();

		$this->assertStringContainsString( '/blog/', $challenge );
	}
}
