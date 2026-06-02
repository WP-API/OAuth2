<?php
/**
 * Tests for the Token REST endpoint.
 *
 * @package WP\OAuth2\Tests
 */

namespace WP\OAuth2\Tests;

require_once __DIR__ . '/class-test-case.php';

use WP\OAuth2\Client;
use WP\OAuth2\Endpoints\Token;
use WP\OAuth2\Tokens\Authorization_Code;
use WP_REST_Request;
use WP_REST_Server;

/**
 * Test cases for the /oauth2/access_token REST endpoint.
 */
class Test_Token_Endpoint extends Test_Case {

	/**
	 * @var WP_REST_Server
	 */
	protected $server;

	/**
	 * @var Client
	 */
	protected $client;

	public function set_up() {
		parent::set_up();
		global $wp_rest_server;
		$this->server = $wp_rest_server = new WP_REST_Server();
		do_action( 'rest_api_init', $this->server );
		$this->client = $this->create_client();
	}

	public function tear_down() {
		global $wp_rest_server;
		$wp_rest_server = null;
		parent::tear_down();
	}

	// -------------------------------------------------------------------------
	// Authorization code grant
	// -------------------------------------------------------------------------

	public function test_exchange_token_missing_client_id() {
		$request = new WP_REST_Request( 'POST', '/oauth2/access_token' );
		$request->set_param( 'grant_type', 'authorization_code' );
		$request->set_param( 'code', 'somecode' );

		$response = $this->server->dispatch( $request );

		$this->assertEquals( 400, $response->get_status() );
		$data = $response->get_data();
		$this->assertEquals( 'rest_missing_callback_param', $data['code'] );
	}

	public function test_exchange_token_missing_code() {
		$request = new WP_REST_Request( 'POST', '/oauth2/access_token' );
		$request->set_param( 'grant_type', 'authorization_code' );
		$request->set_param( 'client_id', $this->client->get_id() );

		$response = $this->server->dispatch( $request );

		$this->assertEquals( 400, $response->get_status() );
		$data = $response->get_data();
		$this->assertEquals( 'rest_missing_callback_param', $data['code'] );
	}

	public function test_exchange_token_invalid_client() {
		$request = new WP_REST_Request( 'POST', '/oauth2/access_token' );
		$request->set_param( 'grant_type', 'authorization_code' );
		$request->set_param( 'client_id', 'nonexistent-client' );
		$request->set_param( 'code', 'anycode' );

		$response = $this->server->dispatch( $request );

		$this->assertEquals( 400, $response->get_status() );
		$data = $response->get_data();
		$this->assertEquals( 'oauth2.endpoints.token.exchange_token.invalid_client', $data['code'] );
	}

	public function test_exchange_token_invalid_code() {
		$request = new WP_REST_Request( 'POST', '/oauth2/access_token' );
		$request->set_param( 'grant_type', 'authorization_code' );
		$request->set_param( 'client_id', $this->client->get_id() );
		$request->set_param( 'code', 'invalid-code-xyz' );

		$response = $this->server->dispatch( $request );

		$this->assertNotEquals( 200, $response->get_status() );
	}

	public function test_exchange_token_expired_code() {
		$user = $this->factory->user->create_and_get();
		$code = Authorization_Code::create( $this->client, $user );

		// Backdate the expiration.
		$meta_key            = Authorization_Code::KEY_PREFIX . $code->get_code();
		$value               = get_post_meta( $this->client->get_post_id(), $meta_key, true );
		$value['expiration'] = time() - 1;
		update_post_meta( $this->client->get_post_id(), $meta_key, $value );

		$request = new WP_REST_Request( 'POST', '/oauth2/access_token' );
		$request->set_param( 'grant_type', 'authorization_code' );
		$request->set_param( 'client_id', $this->client->get_id() );
		$request->set_param( 'code', $code->get_code() );

		$response = $this->server->dispatch( $request );

		$this->assertEquals( 400, $response->get_status() );
	}

	public function test_exchange_token_valid() {
		$user = $this->factory->user->create_and_get();
		$code = Authorization_Code::create( $this->client, $user );

		$request = new WP_REST_Request( 'POST', '/oauth2/access_token' );
		$request->set_param( 'grant_type', 'authorization_code' );
		$request->set_param( 'client_id', $this->client->get_id() );
		$request->set_param( 'code', $code->get_code() );

		$response = $this->server->dispatch( $request );

		$this->assertEquals( 200, $response->get_status() );
		$data = $response->get_data();
		$this->assertArrayHasKey( 'access_token', $data );
		$this->assertEquals( 'bearer', $data['token_type'] );
	}

	public function test_exchange_token_deletes_code_after_use() {
		$user = $this->factory->user->create_and_get();
		$code = Authorization_Code::create( $this->client, $user );

		$request = new WP_REST_Request( 'POST', '/oauth2/access_token' );
		$request->set_param( 'grant_type', 'authorization_code' );
		$request->set_param( 'client_id', $this->client->get_id() );
		$request->set_param( 'code', $code->get_code() );

		$this->server->dispatch( $request );

		$reuse = Authorization_Code::get_by_code( $this->client, $code->get_code() );
		$this->assertWPError( $reuse );
	}

	// -------------------------------------------------------------------------
	// Client credentials grant
	// -------------------------------------------------------------------------

	public function test_client_credentials_via_body_params() {
		$client = $this->create_client( [ 'client_credentials_enabled' => true ] );
		$secret = $client->get_secret();

		$request = new WP_REST_Request( 'POST', '/oauth2/access_token' );
		$request->set_param( 'grant_type', 'client_credentials' );
		$request->set_param( 'client_id', $client->get_id() );
		$request->set_param( 'client_secret', $secret );

		$response = $this->server->dispatch( $request );

		$this->assertEquals( 200, $response->get_status() );
		$data = $response->get_data();
		$this->assertArrayHasKey( 'access_token', $data );
		$this->assertEquals( 'bearer', $data['token_type'] );
	}

	public function test_client_credentials_via_basic_auth_header() {
		$client  = $this->create_client( [ 'client_credentials_enabled' => true ] );
		$secret  = $client->get_secret();
		$encoded = base64_encode( $client->get_id() . ':' . $secret );

		$request = new WP_REST_Request( 'POST', '/oauth2/access_token' );
		$request->set_param( 'grant_type', 'client_credentials' );
		$request->add_header( 'Authorization', 'Basic ' . $encoded );

		$response = $this->server->dispatch( $request );

		$this->assertEquals( 200, $response->get_status() );
		$data = $response->get_data();
		$this->assertArrayHasKey( 'access_token', $data );
	}

	public function test_client_credentials_wrong_secret() {
		$client = $this->create_client( [ 'client_credentials_enabled' => true ] );

		$request = new WP_REST_Request( 'POST', '/oauth2/access_token' );
		$request->set_param( 'grant_type', 'client_credentials' );
		$request->set_param( 'client_id', $client->get_id() );
		$request->set_param( 'client_secret', 'wrong-secret' );

		$response = $this->server->dispatch( $request );

		$this->assertEquals( 401, $response->get_status() );
	}

	public function test_client_credentials_grant_disabled() {
		$secret = $this->client->get_secret();

		$request = new WP_REST_Request( 'POST', '/oauth2/access_token' );
		$request->set_param( 'grant_type', 'client_credentials' );
		$request->set_param( 'client_id', $this->client->get_id() );
		$request->set_param( 'client_secret', $secret );

		$response = $this->server->dispatch( $request );

		$this->assertEquals( 401, $response->get_status() );
	}

	public function test_client_credentials_unknown_client() {
		$request = new WP_REST_Request( 'POST', '/oauth2/access_token' );
		$request->set_param( 'grant_type', 'client_credentials' );
		$request->set_param( 'client_id', 'nonexistent-client' );
		$request->set_param( 'client_secret', 'any-secret' );

		$response = $this->server->dispatch( $request );

		$this->assertEquals( 401, $response->get_status() );
	}

	public function test_client_credentials_invalid_basic_header() {
		$request = new WP_REST_Request( 'POST', '/oauth2/access_token' );
		$request->set_param( 'grant_type', 'client_credentials' );
		$request->add_header( 'Authorization', 'Basic not-valid-base64!!!' );

		$response = $this->server->dispatch( $request );

		$this->assertEquals( 400, $response->get_status() );
	}

	public function test_client_credentials_header_no_colon() {
		// Valid base64 but no colon separator between id and secret.
		$encoded = base64_encode( 'nocoolonseparator' );

		$request = new WP_REST_Request( 'POST', '/oauth2/access_token' );
		$request->set_param( 'grant_type', 'client_credentials' );
		$request->add_header( 'Authorization', 'Basic ' . $encoded );

		$response = $this->server->dispatch( $request );

		$this->assertEquals( 400, $response->get_status() );
	}

	public function test_client_credentials_no_credentials_provided() {
		$request = new WP_REST_Request( 'POST', '/oauth2/access_token' );
		$request->set_param( 'grant_type', 'client_credentials' );

		$response = $this->server->dispatch( $request );

		$this->assertEquals( 400, $response->get_status() );
	}

	// -------------------------------------------------------------------------
	// Grant type validation
	// -------------------------------------------------------------------------

	public function test_validate_grant_type_accepts_authorization_code() {
		$handler = new Token();
		$this->assertTrue( $handler->validate_grant_type( 'authorization_code' ) );
	}

	public function test_validate_grant_type_accepts_client_credentials() {
		$handler = new Token();
		$this->assertTrue( $handler->validate_grant_type( 'client_credentials' ) );
	}

	public function test_validate_grant_type_rejects_unknown() {
		$handler = new Token();
		$this->assertFalse( $handler->validate_grant_type( 'password' ) );
		$this->assertFalse( $handler->validate_grant_type( 'implicit' ) );
		$this->assertFalse( $handler->validate_grant_type( '' ) );
	}
}
