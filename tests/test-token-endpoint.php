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
use WP\OAuth2\PersonalClient;
use WP\OAuth2\Tokens\Access_Token;
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

	public function test_exchange_token_client_id_via_basic_auth_header() {
		$user    = $this->factory->user->create_and_get();
		$code    = Authorization_Code::create( $this->client, $user );
		$encoded = base64_encode( $this->client->get_id() . ':' . $this->client->get_secret() );

		$request = new WP_REST_Request( 'POST', '/oauth2/access_token' );
		$request->set_param( 'grant_type', 'authorization_code' );
		$request->set_param( 'code', $code->get_code() );
		$request->add_header( 'Authorization', 'Basic ' . $encoded );

		$response = $this->server->dispatch( $request );

		$this->assertEquals( 200, $response->get_status() );
		$data = $response->get_data();
		$this->assertArrayHasKey( 'access_token', $data );
	}

	public function test_exchange_token_body_client_id_takes_precedence_over_basic_auth_header() {
		$user    = $this->factory->user->create_and_get();
		$code    = Authorization_Code::create( $this->client, $user );
		$encoded = base64_encode( 'nonexistent-client:any-secret' );

		$request = new WP_REST_Request( 'POST', '/oauth2/access_token' );
		$request->set_param( 'grant_type', 'authorization_code' );
		$request->set_param( 'client_id', $this->client->get_id() );
		$request->set_param( 'code', $code->get_code() );
		$request->add_header( 'Authorization', 'Basic ' . $encoded );

		$response = $this->server->dispatch( $request );

		$this->assertEquals( 200, $response->get_status() );
	}

	public function test_exchange_token_invalid_basic_auth_header() {
		$request = new WP_REST_Request( 'POST', '/oauth2/access_token' );
		$request->set_param( 'grant_type', 'authorization_code' );
		$request->set_param( 'code', 'somecode' );
		$request->add_header( 'Authorization', 'Basic not-valid-base64!!!' );

		$response = $this->server->dispatch( $request );

		$this->assertEquals( 400, $response->get_status() );
		$data = $response->get_data();
		$this->assertEquals( 'oauth2.endpoints.token.invalid_request', $data['code'] );
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

	public function test_client_credentials_basic_auth_header_is_form_decoded() {
		$client = $this->create_client( [ 'client_credentials_enabled' => true ] );
		$secret = 'a b+c';
		update_post_meta( $client->get_post_id(), Client::CLIENT_SECRET_KEY, $secret );

		// Per RFC 6749 section 2.3.1 the client form-encodes both values, so a
		// space arrives as "+" and a literal "+" as "%2B".
		$encoded = base64_encode( urlencode( $client->get_id() ) . ':' . urlencode( $secret ) );

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
	// Token expiry
	// -------------------------------------------------------------------------

	/**
	 * Run the client credentials grant for a client and return the response data.
	 *
	 * @param Client $client Client to authenticate as.
	 *
	 * @return array Response data.
	 */
	protected function request_client_credentials_token( Client $client ) {
		$request = new WP_REST_Request( 'POST', '/oauth2/access_token' );
		$request->set_param( 'grant_type', 'client_credentials' );
		$request->set_param( 'client_id', $client->get_id() );
		$request->set_param( 'client_secret', $client->get_secret() );

		$response = $this->server->dispatch( $request );
		$this->assertEquals( 200, $response->get_status() );

		return $response->get_data();
	}

	public function test_client_credentials_omits_expires_in_without_ttl() {
		$client = $this->create_client( [ 'client_credentials_enabled' => true ] );

		$data = $this->request_client_credentials_token( $client );

		$this->assertArrayNotHasKey( 'expires_in', $data );
	}

	public function test_client_credentials_returns_expires_in_with_ttl() {
		$client = $this->create_client( [
			'client_credentials_enabled' => true,
			'token_ttl'                  => 3600,
		] );

		$data = $this->request_client_credentials_token( $client );

		$this->assertArrayHasKey( 'expires_in', $data );
		// Allow a second of drift between issuing the token and reading it back.
		$this->assertEqualsWithDelta( 3600, $data['expires_in'], 1 );
	}

	public function test_client_credentials_token_expires_after_ttl() {
		$client = $this->create_client( [
			'client_credentials_enabled' => true,
			'token_ttl'                  => 3600,
		] );

		$data  = $this->request_client_credentials_token( $client );
		$token = Access_Token::get_by_id( $data['access_token'] );

		$this->assertInstanceOf( Access_Token::class, $token );
		$this->assertFalse( $token->is_expired() );
		$this->assertEqualsWithDelta( time() + 3600, $token->get_expiration_time(), 1 );
	}

	public function test_authorization_code_grant_omits_expires_in() {
		// User tokens have no TTL, so the response must not claim an expiry.
		$user = $this->factory->user->create_and_get();
		$code = Authorization_Code::create( $this->client, $user );

		$request = new WP_REST_Request( 'POST', '/oauth2/access_token' );
		$request->set_param( 'grant_type', 'authorization_code' );
		$request->set_param( 'client_id', $this->client->get_id() );
		$request->set_param( 'code', $code->get_code() );

		$response = $this->server->dispatch( $request );

		$this->assertEquals( 200, $response->get_status() );
		$this->assertArrayNotHasKey( 'expires_in', $response->get_data() );
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

	// -------------------------------------------------------------------------
	// Confidential client authentication
	// -------------------------------------------------------------------------

	/**
	 * Request an access token for a client, with an optional secret.
	 *
	 * @param Client $client Client to exchange a fresh code for.
	 * @param array  $params Extra request parameters.
	 * @param string $basic  Raw value for an Authorization header, if any.
	 *
	 * @return \WP_REST_Response Dispatched response.
	 */
	protected function request_token( Client $client, array $params = [], $basic = '' ) {
		$user = $this->factory->user->create_and_get();
		$code = Authorization_Code::create( $client, $user );

		$request = new WP_REST_Request( 'POST', '/oauth2/access_token' );
		$request->set_param( 'grant_type', 'authorization_code' );
		$request->set_param( 'code', $code->get_code() );
		foreach ( $params as $key => $value ) {
			$request->set_param( $key, $value );
		}
		if ( '' !== $basic ) {
			$request->add_header( 'Authorization', 'Basic ' . $basic );
		}

		return $this->server->dispatch( $request );
	}

	public function test_private_client_without_secret_is_rejected() {
		$client = $this->create_client( [ 'type' => 'private' ] );

		$response = $this->request_token( $client, [ 'client_id' => $client->get_id() ] );

		$this->assertEquals( 401, $response->get_status() );
		$data = $response->get_data();
		$this->assertEquals( 'oauth2.endpoints.token.invalid_client', $data['code'] );
	}

	public function test_private_client_with_correct_secret_is_accepted() {
		$client = $this->create_client( [ 'type' => 'private' ] );

		$response = $this->request_token(
			$client,
			[
				'client_id'     => $client->get_id(),
				'client_secret' => $client->get_secret(),
			]
		);

		$this->assertEquals( 200, $response->get_status() );
		$this->assertArrayHasKey( 'access_token', $response->get_data() );
	}

	public function test_private_client_with_wrong_secret_is_rejected() {
		$client = $this->create_client( [ 'type' => 'private' ] );

		$response = $this->request_token(
			$client,
			[
				'client_id'     => $client->get_id(),
				'client_secret' => 'wrong-secret',
			]
		);

		$this->assertEquals( 401, $response->get_status() );
	}

	public function test_private_client_secret_via_basic_auth_header() {
		$client  = $this->create_client( [ 'type' => 'private' ] );
		$encoded = base64_encode( $client->get_id() . ':' . $client->get_secret() );

		$response = $this->request_token( $client, [], $encoded );

		$this->assertEquals( 200, $response->get_status() );
		$this->assertArrayHasKey( 'access_token', $response->get_data() );
	}

	public function test_private_client_basic_secret_pairs_with_body_client_id() {
		$client  = $this->create_client( [ 'type' => 'private' ] );
		$encoded = base64_encode( $client->get_id() . ':' . $client->get_secret() );

		$response = $this->request_token( $client, [ 'client_id' => $client->get_id() ], $encoded );

		$this->assertEquals( 200, $response->get_status() );
	}

	public function test_private_client_basic_secret_ignored_for_another_client() {
		$client  = $this->create_client( [ 'type' => 'private' ] );
		$other   = $this->create_client( [ 'type' => 'private' ], 'Other Client' );
		$encoded = base64_encode( $other->get_id() . ':' . $other->get_secret() );

		$response = $this->request_token( $client, [ 'client_id' => $client->get_id() ], $encoded );

		$this->assertEquals( 401, $response->get_status() );
	}

	public function test_private_client_with_empty_stored_secret_is_rejected() {
		$client = $this->create_client( [ 'type' => 'private' ] );
		update_post_meta( $client->get_post_id(), Client::CLIENT_SECRET_KEY, '' );

		$response = $this->request_token(
			$client,
			[
				'client_id'     => $client->get_id(),
				'client_secret' => '',
			]
		);

		$this->assertEquals( 401, $response->get_status() );
	}

	public function test_failed_client_authentication_keeps_the_code() {
		$client = $this->create_client( [ 'type' => 'private' ] );
		$user   = $this->factory->user->create_and_get();
		$code   = Authorization_Code::create( $client, $user );

		$request = new WP_REST_Request( 'POST', '/oauth2/access_token' );
		$request->set_param( 'grant_type', 'authorization_code' );
		$request->set_param( 'client_id', $client->get_id() );
		$request->set_param( 'code', $code->get_code() );
		$this->server->dispatch( $request );

		$stored = Authorization_Code::get_by_code( $client, $code->get_code() );
		$this->assertNotWPError( $stored );
	}

	public function test_failed_basic_authentication_sends_a_challenge() {
		$client  = $this->create_client( [ 'type' => 'private' ] );
		$encoded = base64_encode( $client->get_id() . ':wrong-secret' );

		$response = $this->request_token( $client, [], $encoded );

		$this->assertEquals( 401, $response->get_status() );
		$headers = $response->get_headers();
		$this->assertArrayHasKey( 'WWW-Authenticate', $headers );
		$this->assertStringStartsWith( 'Basic realm=', $headers['WWW-Authenticate'] );
	}

	public function test_failed_body_authentication_sends_no_challenge() {
		$client = $this->create_client( [ 'type' => 'private' ] );

		$response = $this->request_token(
			$client,
			[
				'client_id'     => $client->get_id(),
				'client_secret' => 'wrong-secret',
			]
		);

		$this->assertEquals( 401, $response->get_status() );
		$this->assertArrayNotHasKey( 'WWW-Authenticate', $response->get_headers() );
	}

	public function test_public_client_without_secret_is_accepted() {
		$client = $this->create_client( [ 'type' => 'public' ] );

		$response = $this->request_token( $client, [ 'client_id' => $client->get_id() ] );

		$this->assertEquals( 200, $response->get_status() );
		$this->assertArrayHasKey( 'access_token', $response->get_data() );
	}

	public function test_client_without_a_stored_type_is_accepted() {
		$client = $this->create_client();
		delete_post_meta( $client->get_post_id(), Client::TYPE_KEY );

		$response = $this->request_token( $client, [ 'client_id' => $client->get_id() ] );

		$this->assertEquals( 200, $response->get_status() );
		$this->assertArrayHasKey( 'access_token', $response->get_data() );
	}

	public function test_requires_secret_filter_can_force_authentication() {
		$client = $this->create_client( [ 'type' => 'public' ] );
		add_filter( 'oauth2.client.requires_secret', '__return_true' );

		$response = $this->request_token( $client, [ 'client_id' => $client->get_id() ] );

		remove_filter( 'oauth2.client.requires_secret', '__return_true' );
		$this->assertEquals( 401, $response->get_status() );
	}

	public function test_personal_client_cannot_use_the_authorization_code_grant() {
		$request = new WP_REST_Request( 'POST', '/oauth2/access_token' );
		$request->set_param( 'grant_type', 'authorization_code' );
		$request->set_param( 'client_id', PersonalClient::ID );
		$request->set_param( 'code', 'anycode' );

		$response = $this->server->dispatch( $request );

		$this->assertNotEquals( 200, $response->get_status() );
		$data = $response->get_data();
		$this->assertEquals( 'oauth2.personalclient.no_auth_code', $data['code'] );
	}

	public function test_personal_client_cannot_use_the_client_credentials_grant() {
		$request = new WP_REST_Request( 'POST', '/oauth2/access_token' );
		$request->set_param( 'grant_type', 'client_credentials' );
		$request->set_param( 'client_id', PersonalClient::ID );
		$request->set_param( 'client_secret', 'any-secret' );

		$response = $this->server->dispatch( $request );

		$this->assertEquals( 401, $response->get_status() );
		$data = $response->get_data();
		$this->assertEquals( 'oauth2.endpoints.token.invalid_client', $data['code'] );
	}
}
