<?php
/**
 * Tests for the Client class.
 *
 * @package WP\OAuth2\Tests
 */

namespace WP\OAuth2\Tests;

require_once __DIR__ . '/class-test-case.php';

use WP\OAuth2\Client;
use WP\OAuth2\Tokens\Access_Token;

/**
 * Test cases for Client class functionality.
 */
class Test_Client extends Test_Case {

	/**
	 * @var Client
	 */
	protected $client;

	public function set_up() {
		parent::set_up();
		$this->client = $this->create_client();
	}

	public function test_create_returns_client_instance() {
		$client = Client::create( [
			'name'        => 'New Client',
			'description' => 'A description.',
			'meta'        => [
				'callback'                   => 'https://example.com/callback',
				'type'                       => 'web',
				'client_credentials_enabled' => false,
			],
		] );
		$this->assertInstanceOf( Client::class, $client );
	}

	public function test_create_stores_correct_post_type() {
		$post = get_post( $this->client->get_post_id() );
		$this->assertEquals( Client::POST_TYPE, $post->post_type );
	}

	public function test_create_stores_redirect_uri() {
		$uris = $this->client->get_redirect_uris();
		$this->assertContains( 'https://example.com/callback', $uris );
	}

	public function test_create_stores_type() {
		$this->assertEquals( 'web', $this->client->get_type() );
	}

	public function test_create_stores_secret() {
		$secret = $this->client->get_secret();
		$this->assertNotEmpty( $secret );
		$this->assertIsString( $secret );
	}

	public function test_create_client_credentials_flag_disabled() {
		$this->assertFalse( $this->client->is_client_credentials_enabled() );
	}

	public function test_create_client_credentials_flag_enabled() {
		$client = $this->create_client( [ 'client_credentials_enabled' => true ] );
		$this->assertTrue( $client->is_client_credentials_enabled() );
	}

	public function test_get_by_id_finds_approved_client() {
		$found = Client::get_by_id( $this->client->get_id() );
		$this->assertInstanceOf( Client::class, $found );
		$this->assertEquals( $this->client->get_id(), $found->get_id() );
	}

	public function test_get_by_id_returns_null_for_unknown() {
		$result = Client::get_by_id( 'nonexistent-client-id' );
		$this->assertNull( $result );
	}

	public function test_get_by_id_returns_null_for_unapproved() {
		$data = [
			'name'        => 'Unapproved',
			'description' => 'Draft client.',
			'meta'        => [
				'callback'                   => 'https://example.com/callback',
				'type'                       => 'web',
				'client_credentials_enabled' => false,
			],
		];
		$draft_client = Client::create( $data );
		$this->assertInstanceOf( Client::class, $draft_client );

		$result = Client::get_by_id( $draft_client->get_id() );
		$this->assertNull( $result );
	}

	public function test_get_by_post_id_finds_client() {
		$found = Client::get_by_post_id( $this->client->get_post_id() );
		$this->assertInstanceOf( Client::class, $found );
		$this->assertEquals( $this->client->get_post_id(), $found->get_post_id() );
	}

	public function test_get_by_post_id_returns_null_for_missing() {
		$result = Client::get_by_post_id( 99999999 );
		$this->assertNull( $result );
	}

	public function test_approve_publishes_post() {
		$data = [
			'name'        => 'To Approve',
			'description' => 'Draft.',
			'meta'        => [
				'callback'                   => 'https://example.com/callback',
				'type'                       => 'web',
				'client_credentials_enabled' => false,
			],
		];
		$client = Client::create( $data );
		$this->assertInstanceOf( Client::class, $client );

		$post = get_post( $client->get_post_id() );
		$this->assertEquals( 'draft', $post->post_status );

		$client->approve();

		$post = get_post( $client->get_post_id() );
		$this->assertEquals( 'publish', $post->post_status );
	}

	public function test_delete_removes_post() {
		$post_id = $this->client->get_post_id();
		$this->client->delete();
		$this->assertNull( get_post( $post_id ) );
	}

	public function test_regenerate_secret_changes_secret() {
		$original = $this->client->get_secret();
		$this->client->regenerate_secret();
		$new = $this->client->get_secret();
		$this->assertNotEquals( $original, $new );
		$this->assertNotEmpty( $new );
	}

	public function test_check_secret_true_for_correct_secret() {
		$secret = $this->client->get_secret();
		$this->assertTrue( $this->client->check_secret( $secret ) );
	}

	public function test_check_secret_false_for_wrong_secret() {
		$this->assertFalse( $this->client->check_secret( 'wrongsecret' ) );
	}

	public function test_update_changes_name() {
		$updated = $this->client->update( [
			'name'        => 'Updated Name',
			'description' => 'Updated description.',
			'meta'        => [
				'callback'                   => 'https://example.com/callback',
				'type'                       => 'web',
				'client_credentials_enabled' => false,
			],
		] );
		$this->assertInstanceOf( Client::class, $updated );
		$this->assertEquals( 'Updated Name', $updated->get_name() );
	}

	public function test_issue_token_returns_access_token() {
		$user  = $this->factory->user->create_and_get();
		$token = $this->client->issue_token( $user );
		$this->assertInstanceOf( Access_Token::class, $token );
	}

	public function test_validate_callback_accepts_https() {
		$this->assertTrue( Client::validate_callback( 'https://example.com/callback' ) );
	}

	public function test_validate_callback_accepts_http() {
		$this->assertTrue( Client::validate_callback( 'http://example.com/callback' ) );
	}

	public function test_validate_callback_accepts_custom_scheme() {
		$this->assertTrue( Client::validate_callback( 'myapp://callback' ) );
	}

	public function test_validate_callback_rejects_no_colon() {
		$this->assertFalse( Client::validate_callback( '//example.com/callback' ) );
	}

	public function test_validate_callback_rejects_credentials_in_url() {
		$this->assertFalse( Client::validate_callback( 'https://user@example.com/callback' ) );
	}

	public function test_validate_callback_rejects_ipv6_host() {
		// IPv6 literal addresses have colons in the host, which are rejected.
		$this->assertFalse( Client::validate_callback( 'http://[::1]/callback' ) );
	}

	public function test_check_redirect_uri_matches_exact() {
		$this->assertTrue( $this->client->check_redirect_uri( 'https://example.com/callback' ) );
	}

	public function test_check_redirect_uri_ignores_query_string() {
		$this->assertTrue( $this->client->check_redirect_uri( 'https://example.com/callback?foo=bar' ) );
	}

	public function test_check_redirect_uri_rejects_different_host() {
		$this->assertFalse( $this->client->check_redirect_uri( 'https://other.com/callback' ) );
	}

	public function test_check_redirect_uri_rejects_different_path() {
		$this->assertFalse( $this->client->check_redirect_uri( 'https://example.com/other' ) );
	}

	public function test_check_redirect_uri_rejects_unregistered() {
		$this->assertFalse( $this->client->check_redirect_uri( 'https://evil.com/steal' ) );
	}
}
