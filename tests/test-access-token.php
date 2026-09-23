<?php
/**
 * Tests for the Access_Token class.
 *
 * @package WP\OAuth2\Tests
 */

namespace WP\OAuth2\Tests;

require_once __DIR__ . '/class-test-case.php';

use WP\OAuth2\Client;
use WP\OAuth2\ClientInterface;
use WP\OAuth2\PersonalClient;
use WP\OAuth2\Tokens\Access_Token;
use WP_User;

/**
 * Test cases for Access_Token functionality.
 */
class Test_Access_Token extends Test_Case {

	/**
	 * @var Client
	 */
	protected $client;

	/**
	 * @var WP_User
	 */
	protected $user;

	public function set_up() {
		parent::set_up();
		$this->client = $this->create_client();
		$this->user   = $this->factory->user->create_and_get();
	}

	public function test_create_returns_token_instance() {
		$token = Access_Token::create( $this->client, $this->user );
		$this->assertInstanceOf( Access_Token::class, $token );
	}

	public function test_create_stores_user_meta() {
		$token    = Access_Token::create( $this->client, $this->user );
		$meta_key = Access_Token::META_PREFIX . $token->get_key();
		$value    = get_user_meta( $this->user->ID, $meta_key, false );
		$this->assertNotEmpty( $value );
	}

	public function test_create_returns_error_for_invalid_user() {
		$invalid_user = new WP_User();
		$result       = Access_Token::create( $this->client, $invalid_user );
		$this->assertWPError( $result );
		$this->assertEquals( 'oauth2.tokens.access_token.create.no_user', $result->get_error_code() );
	}

	public function test_create_for_client_returns_token() {
		$client = $this->create_client( [ 'client_credentials_enabled' => true ] );
		$token  = Access_Token::create_for_client( $client );
		$this->assertInstanceOf( Access_Token::class, $token );
	}

	public function test_create_for_client_stores_post_meta() {
		$client   = $this->create_client( [ 'client_credentials_enabled' => true ] );
		$token    = Access_Token::create_for_client( $client );
		$meta_key = Access_Token::CLIENT_META_PREFIX . $token->get_key();
		$value    = get_post_meta( $client->get_post_id(), $meta_key, true );
		$this->assertNotEmpty( $value );
	}

	public function test_create_for_client_errors_for_personal_client() {
		$personal = PersonalClient::get_instance();
		$result   = Access_Token::create_for_client( $personal );
		$this->assertWPError( $result );
		$this->assertEquals( 'oauth2.tokens.access_token.create_for_client.invalid_client', $result->get_error_code() );
	}

	public function test_is_client_token_false_for_user_token() {
		$token = Access_Token::create( $this->client, $this->user );
		$this->assertFalse( $token->is_client_token() );
	}

	public function test_is_client_token_true_for_client_token() {
		$client = $this->create_client( [ 'client_credentials_enabled' => true ] );
		$token  = Access_Token::create_for_client( $client );
		$this->assertTrue( $token->is_client_token() );
	}

	public function test_get_by_id_finds_user_token() {
		$token = Access_Token::create( $this->client, $this->user );
		$found = Access_Token::get_by_id( $token->get_key() );
		$this->assertInstanceOf( Access_Token::class, $found );
		$this->assertEquals( $token->get_key(), $found->get_key() );
	}

	public function test_get_by_id_finds_client_token() {
		$client = $this->create_client( [ 'client_credentials_enabled' => true ] );
		$token  = Access_Token::create_for_client( $client );
		$found  = Access_Token::get_by_id( $token->get_key() );
		$this->assertInstanceOf( Access_Token::class, $found );
		$this->assertEquals( $token->get_key(), $found->get_key() );
	}

	public function test_get_by_id_returns_null_for_missing() {
		$result = Access_Token::get_by_id( 'nonexistenttoken' );
		$this->assertNull( $result );
	}

	public function test_get_for_user_returns_all_user_tokens() {
		Access_Token::create( $this->client, $this->user );
		Access_Token::create( $this->client, $this->user );

		$tokens = Access_Token::get_for_user( $this->user );
		$this->assertCount( 2, $tokens );
	}

	public function test_revoke_deletes_user_meta() {
		$token = Access_Token::create( $this->client, $this->user );
		$key   = $token->get_key();
		$token->revoke();

		$found = Access_Token::get_by_id( $key );
		$this->assertNull( $found );
	}

	public function test_revoke_deletes_client_token_post_meta() {
		$client = $this->create_client( [ 'client_credentials_enabled' => true ] );
		$token  = Access_Token::create_for_client( $client );
		$key    = $token->get_key();
		$token->revoke();

		$found = Access_Token::get_by_id( $key );
		$this->assertNull( $found );
	}

	public function test_get_client_returns_client_instance() {
		$token  = Access_Token::create( $this->client, $this->user );
		$client = $token->get_client();
		$this->assertInstanceOf( ClientInterface::class, $client );
	}

	public function test_get_creation_time_is_recent() {
		$before = time();
		$token  = Access_Token::create( $this->client, $this->user );
		$after  = time();

		$created = $token->get_creation_time();
		$this->assertGreaterThanOrEqual( $before, $created );
		$this->assertLessThanOrEqual( $after, $created );
	}

	public function test_is_valid_true_for_token_without_expiry() {
		$token = Access_Token::create( $this->client, $this->user );
		$this->assertTrue( $token->is_valid() );
	}

	public function test_get_meta_returns_null_for_missing_key() {
		$token = Access_Token::create( $this->client, $this->user );
		$this->assertNull( $token->get_meta( 'nonexistent_key' ) );
	}

	public function test_set_and_get_meta_roundtrip() {
		$token = Access_Token::create( $this->client, $this->user );
		$token->set_meta( 'description', 'My token' );
		$this->assertEquals( 'My token', $token->get_meta( 'description' ) );
	}

	public function test_set_meta_persists_to_database() {
		$token = Access_Token::create( $this->client, $this->user );
		$token->set_meta( 'description', 'Persisted' );

		$reloaded = Access_Token::get_by_id( $token->get_key() );
		$this->assertInstanceOf( Access_Token::class, $reloaded );
		$this->assertEquals( 'Persisted', $reloaded->get_meta( 'description' ) );
	}

	// -------------------------------------------------------------------------
	// Expiry
	// -------------------------------------------------------------------------

	/**
	 * Create a client credentials client with the given TTL.
	 *
	 * @param int|string $ttl TTL in seconds, or '' for no expiry.
	 *
	 * @return Client
	 */
	protected function create_ttl_client( $ttl ) {
		return $this->create_client( [
			'client_credentials_enabled' => true,
			'token_ttl'                  => $ttl,
		] );
	}

	/**
	 * Rewrite a client token's stored expiry timestamp.
	 *
	 * @param Client       $client  Client the token belongs to.
	 * @param Access_Token $token   Token to rewrite.
	 * @param int          $expires Expiry timestamp to store.
	 */
	protected function set_stored_expiry( Client $client, Access_Token $token, $expires ) {
		$meta_key            = Access_Token::CLIENT_META_PREFIX . $token->get_key();
		$value               = get_post_meta( $client->get_post_id(), $meta_key, true );
		$value['expires']    = $expires;
		update_post_meta( $client->get_post_id(), $meta_key, $value );
	}

	public function test_create_for_client_without_ttl_has_no_expiry() {
		$client = $this->create_ttl_client( '' );
		$token  = Access_Token::create_for_client( $client );

		$this->assertNull( $token->get_expiration_time() );
	}

	public function test_create_for_client_with_ttl_sets_expiry() {
		$before = time();
		$client = $this->create_ttl_client( 3600 );
		$token  = Access_Token::create_for_client( $client );
		$after  = time();

		$this->assertGreaterThanOrEqual( $before + 3600, $token->get_expiration_time() );
		$this->assertLessThanOrEqual( $after + 3600, $token->get_expiration_time() );
	}

	public function test_create_for_client_persists_expiry() {
		$client = $this->create_ttl_client( 3600 );
		$token  = Access_Token::create_for_client( $client );

		$reloaded = Access_Token::get_by_id( $token->get_key() );
		$this->assertInstanceOf( Access_Token::class, $reloaded );
		$this->assertEquals( $token->get_expiration_time(), $reloaded->get_expiration_time() );
	}

	public function test_is_expired_false_for_token_without_expiry() {
		$client = $this->create_ttl_client( '' );
		$token  = Access_Token::create_for_client( $client );

		$this->assertFalse( $token->is_expired() );
	}

	public function test_is_expired_false_for_user_token() {
		$token = Access_Token::create( $this->client, $this->user );
		$this->assertFalse( $token->is_expired() );
	}

	public function test_is_expired_false_within_ttl() {
		$client = $this->create_ttl_client( 3600 );
		$token  = Access_Token::create_for_client( $client );

		$this->assertFalse( $token->is_expired() );
	}

	public function test_is_expired_true_after_ttl() {
		$client = $this->create_ttl_client( 3600 );
		$token  = Access_Token::create_for_client( $client );
		$this->set_stored_expiry( $client, $token, time() - 1 );

		$reloaded = Access_Token::get_by_id( $token->get_key() );
		$this->assertTrue( $reloaded->is_expired() );
	}

	public function test_is_expired_true_at_exact_expiry_time() {
		$client = $this->create_ttl_client( 3600 );
		$token  = Access_Token::create_for_client( $client );
		$this->set_stored_expiry( $client, $token, time() );

		$reloaded = Access_Token::get_by_id( $token->get_key() );
		$this->assertTrue( $reloaded->is_expired() );
	}

	public function test_is_valid_false_for_expired_token() {
		$client = $this->create_ttl_client( 3600 );
		$token  = Access_Token::create_for_client( $client );
		$this->set_stored_expiry( $client, $token, time() - 1 );

		$reloaded = Access_Token::get_by_id( $token->get_key() );
		$this->assertFalse( $reloaded->is_valid() );
	}

	public function test_zero_ttl_expires_token_immediately() {
		$client = $this->create_ttl_client( 0 );
		$token  = Access_Token::create_for_client( $client );

		$this->assertTrue( $token->is_expired() );
	}

	public function test_expired_token_is_still_retrievable() {
		// Expiry is checked on use, not on lookup: an expired token still
		// resolves so callers can tell "expired" from "unknown".
		$client = $this->create_ttl_client( 3600 );
		$token  = Access_Token::create_for_client( $client );
		$this->set_stored_expiry( $client, $token, time() - 1 );

		$this->assertInstanceOf( Access_Token::class, Access_Token::get_by_id( $token->get_key() ) );
	}
}
