<?php
/**
 * Tests for the Authorization_Code class.
 *
 * @package WP\OAuth2\Tests
 */

namespace WP\OAuth2\Tests;

require_once __DIR__ . '/class-test-case.php';

use WP\OAuth2\Client;
use WP\OAuth2\Tokens\Authorization_Code;
use WP_User;

/**
 * Test cases for Authorization_Code functionality.
 */
class Test_Authorization_Code extends Test_Case {

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

	public function test_create_returns_instance() {
		$code = Authorization_Code::create( $this->client, $this->user );
		$this->assertInstanceOf( Authorization_Code::class, $code );
	}

	public function test_create_stores_meta_on_client_post() {
		$code     = Authorization_Code::create( $this->client, $this->user );
		$meta_key = Authorization_Code::KEY_PREFIX . $code->get_code();
		$value    = get_post_meta( $this->client->get_post_id(), $meta_key, false );
		$this->assertNotEmpty( $value );
	}

	public function test_get_by_code_returns_instance_for_valid_code() {
		$code   = Authorization_Code::create( $this->client, $this->user );
		$found  = Authorization_Code::get_by_code( $this->client, $code->get_code() );
		$this->assertInstanceOf( Authorization_Code::class, $found );
	}

	public function test_get_by_code_returns_error_for_invalid_code() {
		$result = Authorization_Code::get_by_code( $this->client, 'invalid-code-xyz' );
		$this->assertWPError( $result );
	}

	public function test_get_user_returns_correct_user() {
		$code = Authorization_Code::create( $this->client, $this->user );
		$user = $code->get_user();
		$this->assertInstanceOf( WP_User::class, $user );
		$this->assertEquals( $this->user->ID, $user->ID );
	}

	public function test_get_expiration_is_in_future() {
		$code       = Authorization_Code::create( $this->client, $this->user );
		$expiration = $code->get_expiration();
		$this->assertGreaterThan( time(), $expiration );
	}

	public function test_validate_returns_true_for_fresh_code() {
		$code   = Authorization_Code::create( $this->client, $this->user );
		$result = $code->validate();
		$this->assertTrue( $result );
	}

	public function test_validate_returns_error_for_expired_code() {
		$code     = Authorization_Code::create( $this->client, $this->user );
		$meta_key = Authorization_Code::KEY_PREFIX . $code->get_code();

		// Backdate the expiration to force expiry.
		$value               = get_post_meta( $this->client->get_post_id(), $meta_key, true );
		$value['expiration'] = time() - 1;
		update_post_meta( $this->client->get_post_id(), $meta_key, $value );

		$result = $code->validate();
		$this->assertWPError( $result );
		$this->assertEquals( 'oauth2.tokens.authorization_code.validate.expired', $result->get_error_code() );
	}

	public function test_delete_removes_the_meta() {
		$code = Authorization_Code::create( $this->client, $this->user );
		$code->delete();

		$result = Authorization_Code::get_by_code( $this->client, $code->get_code() );
		$this->assertWPError( $result );
	}

	public function test_code_is_valid_only_for_its_client() {
		$other_client = $this->create_client( [], 'Other Client' );
		$code         = Authorization_Code::create( $this->client, $this->user );

		$result = Authorization_Code::get_by_code( $other_client, $code->get_code() );
		$this->assertWPError( $result );
	}
}
