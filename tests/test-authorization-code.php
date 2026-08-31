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

	// RFC 7636 Appendix B worked example.
	const RFC_VERIFIER  = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
	const RFC_CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

	public function test_create_without_pkce_data_stores_no_challenge() {
		$code = Authorization_Code::create( $this->client, $this->user );
		$this->assertNull( $code->get_code_challenge() );
		$this->assertNull( $code->get_code_challenge_method() );
	}

	public function test_create_with_pkce_data_stores_challenge_and_method() {
		$code = Authorization_Code::create(
			$this->client,
			$this->user,
			[
				'code_challenge'        => static::RFC_CHALLENGE,
				'code_challenge_method' => 'S256',
			]
		);

		$this->assertSame( static::RFC_CHALLENGE, $code->get_code_challenge() );
		$this->assertSame( 'S256', $code->get_code_challenge_method() );
	}

	public function test_create_defaults_challenge_method_to_plain_when_omitted() {
		$code = Authorization_Code::create(
			$this->client,
			$this->user,
			[ 'code_challenge' => static::RFC_VERIFIER ]
		);

		$this->assertSame( 'plain', $code->get_code_challenge_method() );
	}

	public function test_create_data_cannot_override_user_or_expiration() {
		$code = Authorization_Code::create(
			$this->client,
			$this->user,
			[
				'user'       => 999999,
				'expiration' => 1,
			]
		);

		$user = $code->get_user();
		$this->assertInstanceOf( WP_User::class, $user );
		$this->assertEquals( $this->user->ID, $user->ID );
		$this->assertGreaterThan( time(), $code->get_expiration() );
	}

	public function test_validate_with_no_args_still_passes_for_non_pkce_code() {
		// Back-compat guarantee: existing callers pass no args at all.
		$code = Authorization_Code::create( $this->client, $this->user );
		$this->assertTrue( $code->validate() );
	}

	public function test_validate_passes_with_correct_s256_verifier() {
		$code = Authorization_Code::create(
			$this->client,
			$this->user,
			[
				'code_challenge'        => static::RFC_CHALLENGE,
				'code_challenge_method' => 'S256',
			]
		);

		$this->assertTrue( $code->validate( [ 'code_verifier' => static::RFC_VERIFIER ] ) );
	}

	public function test_validate_passes_with_correct_plain_verifier() {
		$code = Authorization_Code::create(
			$this->client,
			$this->user,
			[
				'code_challenge'        => static::RFC_VERIFIER,
				'code_challenge_method' => 'plain',
			]
		);

		$this->assertTrue( $code->validate( [ 'code_verifier' => static::RFC_VERIFIER ] ) );
	}

	public function test_validate_fails_with_wrong_verifier() {
		$code = Authorization_Code::create(
			$this->client,
			$this->user,
			[
				'code_challenge'        => static::RFC_CHALLENGE,
				'code_challenge_method' => 'S256',
			]
		);

		$result = $code->validate( [ 'code_verifier' => 'wrong-verifier-wrong-verifier-wrong-verifier' ] );
		$this->assertWPError( $result );
		$this->assertSame( 'invalid_grant', $result->get_error_data()['error'] );
	}

	public function test_validate_fails_with_missing_verifier() {
		$code = Authorization_Code::create(
			$this->client,
			$this->user,
			[
				'code_challenge'        => static::RFC_CHALLENGE,
				'code_challenge_method' => 'S256',
			]
		);

		$result = $code->validate();
		$this->assertWPError( $result );
		$this->assertEquals( 'oauth2.tokens.authorization_code.validate.missing_verifier', $result->get_error_code() );
	}

	public function test_validate_fails_with_malformed_verifier() {
		$code = Authorization_Code::create(
			$this->client,
			$this->user,
			[
				'code_challenge'        => static::RFC_CHALLENGE,
				'code_challenge_method' => 'S256',
			]
		);

		$result = $code->validate( [ 'code_verifier' => 'too-short' ] );
		$this->assertWPError( $result );
	}

	public function test_validate_rejects_verifier_for_code_with_no_stored_challenge() {
		$code   = Authorization_Code::create( $this->client, $this->user );
		$result = $code->validate( [ 'code_verifier' => static::RFC_VERIFIER ] );

		$this->assertWPError( $result );
		$this->assertEquals( 'oauth2.tokens.authorization_code.validate.unexpected_verifier', $result->get_error_code() );
	}

	public function test_validate_allows_unexpected_verifier_when_filtered() {
		$code = Authorization_Code::create( $this->client, $this->user );

		$filter = '__return_false';
		add_filter( 'oauth2.pkce.reject_unexpected_verifier', $filter );
		$result = $code->validate( [ 'code_verifier' => static::RFC_VERIFIER ] );
		remove_filter( 'oauth2.pkce.reject_unexpected_verifier', $filter );

		$this->assertTrue( $result );
	}

	public function test_validate_fails_closed_when_stored_method_is_missing() {
		$code     = Authorization_Code::create( $this->client, $this->user );
		$meta_key = Authorization_Code::KEY_PREFIX . $code->get_code();

		// Simulate corrupted meta: a challenge with no method.
		$value                    = get_post_meta( $this->client->get_post_id(), $meta_key, true );
		$value['code_challenge']  = static::RFC_CHALLENGE;
		update_post_meta( $this->client->get_post_id(), $meta_key, $value );

		$result = $code->validate( [ 'code_verifier' => static::RFC_VERIFIER ] );
		$this->assertWPError( $result );
		$this->assertEquals( 'oauth2.tokens.authorization_code.validate.missing_challenge_method', $result->get_error_code() );
	}

	public function test_validate_with_malformed_meta_does_not_pass_expiry_check() {
		$code     = Authorization_Code::create( $this->client, $this->user );
		$meta_key = Authorization_Code::KEY_PREFIX . $code->get_code();

		// Corrupt the expiration entirely; get_expiration() now returns a WP_Error.
		$value = get_post_meta( $this->client->get_post_id(), $meta_key, true );
		unset( $value['expiration'] );
		update_post_meta( $this->client->get_post_id(), $meta_key, $value );

		$result = $code->validate();
		$this->assertWPError( $result );
	}
}
