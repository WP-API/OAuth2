<?php
/**
 * Tests for the PKCE helper class.
 *
 * @package WP\OAuth2\Tests
 */

namespace WP\OAuth2\Tests;

require_once __DIR__ . '/class-test-case.php';

use WP\OAuth2\PKCE;

/**
 * Test cases for PKCE functionality.
 */
class Test_PKCE extends Test_Case {

	// RFC 7636 Appendix B worked example.
	const RFC_VERIFIER  = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
	const RFC_CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

	public function test_derive_challenge_matches_rfc_7636_test_vector() {
		$this->assertSame( static::RFC_CHALLENGE, PKCE::derive_challenge( static::RFC_VERIFIER, PKCE::METHOD_S256 ) );
	}

	public function test_s256_challenge_is_unpadded_base64url() {
		$challenge = PKCE::derive_challenge( static::RFC_VERIFIER, PKCE::METHOD_S256 );

		$this->assertSame( 43, strlen( $challenge ) );
		$this->assertMatchesRegularExpression( '/^[A-Za-z0-9\-_]+$/', $challenge );
		$this->assertStringNotContainsString( '=', $challenge );
		$this->assertStringNotContainsString( '+', $challenge );
		$this->assertStringNotContainsString( '/', $challenge );
	}

	public function test_plain_challenge_is_the_verifier_verbatim() {
		$this->assertSame( static::RFC_VERIFIER, PKCE::derive_challenge( static::RFC_VERIFIER, PKCE::METHOD_PLAIN ) );
	}

	public function test_derive_challenge_returns_null_for_unknown_method() {
		$this->assertNull( PKCE::derive_challenge( static::RFC_VERIFIER, 'md5' ) );
	}

	public function test_derive_challenge_is_case_sensitive() {
		$this->assertNull( PKCE::derive_challenge( static::RFC_VERIFIER, 's256' ) );
	}

	public function test_verify_true_for_matching_s256_pair() {
		$this->assertTrue( PKCE::verify( static::RFC_VERIFIER, static::RFC_CHALLENGE, PKCE::METHOD_S256 ) );
	}

	public function test_verify_false_for_wrong_verifier() {
		$this->assertFalse( PKCE::verify( 'wrong-verifier-wrong-verifier-wrong-verifier', static::RFC_CHALLENGE, PKCE::METHOD_S256 ) );
	}

	public function test_verify_true_for_matching_plain_pair() {
		$this->assertTrue( PKCE::verify( static::RFC_VERIFIER, static::RFC_VERIFIER, PKCE::METHOD_PLAIN ) );
	}

	public function test_verify_returns_false_not_typeerror_for_unknown_method() {
		$this->assertFalse( PKCE::verify( static::RFC_VERIFIER, static::RFC_CHALLENGE, 'md5' ) );
	}

	public function test_verify_returns_false_not_typeerror_for_array_verifier() {
		$this->assertFalse( PKCE::verify( [ 'x' ], static::RFC_CHALLENGE, PKCE::METHOD_S256 ) );
	}

	public function test_verify_returns_false_not_typeerror_for_array_challenge() {
		$this->assertFalse( PKCE::verify( static::RFC_VERIFIER, [ 'x' ], PKCE::METHOD_S256 ) );
	}

	public function test_is_valid_verifier_accepts_boundary_lengths() {
		$this->assertTrue( PKCE::is_valid_verifier( str_repeat( 'a', 43 ) ) );
		$this->assertTrue( PKCE::is_valid_verifier( str_repeat( 'a', 128 ) ) );
	}

	public function test_is_valid_verifier_rejects_lengths_outside_boundary() {
		$this->assertFalse( PKCE::is_valid_verifier( str_repeat( 'a', 42 ) ) );
		$this->assertFalse( PKCE::is_valid_verifier( str_repeat( 'a', 129 ) ) );
	}

	public function test_is_valid_verifier_rejects_disallowed_characters() {
		$base = str_repeat( 'a', 42 );

		$this->assertFalse( PKCE::is_valid_verifier( $base . '+' ) );
		$this->assertFalse( PKCE::is_valid_verifier( $base . '/' ) );
		$this->assertFalse( PKCE::is_valid_verifier( $base . '=' ) );
		$this->assertFalse( PKCE::is_valid_verifier( $base . ' ' ) );
		$this->assertFalse( PKCE::is_valid_verifier( $base . '%' ) );
	}

	public function test_is_valid_verifier_rejects_trailing_newline() {
		// A `$`-anchored regex would accept a trailing newline; `\z` must not.
		$this->assertFalse( PKCE::is_valid_verifier( str_repeat( 'a', 43 ) . "\n" ) );
	}

	public function test_is_valid_verifier_rejects_non_string() {
		$this->assertFalse( PKCE::is_valid_verifier( [ 'x' ] ) );
	}

	public function test_is_valid_challenge_for_s256_requires_exactly_43_characters() {
		$this->assertFalse( PKCE::is_valid_challenge( str_repeat( 'a', 42 ), PKCE::METHOD_S256 ) );
		$this->assertTrue( PKCE::is_valid_challenge( str_repeat( 'a', 43 ), PKCE::METHOD_S256 ) );
		$this->assertFalse( PKCE::is_valid_challenge( str_repeat( 'a', 44 ), PKCE::METHOD_S256 ) );
	}

	public function test_is_valid_challenge_for_s256_rejects_padding() {
		$this->assertFalse( PKCE::is_valid_challenge( str_repeat( 'a', 42 ) . '=', PKCE::METHOD_S256 ) );
	}

	public function test_is_valid_challenge_for_s256_rejects_verifier_only_characters() {
		// '.' and '~' are valid in a verifier, but not in base64url.
		$this->assertFalse( PKCE::is_valid_challenge( str_repeat( 'a', 42 ) . '.', PKCE::METHOD_S256 ) );
		$this->assertFalse( PKCE::is_valid_challenge( str_repeat( 'a', 42 ) . '~', PKCE::METHOD_S256 ) );
	}

	public function test_is_valid_challenge_for_plain_uses_verifier_rules() {
		$this->assertTrue( PKCE::is_valid_challenge( static::RFC_VERIFIER, PKCE::METHOD_PLAIN ) );
		$this->assertFalse( PKCE::is_valid_challenge( str_repeat( 'a', 42 ), PKCE::METHOD_PLAIN ) );
	}

	public function test_is_valid_challenge_rejects_unknown_method() {
		$this->assertFalse( PKCE::is_valid_challenge( static::RFC_CHALLENGE, 'md5' ) );
	}

	public function test_supported_methods_defaults_to_s256_and_plain() {
		$this->assertSame( [ PKCE::METHOD_S256, PKCE::METHOD_PLAIN ], PKCE::supported_methods() );
	}

	public function test_supported_methods_filter_removes_plain() {
		$filter = function () {
			return [ PKCE::METHOD_S256 ];
		};
		add_filter( 'oauth2.pkce.supported_methods', $filter );

		$this->assertSame( [ PKCE::METHOD_S256 ], PKCE::supported_methods() );

		remove_filter( 'oauth2.pkce.supported_methods', $filter );
	}

	public function test_generate_verifier_produces_a_valid_verifier() {
		$verifier = PKCE::generate_verifier();
		$this->assertTrue( PKCE::is_valid_verifier( $verifier ) );
	}

	public function test_generate_verifier_respects_requested_length() {
		$this->assertSame( 64, strlen( PKCE::generate_verifier( 64 ) ) );
		$this->assertSame( 100, strlen( PKCE::generate_verifier( 100 ) ) );
	}

	public function test_generate_verifier_clamps_to_valid_range() {
		$this->assertSame( PKCE::VERIFIER_MIN_LENGTH, strlen( PKCE::generate_verifier( 10 ) ) );
		$this->assertSame( PKCE::VERIFIER_MAX_LENGTH, strlen( PKCE::generate_verifier( 500 ) ) );
	}

	public function test_generate_verifier_is_not_deterministic() {
		$this->assertNotSame( PKCE::generate_verifier(), PKCE::generate_verifier() );
	}
}
