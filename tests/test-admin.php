<?php
/**
 * Tests for the admin namespace functions.
 *
 * @package WP\OAuth2\Tests
 */

namespace WP\OAuth2\Tests;

require_once __DIR__ . '/class-test-case.php';

use function WP\OAuth2\Admin\validate_parameters;

/**
 * Test cases for the client admin screens.
 */
class Test_Admin extends Test_Case {

	/**
	 * Build a valid set of submitted client parameters.
	 *
	 * @param array $overrides Values to override or add.
	 *
	 * @return array Parameters as they arrive from the edit form.
	 */
	protected function get_params( array $overrides = [] ) {
		return array_merge(
			[
				'name'        => 'Test Client',
				'description' => 'Test client description.',
				'type'        => 'web',
				'callback'    => 'https://example.com/callback',
			],
			$overrides
		);
	}

	public function test_validate_parameters_accepts_valid_client() {
		$valid = validate_parameters( $this->get_params() );

		$this->assertIsArray( $valid );
		$this->assertEquals( 'Test Client', $valid['name'] );
	}

	// -------------------------------------------------------------------------
	// Token TTL
	// -------------------------------------------------------------------------

	public function test_validate_parameters_ttl_empty_when_not_submitted() {
		$valid = validate_parameters( $this->get_params() );

		$this->assertSame( '', $valid['token_ttl'] );
	}

	public function test_validate_parameters_ttl_empty_for_empty_string() {
		$valid = validate_parameters( $this->get_params( [ 'token_ttl' => '' ] ) );

		$this->assertSame( '', $valid['token_ttl'] );
	}

	public function test_validate_parameters_casts_ttl_to_int() {
		// Form values always arrive as strings.
		$valid = validate_parameters( $this->get_params( [ 'token_ttl' => '3600' ] ) );

		$this->assertSame( 3600, $valid['token_ttl'] );
	}

	public function test_validate_parameters_accepts_zero_ttl() {
		$valid = validate_parameters( $this->get_params( [ 'token_ttl' => '0' ] ) );

		$this->assertSame( 0, $valid['token_ttl'] );
	}

	public function test_validate_parameters_rejects_negative_ttl() {
		$result = validate_parameters( $this->get_params( [ 'token_ttl' => '-1' ] ) );

		$this->assertWPError( $result );
		$this->assertEquals( 'rest_oauth2_invalid_ttl', $result->get_error_code() );
	}
}
