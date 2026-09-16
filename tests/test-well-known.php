<?php
/**
 * Tests for the WP\OAuth2\Well_Known namespace functions.
 *
 * @package WP\OAuth2\Tests
 */

namespace WP\OAuth2\Tests;

require_once __DIR__ . '/class-test-case.php';

use function WP\OAuth2\Well_Known\get_grant_types_supported;
use function WP\OAuth2\Well_Known\get_response_types_supported;
use function WP\OAuth2\Well_Known\match_well_known_path;

/**
 * Test cases for the well-known discovery document functions.
 */
class Test_Well_Known extends Test_Case {

	// -------------------------------------------------------------------------
	// match_well_known_path
	// -------------------------------------------------------------------------

	public function test_match_well_known_path_matches_authorization_server() {
		$this->assertEquals(
			'oauth-authorization-server',
			match_well_known_path( '/.well-known/oauth-authorization-server' )
		);
	}

	public function test_match_well_known_path_tolerates_trailing_slash() {
		$this->assertEquals(
			'oauth-authorization-server',
			match_well_known_path( '/.well-known/oauth-authorization-server/' )
		);
	}

	public function test_match_well_known_path_ignores_query_string() {
		$this->assertEquals(
			'oauth-authorization-server',
			match_well_known_path( '/.well-known/oauth-authorization-server?foo=bar' )
		);
	}

	public function test_match_well_known_path_returns_null_for_unrelated_path() {
		$this->assertNull( match_well_known_path( '/some-other-path' ) );
	}

	// -------------------------------------------------------------------------
	// get_grant_types_supported / get_response_types_supported
	// -------------------------------------------------------------------------

	public function test_get_grant_types_supported_includes_authorization_code() {
		$this->assertContains( 'authorization_code', get_grant_types_supported() );
	}

	public function test_get_grant_types_supported_includes_client_credentials() {
		$this->assertContains( 'client_credentials', get_grant_types_supported() );
	}

	public function test_get_response_types_supported_includes_code_and_token() {
		$response_types = get_response_types_supported();
		$this->assertContains( 'code', $response_types );
		$this->assertContains( 'token', $response_types );
	}
}
