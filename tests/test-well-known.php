<?php
/**
 * Tests for the WP\OAuth2\Well_Known namespace functions.
 *
 * @package WP\OAuth2\Tests
 */

namespace WP\OAuth2\Tests;

require_once __DIR__ . '/class-test-case.php';

use WP_REST_Server;

use function WP\OAuth2\Well_Known\get_grant_types_supported;
use function WP\OAuth2\Well_Known\get_response_types_supported;
use function WP\OAuth2\Well_Known\match_well_known_path;
use function WP\OAuth2\Well_Known\maybe_exempt_login_wall;

/**
 * Test cases for the well-known discovery document functions.
 */
class Test_Well_Known extends Test_Case {

	/**
	 * @var WP_REST_Server
	 */
	protected $server;

	public function set_up() {
		parent::set_up();
		global $wp_rest_server;
		$this->server = $wp_rest_server = new WP_REST_Server();
		do_action( 'rest_api_init', $this->server );
	}

	public function tear_down() {
		global $wp_rest_server;
		$wp_rest_server = null;
		unset( $_SERVER['REQUEST_URI'] );
		parent::tear_down();
	}

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

	// -------------------------------------------------------------------------
	// maybe_exempt_login_wall
	// -------------------------------------------------------------------------

	public function test_maybe_exempt_login_wall_noops_outside_well_known() {
		$_SERVER['REQUEST_URI'] = '/some-other-path';

		$called = false;
		add_filter( 'oauth2.well_known_login_wall_exemptions', function ( $exemptions ) use ( &$called ) {
			$called = true;
			return $exemptions;
		} );

		maybe_exempt_login_wall();

		$this->assertFalse( $called );
	}

	public function test_maybe_exempt_login_wall_removes_configured_action() {
		$_SERVER['REQUEST_URI'] = '/.well-known/oauth-authorization-server';

		$ran      = false;
		$callback = function () use ( &$ran ) {
			$ran = true;
		};
		add_action( 'oauth2_tests_login_wall', $callback, 999 );

		add_filter( 'oauth2.well_known_login_wall_exemptions', function ( $exemptions ) use ( $callback ) {
			$exemptions[] = [ 'oauth2_tests_login_wall', $callback, 999 ];
			return $exemptions;
		} );

		maybe_exempt_login_wall();

		do_action( 'oauth2_tests_login_wall' );
		$this->assertFalse( $ran );
	}
}
