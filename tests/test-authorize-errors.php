<?php
/**
 * Tests for errors returned by the authorize step.
 *
 * @package WP\OAuth2\Tests
 */

namespace WP\OAuth2\Tests;

require_once __DIR__ . '/class-test-case.php';

use WP\OAuth2\Endpoints\Authorization;
use WP\OAuth2\Types\Authorization_Code;
use WP_Error;

/**
 * Test cases for authorize errors.
 */
class Test_Authorize_Errors extends Test_Case {

	public function tear_down() {
		$_GET = [];
		parent::tear_down();
	}

	public function test_unapproved_client_returns_forbidden_error() {
		$client = $this->create_client( [], 'Test Client', false );
		$_GET   = [ 'client_id' => $client->get_id() ];

		$result = ( new Authorization_Code() )->handle_authorisation();

		$this->assertWPError( $result );
		$this->assertSame( 'oauth2.types.authorization_code.handle_authorisation.unapproved_client', $result->get_error_code() );
		$this->assertSame( 403, $result->get_error_data()['status'] );
	}

	public function test_unknown_client_still_returns_invalid_client_id() {
		$_GET = [ 'client_id' => 'nonexistent-client-id' ];

		$result = ( new Authorization_Code() )->handle_authorisation();

		$this->assertWPError( $result );
		$this->assertSame( 'oauth2.types.authorization_code.handle_authorisation.invalid_client_id', $result->get_error_code() );
		$this->assertSame( 400, $result->get_error_data()['status'] );
	}

	public function test_error_status_is_forbidden_for_unapproved_client() {
		$client = $this->create_client( [], 'Test Client', false );
		$_GET   = [ 'client_id' => $client->get_id() ];
		$result = ( new Authorization_Code() )->handle_authorisation();

		$this->assertSame( 403, ( new Authorization() )->get_error_status( $result ) );
	}

	public function test_error_status_defaults_to_bad_request() {
		$this->assertSame( 400, ( new Authorization() )->get_error_status( new WP_Error( 'some_code', 'Message.' ) ) );
	}
}
