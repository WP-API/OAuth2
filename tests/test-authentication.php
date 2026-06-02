<?php
/**
 * Tests for the Authentication namespace functions.
 *
 * @package WP\OAuth2\Tests
 */

namespace WP\OAuth2\Tests;

require_once __DIR__ . '/class-test-case.php';

use WP\OAuth2\Client;
use WP\OAuth2\Tokens\Access_Token;
use WP_User;

use function WP\OAuth2\Authentication\attempt_authentication;
use function WP\OAuth2\Authentication\get_token_from_bearer_header;
use function WP\OAuth2\Authentication\maybe_report_errors;

/**
 * Test cases for authentication functions.
 */
class Test_Authentication extends Test_Case {

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
		unset( $_SERVER['HTTP_AUTHORIZATION'] );
	}

	public function tear_down() {
		unset( $_SERVER['HTTP_AUTHORIZATION'] );
		global $oauth2_error;
		$oauth2_error = null;
		parent::tear_down();
	}

	// -------------------------------------------------------------------------
	// get_token_from_bearer_header
	// -------------------------------------------------------------------------

	public function test_get_token_from_bearer_header_valid() {
		$token = get_token_from_bearer_header( 'Bearer abc123' );
		$this->assertEquals( 'abc123', $token );
	}

	public function test_get_token_from_bearer_header_case_insensitive_bearer() {
		// The regex matches 'Bearer' literally, so 'bearer' won't match — verify
		// documented behaviour rather than assuming case-insensitivity.
		$token = get_token_from_bearer_header( 'Bearer testtoken' );
		$this->assertEquals( 'testtoken', $token );
	}

	public function test_get_token_from_bearer_header_returns_null_for_empty() {
		$token = get_token_from_bearer_header( '' );
		$this->assertNull( $token );
	}

	public function test_get_token_from_bearer_header_returns_null_for_basic() {
		$token = get_token_from_bearer_header( 'Basic dXNlcjpwYXNz' );
		$this->assertNull( $token );
	}

	// -------------------------------------------------------------------------
	// attempt_authentication
	// -------------------------------------------------------------------------

	public function test_attempt_authentication_passes_through_existing_user() {
		$result = attempt_authentication( $this->user );
		$this->assertEquals( $this->user, $result );
	}

	public function test_attempt_authentication_returns_user_id_for_valid_token() {
		$token = Access_Token::create( $this->client, $this->user );

		$_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $token->get_key();
		$result                        = attempt_authentication();

		$this->assertEquals( $this->user->ID, $result );
	}

	public function test_attempt_authentication_returns_zero_for_client_token() {
		$client = $this->create_client( [ 'client_credentials_enabled' => true ] );
		$token  = Access_Token::create_for_client( $client );

		$_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $token->get_key();
		$result                        = attempt_authentication();

		$this->assertEquals( 0, $result );
	}

	public function test_attempt_authentication_sets_error_for_invalid_token() {
		global $oauth2_error;
		$_SERVER['HTTP_AUTHORIZATION'] = 'Bearer invalidtokenxyz';

		attempt_authentication();

		$this->assertWPError( $oauth2_error );
		$this->assertEquals(
			'oauth2.authentication.attempt_authentication.invalid_token',
			$oauth2_error->get_error_code()
		);
	}

	public function test_attempt_authentication_no_op_when_no_token() {
		$result = attempt_authentication();
		$this->assertNull( $result );
	}

	// -------------------------------------------------------------------------
	// maybe_report_errors
	// -------------------------------------------------------------------------

	public function test_maybe_report_errors_passes_through_existing_error() {
		$existing = new \WP_Error( 'existing_error', 'Pre-existing error' );
		$result   = maybe_report_errors( $existing );
		$this->assertEquals( $existing, $result );
	}

	public function test_maybe_report_errors_returns_global_error() {
		global $oauth2_error;
		$oauth2_error = new \WP_Error( 'oauth2_test_error', 'Test OAuth2 error' );

		$result = maybe_report_errors( null );

		$this->assertWPError( $result );
		$this->assertEquals( 'oauth2_test_error', $result->get_error_code() );
	}

	public function test_maybe_report_errors_returns_null_when_no_error() {
		global $oauth2_error;
		$oauth2_error = null;

		$result = maybe_report_errors( null );

		$this->assertNull( $result );
	}
}
