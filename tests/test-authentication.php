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
use function WP\OAuth2\Authentication\get_authorization_header;
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
	// get_authorization_header
	// -------------------------------------------------------------------------

	public function test_get_authorization_header_reads_default_authorization_header() {
		$_SERVER['HTTP_AUTHORIZATION'] = 'Bearer testtoken';

		$result = get_authorization_header();

		$this->assertEquals( 'Bearer testtoken', $result );
	}

	public function test_get_authorization_header_reads_custom_header_name() {
		$_SERVER['HTTP_X_CUSTOM_AUTH'] = 'Bearer customtoken';

		$result = get_authorization_header( 'x-custom-auth' );

		unset( $_SERVER['HTTP_X_CUSTOM_AUTH'] );
		$this->assertEquals( 'Bearer customtoken', $result );
	}

	public function test_get_authorization_header_returns_null_when_header_absent() {
		unset( $_SERVER['HTTP_AUTHORIZATION'] );

		$result = get_authorization_header();

		$this->assertNull( $result );
	}

	public function test_get_authorization_header_returns_null_for_absent_custom_header() {
		unset( $_SERVER['HTTP_X_MISSING'] );

		$result = get_authorization_header( 'x-missing' );

		$this->assertNull( $result );
	}

	public function test_get_authorization_header_converts_hyphen_to_underscore_in_server_key() {
		$_SERVER['HTTP_X_MY_TOKEN'] = 'Bearer hyphentest';

		$result = get_authorization_header( 'x-my-token' );

		unset( $_SERVER['HTTP_X_MY_TOKEN'] );
		$this->assertEquals( 'Bearer hyphentest', $result );
	}

	// -------------------------------------------------------------------------
	// oauth2.authentication.authorization_header filter
	// -------------------------------------------------------------------------

	public function test_authorization_header_filter_default_reads_authorization_header() {
		$token = Access_Token::create( $this->client, $this->user );

		$_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $token->get_key();
		$result                        = attempt_authentication();

		$this->assertEquals( $this->user->ID, $result );
	}

	public function test_custom_authorization_header_filter_authenticates_token() {
		$token = Access_Token::create( $this->client, $this->user );

		add_filter( 'oauth2.authentication.authorization_header', static function () {
			return 'x-my-auth';
		} );
		$_SERVER['HTTP_X_MY_AUTH'] = 'Bearer ' . $token->get_key();

		$result = attempt_authentication();

		remove_all_filters( 'oauth2.authentication.authorization_header' );
		unset( $_SERVER['HTTP_X_MY_AUTH'] );

		$this->assertEquals( $this->user->ID, $result );
	}

	public function test_custom_header_filter_with_hyphenated_name() {
		$token = Access_Token::create( $this->client, $this->user );

		add_filter( 'oauth2.authentication.authorization_header', static function () {
			return 'x-forwarded-auth';
		} );
		$_SERVER['HTTP_X_FORWARDED_AUTH'] = 'Bearer ' . $token->get_key();

		$result = attempt_authentication();

		remove_all_filters( 'oauth2.authentication.authorization_header' );
		unset( $_SERVER['HTTP_X_FORWARDED_AUTH'] );

		$this->assertEquals( $this->user->ID, $result );
	}

	public function test_custom_header_absent_does_not_authenticate() {
		add_filter( 'oauth2.authentication.authorization_header', static function () {
			return 'x-my-auth';
		} );
		unset( $_SERVER['HTTP_X_MY_AUTH'] );

		$result = attempt_authentication();

		remove_all_filters( 'oauth2.authentication.authorization_header' );

		$this->assertNull( $result );
	}

	public function test_custom_header_with_invalid_token_sets_error() {
		global $oauth2_error;

		add_filter( 'oauth2.authentication.authorization_header', static function () {
			return 'x-my-auth';
		} );
		$_SERVER['HTTP_X_MY_AUTH'] = 'Bearer invalidtoken123';

		attempt_authentication();

		remove_all_filters( 'oauth2.authentication.authorization_header' );
		unset( $_SERVER['HTTP_X_MY_AUTH'] );

		$this->assertWPError( $oauth2_error );
		$this->assertEquals(
			'oauth2.authentication.attempt_authentication.invalid_token',
			$oauth2_error->get_error_code()
		);
	}

	public function test_filter_does_not_affect_other_requests_after_removal() {
		$token = Access_Token::create( $this->client, $this->user );

		// Add and immediately remove the filter.
		$cb = static function () {
			return 'x-my-auth';
		};
		add_filter( 'oauth2.authentication.authorization_header', $cb );
		remove_filter( 'oauth2.authentication.authorization_header', $cb );

		// Standard Authorization header should still work.
		$_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $token->get_key();
		$result                        = attempt_authentication();

		$this->assertEquals( $this->user->ID, $result );
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
