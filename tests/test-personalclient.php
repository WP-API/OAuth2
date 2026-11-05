<?php
/**
 * Tests for the PersonalClient class.
 *
 * @package WP\OAuth2\Tests
 */

namespace WP\OAuth2\Tests;

require_once __DIR__ . '/class-test-case.php';

use WP\OAuth2\PersonalClient;

/**
 * Test cases for the internal client backing personal access tokens.
 */
class Test_PersonalClient extends Test_Case {

	/**
	 * @var PersonalClient
	 */
	protected $client;

	public function set_up() {
		parent::set_up();
		$this->client = PersonalClient::get_instance();
	}

	public function test_requires_secret_is_false() {
		$this->assertFalse( $this->client->requires_secret() );
	}

	public function test_check_secret_is_false_for_any_value() {
		$this->assertFalse( $this->client->check_secret( '' ) );
		$this->assertFalse( $this->client->check_secret( 'anything' ) );
	}

	public function test_client_credentials_grant_is_disabled() {
		$this->assertFalse( $this->client->is_client_credentials_enabled() );
	}
}
