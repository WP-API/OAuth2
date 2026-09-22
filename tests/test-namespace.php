<?php
/**
 * Tests for the WP\OAuth2 namespace functions.
 *
 * @package WP\OAuth2\Tests
 */

namespace WP\OAuth2\Tests;

require_once __DIR__ . '/class-test-case.php';

use WP\OAuth2\Client;
use WP\OAuth2\ClientInterface;
use WP\OAuth2\PersonalClient;
use WP\OAuth2\Types\Type;
use WP_REST_Response;
use WP_REST_Server;

use function WP\OAuth2\get_authorization_url;
use function WP\OAuth2\get_client;
use function WP\OAuth2\get_grant_types;
use function WP\OAuth2\get_token_url;
use function WP\OAuth2\register_in_index;

/**
 * Test cases for top-level OAuth2 namespace functions.
 */
class Test_Namespace extends Test_Case {

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
		parent::tear_down();
	}

	public function test_get_grant_types_returns_authorization_code() {
		$types = get_grant_types();
		$this->assertArrayHasKey( 'authorization_code', $types );
		$this->assertInstanceOf( Type::class, $types['authorization_code'] );
	}

	public function test_get_grant_types_returns_implicit() {
		$types = get_grant_types();
		$this->assertArrayHasKey( 'implicit', $types );
		$this->assertInstanceOf( Type::class, $types['implicit'] );
	}

	public function test_get_grant_types_filters_invalid_handlers() {
		$filter = function ( $types ) {
			$types['invalid_type'] = new \stdClass();
			return $types;
		};
		add_filter( 'oauth2.grant_types', $filter );

		$this->setExpectedIncorrectUsage( 'WP\OAuth2\get_grant_types' );
		$types = get_grant_types();

		remove_filter( 'oauth2.grant_types', $filter );

		$this->assertArrayNotHasKey( 'invalid_type', $types );
	}

	public function test_get_authorization_url_contains_action() {
		$url = get_authorization_url();
		$this->assertStringContainsString( 'action=oauth2_authorize', $url );
	}

	public function test_get_token_url_contains_endpoint() {
		$url = get_token_url();
		$this->assertStringContainsString( 'oauth2/access_token', $url );
	}

	public function test_get_client_returns_personal_client() {
		$client = get_client( PersonalClient::ID );
		$this->assertInstanceOf( PersonalClient::class, $client );
	}

	public function test_get_client_returns_regular_client() {
		$created = $this->create_client();
		$found   = get_client( $created->get_id() );
		$this->assertInstanceOf( Client::class, $found );
		$this->assertEquals( $created->get_id(), $found->get_id() );
	}

	public function test_get_client_returns_null_for_unknown() {
		$result = get_client( 'nonexistent-client-id' );
		$this->assertNull( $result );
	}

	public function test_register_in_index_adds_authentication_endpoints() {
		$response = new WP_REST_Response( [] );
		$response = register_in_index( $response );

		$data = $response->get_data();
		$this->assertArrayHasKey( 'authentication', $data );
		$this->assertArrayHasKey( 'oauth2', $data['authentication'] );
		$this->assertArrayHasKey( 'authorization', $data['authentication']['oauth2']['endpoints'] );
		$this->assertArrayHasKey( 'token', $data['authentication']['oauth2']['endpoints'] );
	}

	public function test_register_in_index_lists_grant_types() {
		$response = new WP_REST_Response( [] );
		$response = register_in_index( $response );

		$data = $response->get_data();
		$this->assertArrayHasKey( 'grant_types', $data['authentication']['oauth2'] );
		$this->assertContains( 'authorization_code', $data['authentication']['oauth2']['grant_types'] );
	}
}
