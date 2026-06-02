<?php
/**
 * Shared base test case.
 *
 * @package WP\OAuth2\Tests
 */

namespace WP\OAuth2\Tests;

use WP\OAuth2\Client;
use WP_UnitTestCase;

/**
 * Base test case with helpers shared across all OAuth2 test classes.
 */
abstract class Test_Case extends WP_UnitTestCase {

	/**
	 * Create and approve a test client.
	 *
	 * @param array  $meta_overrides  Optional overrides for the client meta.
	 * @param string $name            Client name.
	 *
	 * @return Client
	 */
	protected function create_client( array $meta_overrides = [], $name = 'Test Client' ) {
		$data = [
			'name'        => $name,
			'description' => 'Test client description.',
			'meta'        => array_merge(
				[
					'callback'                   => 'https://example.com/callback',
					'type'                       => 'web',
					'client_credentials_enabled' => false,
				],
				$meta_overrides
			),
		];

		$client = Client::create( $data );
		$this->assertInstanceOf( Client::class, $client, 'create_client helper: Client::create() must return a Client instance.' );
		$client->approve();

		return $client;
	}
}
