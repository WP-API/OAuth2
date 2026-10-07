<?php
/**
 * Shared base test case.
 *
 * @package WP\OAuth2\Tests
 */

namespace WP\OAuth2\Tests;

use WP\OAuth2\Client;
use WP\OAuth2\PKCE;
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
					'type'                       => 'public',
					'client_credentials_enabled' => false,
					'pkce_required'              => false,
				],
				$meta_overrides
			),
		];

		$client = Client::create( $data );
		$this->assertInstanceOf( Client::class, $client, 'create_client helper: Client::create() must return a Client instance.' );
		$client->approve();

		return $client;
	}

	/**
	 * Generate a matching PKCE verifier/challenge pair for use in tests.
	 *
	 * @param string $method Challenge method, `S256` or `plain`. Default `S256`.
	 *
	 * @return array {
	 *     @var string $code_verifier Code verifier.
	 *     @var string $code_challenge Derived code challenge.
	 *     @var string $code_challenge_method Method used to derive the challenge.
	 * }
	 */
	protected function make_pkce_pair( $method = PKCE::METHOD_S256 ) {
		$verifier = PKCE::generate_verifier();

		return [
			'code_verifier'         => $verifier,
			'code_challenge'        => PKCE::derive_challenge( $verifier, $method ),
			'code_challenge_method' => $method,
		];
	}
}
