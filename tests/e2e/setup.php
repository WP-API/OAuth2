<?php
/**
 * Creates the OAuth clients the e2e checks use, and writes their IDs to
 * /wordpress/e2e-clients.json so pkce.py can read them over HTTP.
 *
 * Runs once from the Playground blueprint, after WordPress has loaded.
 *
 * @package WP\OAuth2\Tests
 */

use WP\OAuth2\Client;

$e2e_clients = [];

foreach ( [ 'required' => true, 'optional' => false ] as $e2e_name => $e2e_pkce_required ) {
	$e2e_client = Client::create(
		[
			'name'        => "PKCE $e2e_name",
			'description' => 'Created by tests/e2e/setup.php.',
			'meta'        => [
				'callback'      => 'http://127.0.0.1:9876/callback',
				'type'          => 'public',
				'pkce_required' => $e2e_pkce_required,
			],
		]
	);
	$e2e_client->approve();

	$e2e_clients[ $e2e_name ] = $e2e_client->get_id();
}

file_put_contents( ABSPATH . 'e2e-clients.json', wp_json_encode( $e2e_clients ) );
