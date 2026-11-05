<?php
/**
 * Tests for client ID metadata document shadow clients.
 *
 * @package WP\OAuth2\Tests
 */

namespace WP\OAuth2\Tests;

require_once __DIR__ . '/class-test-case.php';
require_once __DIR__ . '/trait-cimd-helpers.php';

use WP\OAuth2\Client;
use WP_Error;

use function WP\OAuth2\CIMD\is_enabled;
use function WP\OAuth2\CIMD\validate_document;

/**
 * Test cases for the storage and behaviour of shadow clients.
 */
class Test_CIMD_Clients extends Test_Case {
	use CIMD_Test_Helpers;

	const URL = 'https://client.example.com/oauth/client.json';

	public function tear_down() {
		$this->reset_cimd_mocks();

		parent::tear_down();
	}

	/**
	 * Normalised metadata for the test URL.
	 *
	 * @param array $overrides Document fields to override.
	 * @return array
	 */
	protected function metadata( array $overrides = [] ) {
		$metadata = validate_document( $this->document( $overrides ), static::URL );
		$this->assertIsArray( $metadata );

		return $metadata;
	}

	/**
	 * Store a shadow client for the test URL.
	 *
	 * @param string $status    Post status.
	 * @param int    $expires   Expiry time.
	 * @param array  $overrides Document fields to override.
	 * @return Client
	 */
	protected function store( $status = 'publish', $expires = null, array $overrides = [] ) {
		$client = Client::save_cimd( static::URL, $this->metadata( $overrides ), $expires ?? time() + 300, $status );
		$this->assertInstanceOf( Client::class, $client );

		return $client;
	}

	/**
	 * Count the client posts of any status.
	 *
	 * @return int
	 */
	protected function count_client_posts() {
		return count(
			get_posts(
				[
					'post_type'      => Client::POST_TYPE,
					'post_status'    => 'any',
					'posts_per_page' => -1,
					'fields'         => 'ids',
				]
			)
		);
	}

	public function test_is_enabled_defaults_to_true() {
		$this->assertTrue( is_enabled() );
	}

	public function test_is_enabled_can_be_filtered_off() {
		add_filter( 'oauth2.cimd.enabled', '__return_false' );

		$this->assertFalse( is_enabled() );
	}

	// save_cimd().

	public function test_save_cimd_creates_a_shadow_client() {
		$expires  = time() + 300;
		$metadata = $this->metadata();

		$client = Client::save_cimd( static::URL, $metadata, $expires, 'publish' );

		$this->assertInstanceOf( Client::class, $client );
		$post = get_post( $client->get_post_id() );
		$this->assertSame( Client::POST_TYPE, $post->post_type );
		$this->assertSame( 'cimd-' . hash( 'sha256', static::URL ), $post->post_name );
		$this->assertSame( 'Example Client', $post->post_title );
		$this->assertSame( '', $post->post_content );
		$this->assertSame( 'publish', $post->post_status );
		$this->assertSame( 'cimd', get_post_meta( $post->ID, '_oauth2_client_kind', true ) );
		$this->assertSame( static::URL, get_post_meta( $post->ID, '_oauth2_cimd_client_id', true ) );
		$this->assertSame( $metadata, get_post_meta( $post->ID, '_oauth2_cimd_metadata', true ) );
		$this->assertSame( $expires, (int) get_post_meta( $post->ID, '_oauth2_cimd_expires', true ) );
		$this->assertSame( 'public', get_post_meta( $post->ID, '_oauth2_client_type', true ) );
		$this->assertTrue( $client->is_cimd() );
		$this->assertTrue( $client->is_approved() );
		$this->assertSame( $metadata, $client->get_cimd_metadata() );
		$this->assertSame( $expires, $client->get_cimd_expires() );
	}

	public function test_save_cimd_creates_a_draft_when_asked() {
		$client = $this->store( 'draft' );

		$this->assertSame( 'draft', get_post_status( $client->get_post_id() ) );
		$this->assertFalse( $client->is_approved() );
	}

	public function test_save_cimd_updates_the_existing_client_and_keeps_its_status() {
		$first = $this->store( 'draft', time() + 300 );

		$expires = time() + 900;
		$second  = Client::save_cimd(
			static::URL,
			$this->metadata(
				[
					'client_name'   => 'Renamed Client',
					'redirect_uris' => [ 'https://client.example.com/new' ],
				]
			),
			$expires,
			'publish'
		);

		$this->assertInstanceOf( Client::class, $second );
		$this->assertSame( $first->get_post_id(), $second->get_post_id() );
		$this->assertSame( 1, $this->count_client_posts() );
		$this->assertSame( 'draft', get_post_status( $second->get_post_id() ) );
		$this->assertSame( 'Renamed Client', get_post( $second->get_post_id() )->post_title );
		$this->assertSame( [ 'https://client.example.com/new' ], $second->get_redirect_uris() );
		$this->assertSame( $expires, $second->get_cimd_expires() );
	}

	public function test_save_cimd_keeps_a_published_client_published() {
		$first = $this->store( 'publish' );

		$second = Client::save_cimd( static::URL, $this->metadata(), time() + 900, 'draft' );

		$this->assertSame( $first->get_post_id(), $second->get_post_id() );
		$this->assertTrue( $second->is_approved() );
	}

	public function test_save_cimd_stores_metadata_with_backslashes_unchanged() {
		$client = $this->store( 'publish', null, [ 'client_name' => 'Back\\slash' ] );

		$this->assertSame( 'Back\\slash', $client->get_cimd_metadata()['client_name'] );
		$this->assertSame( 'Back\\slash', get_post( $client->get_post_id() )->post_title );
	}

	public function test_save_cimd_does_not_touch_a_registered_client() {
		$registered = $this->create_client( [], 'Registered Client' );
		$before     = get_post( $registered->get_post_id() );

		$this->store();

		$after = get_post( $registered->get_post_id() );
		$this->assertSame( $before->post_name, $after->post_name );
		$this->assertSame( 'Registered Client', $after->post_title );
		$this->assertSame( '', get_post_meta( $registered->get_post_id(), '_oauth2_client_kind', true ) );
		$this->assertFalse( $registered->is_cimd() );
		$this->assertSame( 2, $this->count_client_posts() );
	}

	public function test_save_cimd_refuses_to_use_a_slug_taken_by_another_client() {
		$post_id = wp_insert_post(
			[
				'post_type'   => Client::POST_TYPE,
				'post_title'  => 'Other',
				'post_name'   => 'cimd-' . hash( 'sha256', static::URL ),
				'post_status' => 'publish',
			]
		);

		$result = Client::save_cimd( static::URL, $this->metadata(), time() + 300, 'publish' );

		$this->assertWPError( $result );
		$this->assertSame( 'Other', get_post( $post_id )->post_title );
		$this->assertSame( '', get_post_meta( $post_id, '_oauth2_client_kind', true ) );
	}

	// get_by_id().

	public function test_get_by_id_finds_a_shadow_client_by_url() {
		$stored = $this->store();

		$client = Client::get_by_id( static::URL );

		$this->assertInstanceOf( Client::class, $client );
		$this->assertSame( $stored->get_post_id(), $client->get_post_id() );
	}

	public function test_get_by_id_returns_null_for_an_unknown_url() {
		$this->store();

		$this->assertNull( Client::get_by_id( 'https://other.example.com/oauth/client.json' ) );
	}

	public function test_get_by_id_matches_unapproved_shadow_clients_only_when_asked() {
		$this->store( 'draft' );

		$this->assertNull( Client::get_by_id( static::URL ) );
		$this->assertInstanceOf( Client::class, Client::get_by_id( static::URL, true ) );
	}

	public function test_get_by_id_never_matches_a_trashed_shadow_client() {
		$stored = $this->store();
		wp_trash_post( $stored->get_post_id() );

		$this->assertNull( Client::get_by_id( static::URL, true ) );
	}

	public function test_get_by_id_returns_null_when_the_stored_url_differs() {
		$stored = $this->store();
		update_post_meta( $stored->get_post_id(), '_oauth2_cimd_client_id', 'https://other.example.com/oauth/client.json' );

		$this->assertNull( Client::get_by_id( static::URL ) );
	}

	public function test_get_by_id_returns_null_when_the_post_is_not_a_shadow_client() {
		$this->store();
		$registered = $this->create_client();
		wp_update_post(
			[
				'ID'        => $registered->get_post_id(),
				'post_name' => 'cimd-' . hash( 'sha256', 'https://other.example.com/id' ),
			]
		);

		$this->assertNull( Client::get_by_id( 'https://other.example.com/id' ) );
	}

	public function test_get_by_id_does_not_return_a_shadow_client_by_its_slug() {
		$this->store();

		$this->assertNull( Client::get_by_id( 'cimd-' . hash( 'sha256', static::URL ) ) );
	}

	public function test_get_by_id_still_finds_registered_clients_by_slug() {
		$registered = $this->create_client();

		$client = Client::get_by_id( $registered->get_id() );

		$this->assertSame( $registered->get_post_id(), $client->get_post_id() );
	}

	public function test_get_id_returns_the_url() {
		$client = $this->store();

		$this->assertSame( static::URL, $client->get_id() );
		$this->assertSame( static::URL, Client::get_by_id( static::URL )->get_id() );
	}

	public function test_get_id_of_a_registered_client_is_its_slug() {
		$registered = $this->create_client();

		$this->assertSame( get_post( $registered->get_post_id() )->post_name, $registered->get_id() );
	}

	// Overrides.

	public function test_cimd_client_is_public() {
		$client = $this->store();
		update_post_meta( $client->get_post_id(), '_oauth2_client_type', 'private' );

		$this->assertSame( 'public', $client->get_type() );
	}

	public function test_cimd_client_requires_no_secret() {
		$client = $this->store();
		update_post_meta( $client->get_post_id(), '_oauth2_client_type', 'private' );

		$this->assertFalse( $client->requires_secret() );
	}

	public function test_cimd_client_requires_pkce() {
		$client = $this->store();

		$this->assertTrue( $client->is_pkce_required() );
	}

	public function test_cimd_client_pkce_requirement_goes_through_the_filter() {
		$client = $this->store();
		add_filter( 'oauth2.pkce.required', '__return_false' );

		$this->assertFalse( $client->is_pkce_required() );
	}

	public function test_cimd_client_cannot_use_client_credentials() {
		$client = $this->store();
		update_post_meta( $client->get_post_id(), '_oauth2_client_credentials_enabled', '1' );

		$this->assertFalse( $client->is_client_credentials_enabled() );
	}

	public function test_cimd_client_redirect_uris_come_from_the_metadata() {
		$client = $this->store(
			'publish',
			null,
			[
				'redirect_uris' => [ 'https://client.example.com/a', 'http://localhost/b' ],
			]
		);

		$this->assertSame( [ 'https://client.example.com/a', 'http://localhost/b' ], $client->get_redirect_uris() );
	}

	public function test_registered_client_is_unchanged_by_the_overrides() {
		$registered = $this->create_client(
			[
				'type'                       => 'private',
				'client_credentials_enabled' => true,
				'pkce_required'              => false,
			]
		);

		$this->assertSame( 'private', $registered->get_type() );
		$this->assertTrue( $registered->requires_secret() );
		$this->assertFalse( $registered->is_pkce_required() );
		$this->assertTrue( $registered->is_client_credentials_enabled() );
		$this->assertSame( [ 'https://example.com/callback' ], $registered->get_redirect_uris() );
	}

	// check_redirect_uri().

	/**
	 * Redirect URIs registered by the document.
	 *
	 * @return string[]
	 */
	protected function registered_redirect_uris() {
		return [
			'https://client.example.com/callback',
			'https://localhost/secure',
			'http://localhost/cb',
			'http://127.0.0.1/cb?x=1',
			'http://[::1]/cb',
		];
	}

	/**
	 * @dataProvider accepted_redirect_uri_provider
	 */
	public function test_check_redirect_uri_accepts( $uri ) {
		$client = $this->store( 'publish', null, [ 'redirect_uris' => $this->registered_redirect_uris() ] );

		$this->assertTrue( $client->check_redirect_uri( $uri ) );
	}

	public function accepted_redirect_uri_provider() {
		return [
			'exact https'          => [ 'https://client.example.com/callback' ],
			'exact https localhost' => [ 'https://localhost/secure' ],
			'exact loopback'       => [ 'http://localhost/cb' ],
			'localhost with port'  => [ 'http://localhost:8080/cb' ],
			'localhost other port' => [ 'http://localhost:3000/cb' ],
			'127.0.0.1 with port'  => [ 'http://127.0.0.1:5000/cb?x=1' ],
			'ipv6 with port'       => [ 'http://[::1]:9000/cb' ],
		];
	}

	/**
	 * @dataProvider rejected_redirect_uri_provider
	 */
	public function test_check_redirect_uri_rejects( $uri ) {
		$client = $this->store( 'publish', null, [ 'redirect_uris' => $this->registered_redirect_uris() ] );

		$this->assertFalse( $client->check_redirect_uri( $uri ) );
	}

	public function rejected_redirect_uri_provider() {
		return [
			'added query'                  => [ 'https://client.example.com/callback?x=1' ],
			'trailing slash'               => [ 'https://client.example.com/callback/' ],
			'other path'                   => [ 'https://client.example.com/other' ],
			'https port'                   => [ 'https://client.example.com:8443/callback' ],
			'fragment'                     => [ 'https://client.example.com/callback#frag' ],
			'other host'                   => [ 'https://other.example.com/callback' ],
			'http scheme'                  => [ 'http://client.example.com/callback' ],
			'case differs'                 => [ 'https://client.example.com/Callback' ],
			'https localhost with port'    => [ 'https://localhost:8443/secure' ],
			'loopback with added query'    => [ 'http://localhost:8080/cb?x=1' ],
			'loopback trailing slash'      => [ 'http://localhost:8080/cb/' ],
			'loopback other path'          => [ 'http://localhost:8080/other' ],
			'loopback fragment'            => [ 'http://localhost:8080/cb#f' ],
			'loopback https'               => [ 'https://localhost:8080/cb' ],
			'loopback query missing'       => [ 'http://127.0.0.1:5000/cb' ],
			'loopback other query'         => [ 'http://127.0.0.1:5000/cb?x=2' ],
			'other loopback address'       => [ 'http://127.0.0.2:5000/cb?x=1' ],
			'loopback name for address'    => [ 'http://localhost:5000/cb?x=1' ],
			'port out of range'            => [ 'http://localhost:99999/cb' ],
			'port zero'                    => [ 'http://localhost:0/cb' ],
			'user info'                    => [ 'http://user@localhost:8080/cb' ],
			'port hides another host'      => [ 'http://localhost:80@evil.example/cb' ],
			'empty'                        => [ '' ],
			'only a scheme'                => [ 'http:' ],
		];
	}

	public function test_check_redirect_uri_ignores_the_registered_client_matching_filter() {
		$client = $this->store();
		add_filter( 'rest_oauth.check_callback', '__return_true' );

		$this->assertFalse( $client->check_redirect_uri( 'https://client.example.com/other' ) );
	}

	public function test_check_redirect_uri_for_registered_clients_is_unchanged() {
		$registered = $this->create_client();

		$this->assertTrue( $registered->check_redirect_uri( 'https://example.com/callback?extra=1' ) );
		$this->assertFalse( $registered->check_redirect_uri( 'https://example.com/other' ) );
	}
}
