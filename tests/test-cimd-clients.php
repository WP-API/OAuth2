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
use WP\OAuth2\Endpoints\Authorization;
use WP\OAuth2\PKCE;
use WP\OAuth2\Tokens;
use WP\OAuth2\Types\Authorization_Code;
use WP_Error;
use WP_REST_Request;
use WP_REST_Server;

use function WP\OAuth2\get_client;
use function WP\OAuth2\CIMD\is_enabled;
use function WP\OAuth2\CIMD\validate_document;

/**
 * Shared setup and helpers for tests of shadow clients.
 */
abstract class CIMD_Clients_Test_Case extends Test_Case {
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
}

/**
 * Test cases for the storage and behaviour of shadow clients.
 */
class Test_CIMD_Clients extends CIMD_Clients_Test_Case {
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

	public function test_cimd_client_pkce_requirement_cannot_be_filtered_off() {
		$client = $this->store();
		add_filter( 'oauth2.pkce.required', '__return_false' );

		$this->assertTrue( $client->is_pkce_required() );
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

/**
 * Test cases for resolving a client ID, with and without discovery.
 */
class Test_CIMD_Resolver extends CIMD_Clients_Test_Case {

	const OTHER_URL = 'https://other.example.com/oauth/client.json';

	/**
	 * Serve a metadata document for the test URL.
	 *
	 * @param array $overrides Document fields to override.
	 * @param array $headers   Response headers.
	 */
	protected function serve( array $overrides = [], array $headers = [] ) {
		$this->mock_dns();
		$this->mock_http( $this->http_response( wp_json_encode( $this->document( $overrides ) ), $headers ) );
	}

	/**
	 * Make fetched documents expire immediately.
	 */
	protected function expire_immediately() {
		add_filter( 'oauth2.cimd.cache_ttl', '__return_zero' );
	}

	/**
	 * Resolve the test URL with discovery on.
	 *
	 * @param array $args Extra arguments.
	 * @return mixed
	 */
	protected function discover( array $args = [] ) {
		return get_client( static::URL, array_merge( [ 'discover' => true ], $args ) );
	}

	/**
	 * Option name of the fetch lock for a URL.
	 *
	 * @param string $url Client ID URL.
	 * @return string
	 */
	protected function lock_name( $url = self::URL ) {
		return 'oauth2_cimd_lock_' . md5( $url );
	}

	// Without discovery.

	public function test_get_client_without_discovery_never_calls_http() {
		$this->serve();

		$this->assertNull( get_client( static::URL ) );
		$this->assertNull( get_client( static::URL, [ 'include_unapproved' => true ] ) );
		$this->assertSame( 0, $this->request_count );
		$this->assertSame( 0, $this->count_client_posts() );
	}

	public function test_get_client_without_discovery_returns_a_stored_client_even_if_stale() {
		$this->serve();
		$stored = $this->store( 'publish', time() - 100 );

		$client = get_client( static::URL );

		$this->assertSame( $stored->get_post_id(), $client->get_post_id() );
		$this->assertSame( 0, $this->request_count );
	}

	public function test_get_client_passes_include_unapproved_through() {
		$this->store( 'draft' );

		$this->assertNull( get_client( static::URL ) );
		$this->assertInstanceOf( Client::class, get_client( static::URL, [ 'include_unapproved' => true ] ) );
	}

	public function test_get_client_leaves_registered_clients_unchanged() {
		$this->serve();
		$approved = $this->create_client();
		$draft    = $this->create_client( [], 'Draft Client', false );

		$this->assertSame( $approved->get_post_id(), get_client( $approved->get_id() )->get_post_id() );
		$this->assertSame( $approved->get_post_id(), get_client( $approved->get_id(), [ 'discover' => true ] )->get_post_id() );
		$this->assertNull( get_client( $draft->get_id() ) );
		$this->assertSame( $draft->get_post_id(), get_client( $draft->get_id(), [ 'include_unapproved' => true ] )->get_post_id() );
		$this->assertNull( get_client( 'unknown-client' ) );
		$this->assertSame( 0, $this->request_count );
	}

	public function test_get_client_returns_the_personal_client() {
		$this->assertInstanceOf( \WP\OAuth2\PersonalClient::class, get_client( \WP\OAuth2\PersonalClient::ID, [ 'discover' => true ] ) );
	}

	// Discovery.

	public function test_discovery_creates_a_published_client_for_an_unknown_url() {
		$this->serve();

		$client = $this->discover();

		$this->assertInstanceOf( Client::class, $client );
		$this->assertTrue( $client->is_cimd() );
		$this->assertTrue( $client->is_approved() );
		$this->assertSame( static::URL, $client->get_id() );
		$this->assertSame( 'Example Client', $client->get_name() );
		$this->assertSame( [ 'https://client.example.com/callback' ], $client->get_redirect_uris() );
		$this->assertGreaterThan( time(), $client->get_cimd_expires() );
		$this->assertSame( 1, $this->request_count );
		$this->assertSame( 1, $this->count_client_posts() );
	}

	public function test_a_fresh_cache_does_not_fetch() {
		$this->serve();
		$stored = $this->store( 'publish', time() + 300 );

		$client = $this->discover();

		$this->assertSame( $stored->get_post_id(), $client->get_post_id() );
		$this->assertSame( 0, $this->request_count );
	}

	public function test_an_expired_cache_refetches_and_updates() {
		$this->serve(
			[
				'client_name'   => 'New Name',
				'redirect_uris' => [ 'https://client.example.com/new' ],
			]
		);
		$stored = $this->store( 'publish', time() - 10, [ 'client_name' => 'Old Name' ] );

		$client = $this->discover();

		$this->assertSame( 1, $this->request_count );
		$this->assertSame( $stored->get_post_id(), $client->get_post_id() );
		$this->assertSame( 'New Name', $client->get_name() );
		$this->assertSame( [ 'https://client.example.com/new' ], $client->get_redirect_uris() );
		$this->assertGreaterThan( time(), $client->get_cimd_expires() );
		$this->assertSame( 1, $this->count_client_posts() );
	}

	public function test_a_transient_failure_returns_the_stale_client() {
		$this->mock_dns();
		$this->mock_http( new WP_Error( 'http_request_failed', 'Timed out' ) );
		$stored = $this->store( 'publish', time() - 10 );

		$client = $this->discover();

		$this->assertSame( 1, $this->request_count );
		$this->assertInstanceOf( Client::class, $client );
		$this->assertSame( $stored->get_post_id(), $client->get_post_id() );
		$this->assertLessThan( time(), $client->get_cimd_expires() );
	}

	public function test_a_server_error_returns_the_stale_client() {
		$this->mock_dns();
		$this->mock_http( $this->http_response( '', [], 503 ) );
		$stored = $this->store( 'publish', time() - 10 );

		$this->assertSame( $stored->get_post_id(), $this->discover()->get_post_id() );
	}

	public function test_a_transient_failure_without_a_stored_client_returns_the_error() {
		$this->mock_dns();
		$this->mock_http( new WP_Error( 'http_request_failed', 'Timed out' ) );

		$this->assertCimdError( 'oauth2.cimd.fetch_failed', 503, $this->discover(), true );
		$this->assertSame( 0, $this->count_client_posts() );
	}

	public function test_a_terminal_failure_returns_the_error_even_with_a_stored_client() {
		$this->mock_dns();
		$this->mock_http( $this->http_response( '', [], 404 ) );
		$this->store( 'publish', time() - 10 );

		$this->assertCimdError( 'oauth2.cimd.fetch_failed', 400, $this->discover(), false );
	}

	public function test_an_invalid_document_returns_the_error_and_stores_nothing() {
		$this->serve( [ 'client_id' => 'https://other.example.com/oauth/client.json' ] );

		$this->assertCimdError( 'oauth2.cimd.invalid_document', 400, $this->discover(), false );
		$this->assertSame( 0, $this->count_client_posts() );
	}

	public function test_an_invalid_url_is_rejected_without_a_fetch_or_a_rate_limit_charge() {
		$this->serve();
		wp_set_current_user( $this->factory->user->create() );

		$result = get_client( 'https://client.example.com/', [ 'discover' => true ] );

		$this->assertCimdError( 'oauth2.cimd.invalid_client_id', 400, $result );
		$this->assertSame( 0, $this->request_count );
		$this->assertFalse( get_transient( 'oauth2_cimd_rl_' . get_current_user_id() ) );
	}

	public function test_an_unapproved_client_is_hidden_unless_requested() {
		$this->serve();
		$this->store( 'draft', time() + 300 );

		$this->assertNull( $this->discover() );
		$this->assertInstanceOf( Client::class, $this->discover( [ 'include_unapproved' => true ] ) );
		$this->assertSame( 0, $this->request_count );
	}

	public function test_discovery_that_creates_a_draft_hides_it_unless_requested() {
		$this->serve();
		add_filter(
			'oauth2.cimd.policy',
			function () {
				return 'manual';
			}
		);

		$this->assertNull( $this->discover() );
		$this->assertSame( 1, $this->count_client_posts() );
	}

	// Policy.

	public function test_policy_deny_refuses_the_client_and_stores_nothing() {
		$this->serve();
		add_filter(
			'oauth2.cimd.policy',
			function () {
				return 'deny';
			}
		);

		$this->assertCimdError( 'oauth2.cimd.not_allowed', 403, $this->discover() );
		$this->assertSame( 0, $this->count_client_posts() );
	}

	public function test_policy_manual_saves_a_new_client_as_a_draft() {
		$this->serve();
		add_filter(
			'oauth2.cimd.policy',
			function () {
				return 'manual';
			}
		);

		$client = $this->discover( [ 'include_unapproved' => true ] );

		$this->assertInstanceOf( Client::class, $client );
		$this->assertFalse( $client->is_approved() );
		$this->assertSame( 'draft', get_post_status( $client->get_post_id() ) );
	}

	public function test_policy_auto_publishes_a_new_client() {
		$this->serve();
		add_filter(
			'oauth2.cimd.policy',
			function () {
				return 'auto';
			}
		);

		$this->assertSame( 'publish', get_post_status( $this->discover()->get_post_id() ) );
	}

	public function test_policy_receives_the_metadata_url_and_existing_client() {
		$this->serve();
		$seen = [];
		add_filter(
			'oauth2.cimd.policy',
			function ( $policy, $metadata, $url, $existing ) use ( &$seen ) {
				$seen[] = [ $policy, $metadata, $url, $existing ];
				return $policy;
			},
			10,
			4
		);

		$first = $this->discover();
		update_post_meta( $first->get_post_id(), '_oauth2_cimd_expires', time() - 1 );
		$this->discover();

		$this->assertSame( 'auto', $seen[0][0] );
		$this->assertSame( $this->metadata(), $seen[0][1] );
		$this->assertSame( static::URL, $seen[0][2] );
		$this->assertNull( $seen[0][3] );
		$this->assertInstanceOf( Client::class, $seen[1][3] );
	}

	public function test_a_refreshed_document_does_not_approve_an_existing_draft() {
		$this->serve();
		$stored = $this->store( 'draft', time() - 10 );

		$client = $this->discover( [ 'include_unapproved' => true ] );

		$this->assertSame( $stored->get_post_id(), $client->get_post_id() );
		$this->assertSame( 'draft', get_post_status( $client->get_post_id() ) );
	}

	public function test_a_refreshed_document_does_not_unapprove_an_existing_client() {
		$this->serve();
		add_filter(
			'oauth2.cimd.policy',
			function () {
				return 'manual';
			}
		);
		$stored = $this->store( 'publish', time() - 10 );

		$client = $this->discover();

		$this->assertSame( $stored->get_post_id(), $client->get_post_id() );
		$this->assertSame( 'publish', get_post_status( $client->get_post_id() ) );
	}

	public function test_policy_deny_also_refuses_a_refresh_of_an_existing_client() {
		$this->serve();
		add_filter(
			'oauth2.cimd.policy',
			function () {
				return 'deny';
			}
		);
		$this->store( 'publish', time() - 10 );

		$this->assertCimdError( 'oauth2.cimd.not_allowed', 403, $this->discover() );
	}

	// Rate limit.

	public function test_rate_limit_without_a_stored_client_returns_an_error() {
		$this->serve();
		$this->expire_immediately();
		add_filter(
			'oauth2.cimd.rate_limit',
			function () {
				return [
					'limit'  => 1,
					'window' => 600,
				];
			}
		);
		wp_set_current_user( $this->factory->user->create() );

		$this->assertInstanceOf( Client::class, $this->discover() );
		$result = get_client( static::OTHER_URL, [ 'discover' => true ] );

		$this->assertCimdError( 'oauth2.cimd.rate_limited', 429, $result, true );
		$this->assertSame( 1, $this->request_count );
	}

	public function test_rate_limit_with_a_stored_client_returns_it_without_a_fetch() {
		$this->serve();
		$this->expire_immediately();
		add_filter(
			'oauth2.cimd.rate_limit',
			function () {
				return [
					'limit'  => 1,
					'window' => 600,
				];
			}
		);
		wp_set_current_user( $this->factory->user->create() );

		$first  = $this->discover();
		$second = $this->discover();

		$this->assertSame( $first->get_post_id(), $second->get_post_id() );
		$this->assertSame( 1, $this->request_count );
	}

	public function test_rate_limit_applies_per_user() {
		$this->serve();
		add_filter(
			'oauth2.cimd.rate_limit',
			function () {
				return [
					'limit'  => 1,
					'window' => 600,
				];
			}
		);
		wp_set_current_user( $this->factory->user->create() );
		$this->assertInstanceOf( Client::class, $this->discover() );
		$this->assertWPError( get_client( static::OTHER_URL, [ 'discover' => true ] ) );

		wp_set_current_user( $this->factory->user->create() );
		$this->mock_http( $this->http_response( wp_json_encode( $this->document( [ 'client_id' => static::OTHER_URL ] ) ) ) );

		$this->assertInstanceOf( Client::class, get_client( static::OTHER_URL, [ 'discover' => true ] ) );
	}

	public function test_rate_limit_defaults_to_ten_fetches_per_ten_minutes() {
		$this->serve();
		$this->expire_immediately();
		$user_id = $this->factory->user->create();
		wp_set_current_user( $user_id );
		$seen = null;
		add_filter(
			'oauth2.cimd.rate_limit',
			function ( $limit, $filter_user_id ) use ( &$seen ) {
				$seen = [ $limit, $filter_user_id ];
				return $limit;
			},
			10,
			2
		);

		for ( $i = 0; $i < 10; $i++ ) {
			$this->assertInstanceOf( Client::class, $this->discover() );
		}
		$this->assertSame( 10, $this->request_count );
		$this->assertSame(
			[
				[
					'limit'  => 10,
					'window' => 600,
				],
				$user_id,
			],
			$seen
		);

		$this->discover();

		$this->assertSame( 10, $this->request_count );
		$this->assertSame( 10, get_transient( 'oauth2_cimd_rl_' . $user_id )['count'] );
	}

	public function test_only_real_fetches_count_against_the_rate_limit() {
		$this->serve();
		add_filter(
			'oauth2.cimd.rate_limit',
			function () {
				return [
					'limit'  => 1,
					'window' => 600,
				];
			}
		);
		wp_set_current_user( $this->factory->user->create() );
		$this->store( 'publish', time() + 300 );

		for ( $i = 0; $i < 3; $i++ ) {
			$this->assertInstanceOf( Client::class, $this->discover() );
		}
		$this->assertFalse( get_transient( 'oauth2_cimd_rl_' . get_current_user_id() ) );

		$this->mock_http( $this->http_response( wp_json_encode( $this->document( [ 'client_id' => static::OTHER_URL ] ) ) ) );
		$this->assertInstanceOf( Client::class, get_client( static::OTHER_URL, [ 'discover' => true ] ) );
		$this->assertSame( 1, $this->request_count );
	}

	public function test_a_held_lock_does_not_count_against_the_rate_limit() {
		$this->serve();
		wp_set_current_user( $this->factory->user->create() );
		add_option( $this->lock_name(), time(), '', false );

		$this->assertWPError( $this->discover() );

		$this->assertFalse( get_transient( 'oauth2_cimd_rl_' . get_current_user_id() ) );
	}

	// Lock.

	public function test_a_held_lock_with_a_stored_client_returns_it_without_a_fetch() {
		$this->serve();
		$stored = $this->store( 'publish', time() - 10 );
		add_option( $this->lock_name(), time(), '', false );

		$client = $this->discover();

		$this->assertSame( $stored->get_post_id(), $client->get_post_id() );
		$this->assertSame( 0, $this->request_count );
		$this->assertNotFalse( get_option( $this->lock_name() ) );
	}

	public function test_a_held_lock_without_a_stored_client_returns_a_busy_error() {
		$this->serve();
		add_option( $this->lock_name(), time(), '', false );

		$this->assertCimdError( 'oauth2.cimd.busy', 503, $this->discover(), true );
		$this->assertSame( 0, $this->request_count );
		$this->assertNotFalse( get_option( $this->lock_name() ) );
	}

	public function test_a_stale_lock_is_replaced() {
		$this->serve();
		add_option( $this->lock_name(), time() - 31, '', false );

		$this->assertInstanceOf( Client::class, $this->discover() );
		$this->assertSame( 1, $this->request_count );
		$this->assertFalse( get_option( $this->lock_name() ) );
	}

	public function test_the_lock_is_released_after_a_fetch() {
		$this->serve();

		$this->discover();

		$this->assertFalse( get_option( $this->lock_name() ) );
	}

	public function test_the_lock_is_released_after_a_failed_fetch() {
		$this->mock_dns();
		$this->mock_http( $this->http_response( '', [], 404 ) );

		$this->assertWPError( $this->discover() );

		$this->assertFalse( get_option( $this->lock_name() ) );
	}

	public function test_the_lock_is_released_when_the_fetch_throws() {
		$this->mock_dns();
		add_filter(
			'pre_http_request',
			function () {
				throw new \RuntimeException( 'boom' );
			}
		);

		try {
			$this->discover();
			$this->fail( 'The exception should propagate.' );
		} catch ( \RuntimeException $e ) {
			$this->assertSame( 'boom', $e->getMessage() );
		}

		$this->assertFalse( get_option( $this->lock_name() ) );
	}

	// Feature flag.

	public function test_a_disabled_feature_never_fetches_for_an_unknown_url() {
		$this->serve();
		add_filter( 'oauth2.cimd.enabled', '__return_false' );

		$this->assertNull( $this->discover() );
		$this->assertSame( 0, $this->request_count );
		$this->assertSame( 0, $this->count_client_posts() );
	}

	public function test_a_disabled_feature_returns_a_stale_stored_client_without_a_fetch() {
		$this->serve();
		$stored = $this->store( 'publish', time() - 10 );
		add_filter( 'oauth2.cimd.enabled', '__return_false' );

		$client = $this->discover();

		$this->assertSame( $stored->get_post_id(), $client->get_post_id() );
		$this->assertSame( 0, $this->request_count );
	}
}

/**
 * Thrown from a wp_redirect filter to capture the location and stop before exit().
 */
class CIMD_Redirect_Interrupt extends \RuntimeException {}

/**
 * Authorization code type that returns a marker instead of rendering the consent form.
 */
class CIMD_Form_Authorization_Code extends Authorization_Code {
	protected function render_form( Client $client, ?WP_Error $errors = null ) {
		return 'form:' . $client->get_id();
	}
}

/**
 * Test cases for the authorize step and token exchange of CIMD clients.
 */
class Test_CIMD_Flow extends CIMD_Clients_Test_Case {

	const REDIRECT_URI = 'https://client.example.com/callback';

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
		$_GET           = [];
		$_POST          = [];

		parent::tear_down();
	}

	/**
	 * Serve the test document.
	 *
	 * @param array $overrides Document fields to override.
	 */
	protected function serve( array $overrides = [] ) {
		$this->mock_dns();
		$this->mock_http( $this->http_response( wp_json_encode( $this->document( $overrides ) ) ) );
	}

	/**
	 * Run the authorize step.
	 *
	 * @param array $get  Query parameters.
	 * @param array $post Form fields.
	 * @return array Result of handle_authorisation() as `result`, and the redirect location as `location`.
	 */
	protected function authorize( array $get, array $post = [] ) {
		$_GET     = $get;
		$_POST    = $post;
		$location = null;
		$filter   = function ( $url ) use ( &$location ) {
			$location = $url;
			throw new CIMD_Redirect_Interrupt();
		};
		add_filter( 'wp_redirect', $filter );

		$result = null;
		try {
			$result = ( new CIMD_Form_Authorization_Code() )->handle_authorisation();
		} catch ( CIMD_Redirect_Interrupt $e ) {
			// The location was captured by the filter.
			unset( $e );
		} finally {
			remove_filter( 'wp_redirect', $filter );
			$_GET  = [];
			$_POST = [];
		}

		return compact( 'result', 'location' );
	}

	/**
	 * Query parameters of a valid authorize request.
	 *
	 * @param array $pair      PKCE pair.
	 * @param array $overrides Parameters to override.
	 * @return array
	 */
	protected function authorize_params( array $pair, array $overrides = [] ) {
		return array_merge(
			[
				'client_id'             => static::URL,
				'redirect_uri'          => static::REDIRECT_URI,
				'code_challenge'        => $pair['code_challenge'],
				'code_challenge_method' => $pair['code_challenge_method'],
			],
			$overrides
		);
	}

	/**
	 * Send a request to the token endpoint.
	 *
	 * @param array $params  Body parameters.
	 * @param array $headers Request headers.
	 * @return \WP_REST_Response
	 */
	protected function token( array $params, array $headers = [] ) {
		$request = new WP_REST_Request( 'POST', '/oauth2/access_token' );
		foreach ( $params as $key => $value ) {
			$request->set_param( $key, $value );
		}
		foreach ( $headers as $name => $value ) {
			$request->add_header( $name, $value );
		}

		return $this->server->dispatch( $request );
	}

	/**
	 * Mint an authorization code for the stored shadow client.
	 *
	 * @param Client $client Shadow client.
	 * @param array  $pair   PKCE pair.
	 * @return string
	 */
	protected function mint_code( Client $client, array $pair ) {
		$code = $client->generate_authorization_code(
			$this->factory->user->create_and_get(),
			[
				'code_challenge'        => $pair['code_challenge'],
				'code_challenge_method' => $pair['code_challenge_method'],
			]
		);
		$this->assertNotWPError( $code );

		return $code->get_code();
	}

	// Authorize: logged out.

	public function test_a_logged_out_request_for_an_unknown_url_redirects_to_login_without_a_fetch() {
		$this->serve();
		$pair = $this->make_pkce_pair();

		$out = $this->authorize( $this->authorize_params( $pair ) );

		$this->assertNull( $out['result'] );
		$this->assertStringStartsWith( wp_login_url(), $out['location'] );
		$this->assertSame( 0, $this->request_count );
		$this->assertSame( 0, $this->count_client_posts() );
		$this->assertFalse( get_option( 'oauth2_cimd_lock_' . md5( static::URL ) ) );
	}

	public function test_a_logged_out_request_for_an_unknown_url_redirects_to_login_even_without_other_parameters() {
		$this->serve();

		$out = $this->authorize( [ 'client_id' => static::URL ] );

		$this->assertStringStartsWith( wp_login_url(), $out['location'] );
		$this->assertSame( 0, $this->request_count );
		$this->assertSame( 0, $this->count_client_posts() );
	}

	public function test_a_logged_out_request_for_a_stale_stored_client_does_not_refetch() {
		$this->serve();
		$this->store( 'publish', time() - 10 );
		$pair = $this->make_pkce_pair();

		$out = $this->authorize( $this->authorize_params( $pair ) );

		$this->assertStringStartsWith( wp_login_url(), $out['location'] );
		$this->assertSame( 0, $this->request_count );
	}

	public function test_a_logged_out_request_for_an_unknown_slug_is_still_an_invalid_client() {
		$out = $this->authorize( [ 'client_id' => 'nonexistent-client-id' ] );

		$this->assertWPError( $out['result'] );
		$this->assertSame( 'oauth2.types.authorization_code.handle_authorisation.invalid_client_id', $out['result']->get_error_code() );
	}

	// Authorize: logged in.

	public function test_a_logged_in_request_for_an_unknown_url_creates_a_published_client_and_shows_the_form() {
		$this->serve();
		wp_set_current_user( $this->factory->user->create() );
		$pair = $this->make_pkce_pair();

		$out = $this->authorize( $this->authorize_params( $pair ) );

		$this->assertSame( 'form:' . static::URL, $out['result'] );
		$this->assertNull( $out['location'] );
		$this->assertSame( 1, $this->request_count );
		$this->assertSame( 1, $this->count_client_posts() );
		$this->assertTrue( Client::get_by_id( static::URL )->is_approved() );
	}

	public function test_a_logged_in_request_without_pkce_is_reported_to_the_client() {
		$this->serve();
		wp_set_current_user( $this->factory->user->create() );

		$out = $this->authorize(
			[
				'client_id'    => static::URL,
				'redirect_uri' => static::REDIRECT_URI,
			]
		);

		$this->assertStringStartsWith( static::REDIRECT_URI, $out['location'] );
		$this->assertStringContainsString( 'error=invalid_request', $out['location'] );
	}

	public function test_a_request_without_pkce_is_rejected_even_when_the_filter_turns_pkce_off() {
		$this->serve();
		add_filter( 'oauth2.pkce.required', '__return_false' );
		wp_set_current_user( $this->factory->user->create() );

		$out = $this->authorize(
			[
				'client_id'    => static::URL,
				'redirect_uri' => static::REDIRECT_URI,
			]
		);

		$this->assertNull( $out['result'] );
		$this->assertStringStartsWith( static::REDIRECT_URI, $out['location'] );
		$this->assertStringContainsString( 'error=invalid_request', $out['location'] );
	}

	public function test_a_logged_in_request_with_an_unregistered_redirect_uri_is_an_error() {
		$this->serve();
		wp_set_current_user( $this->factory->user->create() );
		$pair = $this->make_pkce_pair();

		$out = $this->authorize( $this->authorize_params( $pair, [ 'redirect_uri' => 'https://attacker.example/callback' ] ) );

		$this->assertWPError( $out['result'] );
		$this->assertSame( 'oauth2.types.authorization_code.handle_authorisation.invalid_redirect_uri', $out['result']->get_error_code() );
		$this->assertNull( $out['location'] );
	}

	public function test_a_fetch_error_is_returned_with_its_own_status_and_message() {
		$this->mock_dns();
		$this->mock_http( $this->http_response( '', [], 404 ) );
		wp_set_current_user( $this->factory->user->create() );
		$pair = $this->make_pkce_pair();

		$out = $this->authorize( $this->authorize_params( $pair ) );

		$this->assertCimdError( 'oauth2.cimd.fetch_failed', 400, $out['result'], false );
		$this->assertSame( 'The client metadata document request did not return 200.', $out['result']->get_error_message() );
		$this->assertSame( 400, ( new Authorization() )->get_error_status( $out['result'] ) );
		$this->assertNull( $out['location'] );
	}

	public function test_a_transient_fetch_error_keeps_its_status() {
		$this->mock_dns();
		$this->mock_http( new WP_Error( 'http_request_failed', 'Timed out' ) );
		wp_set_current_user( $this->factory->user->create() );
		$pair = $this->make_pkce_pair();

		$out = $this->authorize( $this->authorize_params( $pair ) );

		$this->assertCimdError( 'oauth2.cimd.fetch_failed', 503, $out['result'], true );
		$this->assertSame( 503, ( new Authorization() )->get_error_status( $out['result'] ) );
		$this->assertNull( $out['location'] );
	}

	public function test_the_manual_policy_gives_the_unapproved_client_error() {
		$this->serve();
		add_filter(
			'oauth2.cimd.policy',
			function () {
				return 'manual';
			}
		);
		wp_set_current_user( $this->factory->user->create() );
		$pair = $this->make_pkce_pair();

		$out = $this->authorize( $this->authorize_params( $pair ) );

		$this->assertWPError( $out['result'] );
		$this->assertSame( 'oauth2.types.authorization_code.handle_authorisation.unapproved_client', $out['result']->get_error_code() );
		$this->assertSame( 403, $out['result']->get_error_data()['status'] );
		$this->assertSame( 'draft', get_post_status( Client::get_by_id( static::URL, true )->get_post_id() ) );
	}

	public function test_the_deny_policy_returns_a_forbidden_error() {
		$this->serve();
		add_filter(
			'oauth2.cimd.policy',
			function () {
				return 'deny';
			}
		);
		wp_set_current_user( $this->factory->user->create() );
		$pair = $this->make_pkce_pair();

		$out = $this->authorize( $this->authorize_params( $pair ) );

		$this->assertCimdError( 'oauth2.cimd.not_allowed', 403, $out['result'] );
		$this->assertSame( 0, $this->count_client_posts() );
	}

	public function test_the_personal_client_id_is_still_an_invalid_client_at_authorize() {
		$this->serve();
		wp_set_current_user( $this->factory->user->create() );

		$out = $this->authorize( [ 'client_id' => \WP\OAuth2\PersonalClient::ID ] );

		$this->assertWPError( $out['result'] );
		$this->assertSame( 'oauth2.types.authorization_code.handle_authorisation.invalid_client_id', $out['result']->get_error_code() );
		$this->assertSame( 0, $this->request_count );
	}

	public function test_a_disabled_feature_leaves_an_unknown_url_an_invalid_client() {
		$this->serve();
		add_filter( 'oauth2.cimd.enabled', '__return_false' );
		wp_set_current_user( $this->factory->user->create() );
		$pair = $this->make_pkce_pair();

		$out = $this->authorize( $this->authorize_params( $pair ) );

		$this->assertWPError( $out['result'] );
		$this->assertSame( 'oauth2.types.authorization_code.handle_authorisation.invalid_client_id', $out['result']->get_error_code() );
		$this->assertSame( 0, $this->request_count );
	}

	// End to end.

	public function test_authorize_then_exchange_the_code_with_a_verifier() {
		$this->serve();
		$user = $this->factory->user->create_and_get();
		wp_set_current_user( $user->ID );
		$pair = $this->make_pkce_pair();

		$out = $this->authorize(
			$this->authorize_params( $pair, [ 'state' => 'xyz' ] ),
			[
				'_wpnonce'  => wp_create_nonce( 'oauth2_authorize:' . static::URL ),
				'wp-submit' => 'authorize',
			]
		);

		$this->assertStringStartsWith( static::REDIRECT_URI, $out['location'] );
		parse_str( wp_parse_url( $out['location'], PHP_URL_QUERY ), $args );
		$this->assertSame( 'xyz', $args['state'] );
		$this->assertNotEmpty( $args['code'] );

		wp_set_current_user( 0 );
		$requests = $this->request_count;

		$response = $this->token(
			[
				'grant_type'    => 'authorization_code',
				'client_id'     => static::URL,
				'code'          => $args['code'],
				'code_verifier' => $pair['code_verifier'],
				'redirect_uri'  => static::REDIRECT_URI,
			]
		);

		$this->assertSame( 200, $response->get_status() );
		$data = $response->get_data();
		$this->assertSame( 'bearer', $data['token_type'] );
		$token = Tokens\get_by_id( $data['access_token'] );
		$this->assertSame( static::URL, $token->get_client()->get_id() );
		$this->assertSame( $user->ID, $token->get_user()->ID );
		$this->assertSame( $requests, $this->request_count );
	}

	public function test_the_token_endpoint_rejects_a_wrong_verifier() {
		$this->serve();
		$client = $this->store();
		$pair   = $this->make_pkce_pair();

		$response = $this->token(
			[
				'grant_type'    => 'authorization_code',
				'client_id'     => static::URL,
				'code'          => $this->mint_code( $client, $pair ),
				'code_verifier' => PKCE::generate_verifier(),
			]
		);

		$this->assertSame( 400, $response->get_status() );
		$this->assertSame( 'invalid_grant', $response->get_data()['error'] );
	}

	public function test_the_token_endpoint_rejects_a_client_secret() {
		$this->serve();
		$client = $this->store();
		$pair   = $this->make_pkce_pair();
		$code   = $this->mint_code( $client, $pair );

		$response = $this->token(
			[
				'grant_type'    => 'authorization_code',
				'client_id'     => static::URL,
				'client_secret' => 'a-secret',
				'code'          => $code,
				'code_verifier' => $pair['code_verifier'],
			]
		);

		$this->assertSame( 401, $response->get_status() );
		$this->assertSame( 'invalid_client', $response->get_data()['error'] );
		$this->assertSame( 0, $this->request_count );

		$retry = $this->token(
			[
				'grant_type'    => 'authorization_code',
				'client_id'     => static::URL,
				'code'          => $code,
				'code_verifier' => $pair['code_verifier'],
			]
		);
		$this->assertSame( 200, $retry->get_status() );
	}

	public function test_the_token_endpoint_rejects_a_basic_auth_secret() {
		$client = $this->store();
		$pair   = $this->make_pkce_pair();

		$response = $this->token(
			[
				'grant_type'    => 'authorization_code',
				'code'          => $this->mint_code( $client, $pair ),
				'code_verifier' => $pair['code_verifier'],
			],
			[ 'Authorization' => 'Basic ' . base64_encode( urlencode( static::URL ) . ':' . urlencode( 'a-secret' ) ) ]
		);

		$this->assertSame( 401, $response->get_status() );
		$this->assertSame( 'invalid_client', $response->get_data()['error'] );
	}

	public function test_the_token_endpoint_accepts_basic_auth_with_an_empty_secret() {
		$client = $this->store();
		$pair   = $this->make_pkce_pair();

		$response = $this->token(
			[
				'grant_type'    => 'authorization_code',
				'code'          => $this->mint_code( $client, $pair ),
				'code_verifier' => $pair['code_verifier'],
			],
			[ 'Authorization' => 'Basic ' . base64_encode( urlencode( static::URL ) . ':' ) ]
		);

		$this->assertSame( 200, $response->get_status() );
	}

	public function test_the_token_endpoint_does_not_fetch_an_unknown_url() {
		$this->serve();

		$response = $this->token(
			[
				'grant_type'    => 'authorization_code',
				'client_id'     => static::URL,
				'code'          => 'somecode',
				'code_verifier' => $this->make_pkce_pair()['code_verifier'],
			]
		);

		$this->assertSame( 400, $response->get_status() );
		$this->assertSame( 'invalid_client', $response->get_data()['error'] );
		$this->assertSame( 0, $this->request_count );
		$this->assertSame( 0, $this->count_client_posts() );
	}

	public function test_the_token_endpoint_does_not_serve_an_unapproved_client() {
		$client = $this->store( 'draft' );
		$pair   = $this->make_pkce_pair();

		$response = $this->token(
			[
				'grant_type'    => 'authorization_code',
				'client_id'     => static::URL,
				'code'          => $this->mint_code( $client, $pair ),
				'code_verifier' => $pair['code_verifier'],
			]
		);

		$this->assertSame( 400, $response->get_status() );
		$this->assertSame( 'invalid_client', $response->get_data()['error'] );
	}

	public function test_the_client_credentials_grant_is_refused_for_a_cimd_client() {
		$this->store();

		$response = $this->token(
			[
				'grant_type'    => 'client_credentials',
				'client_id'     => static::URL,
				'client_secret' => 'a-secret',
			]
		);

		$this->assertSame( 401, $response->get_status() );
		$this->assertSame( 'invalid_client', $response->get_data()['error'] );
	}
}
