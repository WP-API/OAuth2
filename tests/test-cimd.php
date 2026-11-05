<?php
/**
 * Tests for OAuth Client ID Metadata Document support.
 *
 * @package WP\OAuth2\Tests
 */

namespace WP\OAuth2\Tests;

require_once __DIR__ . '/class-test-case.php';

use WP_Error;

use function WP\OAuth2\CIMD\fetch_document;
use function WP\OAuth2\CIMD\is_cimd_client_id;
use function WP\OAuth2\CIMD\is_public_ip;
use function WP\OAuth2\CIMD\resolve_host;
use function WP\OAuth2\CIMD\validate_client_id_url;
use function WP\OAuth2\CIMD\validate_document;

/**
 * Test cases for client ID metadata documents.
 */
class Test_CIMD extends Test_Case {

	const URL  = 'https://client.example.com/oauth/client.json';
	const HOST = 'client.example.com';

	/**
	 * Arguments passed to the most recent mocked HTTP request.
	 *
	 * @var array|null
	 */
	protected $request_args = null;

	/**
	 * Number of mocked HTTP requests made.
	 *
	 * @var int
	 */
	protected $request_count = 0;

	public function tear_down() {
		remove_all_filters( 'pre_http_request' );
		remove_all_filters( 'oauth2.cimd.pre_resolve_host' );
		remove_all_filters( 'oauth2.cimd.admit_url' );
		remove_all_filters( 'oauth2.cimd.allow_loopback' );
		remove_all_filters( 'oauth2.cimd.cache_ttl' );
		remove_all_actions( 'http_api_curl' );
		$this->request_args  = null;
		$this->request_count = 0;

		parent::tear_down();
	}

	/**
	 * Mock DNS so that the host resolves to the given addresses.
	 *
	 * @param string[] $ips Addresses to return.
	 */
	protected function mock_dns( array $ips = [ '93.184.216.34' ] ) {
		add_filter(
			'oauth2.cimd.pre_resolve_host',
			function () use ( $ips ) {
				return $ips;
			}
		);
	}

	/**
	 * Mock the HTTP response and capture the request arguments.
	 *
	 * @param array|WP_Error $response Response to return.
	 */
	protected function mock_http( $response ) {
		add_filter(
			'pre_http_request',
			function ( $pre, $args ) use ( $response ) {
				$this->request_args = $args;
				++$this->request_count;
				return $response;
			},
			10,
			2
		);
	}

	/**
	 * Build a mocked HTTP response.
	 *
	 * @param string $body    Response body.
	 * @param array  $headers Response headers.
	 * @param int    $code    Status code.
	 * @return array
	 */
	protected function http_response( $body, array $headers = [], $code = 200 ) {
		return [
			'headers'  => array_merge( [ 'content-type' => 'application/json' ], $headers ),
			'body'     => $body,
			'response' => [
				'code'    => $code,
				'message' => '',
			],
			'cookies'  => [],
			'filename' => null,
		];
	}

	/**
	 * Fetch the test URL with a mocked 200 response.
	 *
	 * @param array  $headers Response headers.
	 * @param string $body    Response body.
	 * @return array|WP_Error
	 */
	protected function fetch_with_headers( array $headers = [], $body = '{"client_id":"x"}' ) {
		$this->mock_dns();
		$this->mock_http( $this->http_response( $body, $headers ) );

		return fetch_document( static::URL );
	}

	/**
	 * Assert that a value is a WP_Error with the given code and data.
	 *
	 * @param string $code     Expected error code.
	 * @param int    $status   Expected status.
	 * @param mixed  $actual   Value under test.
	 * @param bool   $transient Expected transient flag, or null if not set.
	 */
	protected function assertCimdError( $code, $status, $actual, $transient = null ) {
		$this->assertWPError( $actual );
		$this->assertSame( $code, $actual->get_error_code() );
		$data = $actual->get_error_data();
		$this->assertSame( $status, $data['status'] );
		if ( null === $transient ) {
			$this->assertArrayNotHasKey( 'transient', $data );
		} else {
			$this->assertSame( $transient, $data['transient'] );
		}
	}

	/**
	 * A minimal valid metadata document.
	 *
	 * @param array $overrides Fields to override.
	 * @return array
	 */
	protected function document( array $overrides = [] ) {
		return array_merge(
			[
				'client_id'     => static::URL,
				'client_name'   => 'Example Client',
				'redirect_uris' => [ 'https://client.example.com/callback' ],
			],
			$overrides
		);
	}

	public function test_is_cimd_client_id() {
		$this->assertTrue( is_cimd_client_id( 'https://client.example.com/id' ) );
		$this->assertFalse( is_cimd_client_id( 'http://client.example.com/id' ) );
		$this->assertFalse( is_cimd_client_id( 'HTTPS://client.example.com/id' ) );
		$this->assertFalse( is_cimd_client_id( 'abcdefghijkl' ) );
		$this->assertFalse( is_cimd_client_id( null ) );
		$this->assertFalse( is_cimd_client_id( [ 'https://client.example.com/id' ] ) );
	}

	// validate_client_id_url().

	public function test_validate_client_id_url_accepts_valid_url() {
		$this->assertTrue( validate_client_id_url( static::URL ) );
		$this->assertTrue( validate_client_id_url( 'https://client.example.com:8443/a/b' ) );
		$this->assertTrue( validate_client_id_url( 'https://client.example.com/a/..b/c.' ) );
	}

	/**
	 * @dataProvider invalid_client_id_provider
	 *
	 * @param mixed $url Invalid URL.
	 */
	public function test_validate_client_id_url_rejects( $url ) {
		$this->assertCimdError( 'oauth2.cimd.invalid_client_id', 400, validate_client_id_url( $url ) );
	}

	public function invalid_client_id_provider() {
		return [
			'not a string'        => [ [ 'https://client.example.com/id' ] ],
			'null'                => [ null ],
			'too long'            => [ 'https://client.example.com/' . str_repeat( 'a', 2048 ) ],
			'http scheme'         => [ 'http://client.example.com/id' ],
			'uppercase scheme'    => [ 'HTTPS://client.example.com/id' ],
			'legacy slug'         => [ 'abcdefghijkl' ],
			'no host'             => [ 'https:///id' ],
			'unparseable'         => [ 'https://:/id' ],
			'user'                => [ 'https://user@client.example.com/id' ],
			'user and pass'       => [ 'https://user:pass@client.example.com/id' ],
			'fragment'            => [ 'https://client.example.com/id#frag' ],
			'empty fragment'      => [ 'https://client.example.com/id#' ],
			'query'               => [ 'https://client.example.com/id?a=b' ],
			'empty query'         => [ 'https://client.example.com/id?' ],
			'no path'             => [ 'https://client.example.com' ],
			'root path'           => [ 'https://client.example.com/' ],
			'single dot segment'  => [ 'https://client.example.com/a/./b' ],
			'double dot segment'  => [ 'https://client.example.com/a/../b' ],
			'encoded dot'         => [ 'https://client.example.com/a/%2e/b' ],
			'encoded double dots' => [ 'https://client.example.com/a/%2E%2e/b' ],
			'trailing dot'        => [ 'https://client.example.com/a/..' ],
		];
	}

	public function test_validate_client_id_url_accepts_exactly_2048_bytes() {
		$url = 'https://client.example.com/' . str_repeat( 'a', 2048 - strlen( 'https://client.example.com/' ) );

		$this->assertSame( 2048, strlen( $url ) );
		$this->assertTrue( validate_client_id_url( $url ) );
	}

	public function test_validate_client_id_url_rejects_the_issuer() {
		$this->assertCimdError( 'oauth2.cimd.invalid_client_id', 400, validate_client_id_url( home_url() ) );
		$this->assertCimdError( 'oauth2.cimd.invalid_client_id', 400, validate_client_id_url( trailingslashit( home_url() ) ) );
	}

	public function test_validate_client_id_url_rejects_the_issuer_with_a_path() {
		add_filter(
			'home_url',
			function () {
				return 'https://client.example.com/site';
			}
		);

		$this->assertCimdError( 'oauth2.cimd.invalid_client_id', 400, validate_client_id_url( 'https://client.example.com/site' ) );
		$this->assertCimdError( 'oauth2.cimd.invalid_client_id', 400, validate_client_id_url( 'https://client.example.com/site/' ) );

		remove_all_filters( 'home_url' );
	}

	public function test_validate_client_id_url_honours_admit_filter() {
		$seen = null;
		add_filter(
			'oauth2.cimd.admit_url',
			function ( $admit, $url ) use ( &$seen ) {
				$seen = $url;
				return false;
			},
			10,
			2
		);

		$this->assertCimdError( 'oauth2.cimd.not_allowed', 403, validate_client_id_url( static::URL ) );
		$this->assertSame( static::URL, $seen );
	}

	// is_public_ip().

	/**
	 * @dataProvider blocked_ip_provider
	 *
	 * @param string $ip Address in a blocked range.
	 */
	public function test_is_public_ip_rejects_special_use_ranges( $ip ) {
		$this->assertFalse( is_public_ip( $ip ) );
	}

	public function blocked_ip_provider() {
		return [
			'0.0.0.0/8'        => [ '0.1.2.3' ],
			'10.0.0.0/8'       => [ '10.1.2.3' ],
			'100.64.0.0/10'    => [ '100.100.1.1' ],
			'127.0.0.0/8'      => [ '127.0.0.1' ],
			'169.254.0.0/16'   => [ '169.254.169.254' ],
			'172.16.0.0/12'    => [ '172.20.0.1' ],
			'192.0.0.0/24'     => [ '192.0.0.8' ],
			'192.0.2.0/24'     => [ '192.0.2.1' ],
			'192.88.99.0/24'   => [ '192.88.99.1' ],
			'192.168.0.0/16'   => [ '192.168.1.1' ],
			'198.18.0.0/15'    => [ '198.19.0.1' ],
			'198.51.100.0/24'  => [ '198.51.100.7' ],
			'203.0.113.0/24'   => [ '203.0.113.9' ],
			'224.0.0.0/4'      => [ '239.255.255.250' ],
			'240.0.0.0/4'      => [ '250.0.0.1' ],
			'255.255.255.255'  => [ '255.255.255.255' ],
			'::/128'           => [ '::' ],
			'::1/128'          => [ '::1' ],
			'::ffff:0:0/96'    => [ '::ffff:127.0.0.1' ],
			'::ffff public v4' => [ '::ffff:93.184.216.34' ],
			'64:ff9b::/96'     => [ '64:ff9b::7f00:1' ],
			'64:ff9b:1::/48'   => [ '64:ff9b:1::1' ],
			'100::/64'         => [ '100::1' ],
			'2001::/23'        => [ '2001:1::1' ],
			'2001:db8::/32'    => [ '2001:db8::1' ],
			'2002::/16'        => [ '2002:7f00:1::1' ],
			'fc00::/7 fc'      => [ 'fc00::1' ],
			'fc00::/7 fd'      => [ 'fd12:3456:789a::1' ],
			'fe80::/10'        => [ 'fe80::1' ],
			'ff00::/8'         => [ 'ff02::1' ],
			'invalid'          => [ 'not-an-ip' ],
			'empty'            => [ '' ],
			'host name'        => [ 'client.example.com' ],
		];
	}

	/**
	 * @dataProvider public_ip_provider
	 *
	 * @param string $ip Public address.
	 */
	public function test_is_public_ip_accepts_public_addresses( $ip ) {
		$this->assertTrue( is_public_ip( $ip ) );
	}

	public function public_ip_provider() {
		return [
			'example.com v4'     => [ '93.184.216.34' ],
			'example.com v6'     => [ '2606:2800:220:1::1' ],
			'just outside /12'   => [ '172.32.0.1' ],
			'just outside CGNAT' => [ '100.128.0.1' ],
			'just outside /15'   => [ '198.20.0.1' ],
			'just outside 2001'  => [ '2001:200::1' ],
			'8.8.8.8'            => [ '8.8.8.8' ],
		];
	}

	public function test_is_public_ip_rejects_non_strings() {
		$this->assertFalse( is_public_ip( null ) );
		$this->assertFalse( is_public_ip( 134744072 ) );
		$this->assertFalse( is_public_ip( [ '8.8.8.8' ] ) );
	}

	public function test_is_public_ip_allow_loopback_filter() {
		add_filter( 'oauth2.cimd.allow_loopback', '__return_true' );

		$this->assertTrue( is_public_ip( '127.0.0.1' ) );
		$this->assertTrue( is_public_ip( '127.8.9.10' ) );
		$this->assertTrue( is_public_ip( '::1' ) );
		$this->assertFalse( is_public_ip( '10.0.0.1' ) );
		$this->assertFalse( is_public_ip( '192.168.1.1' ) );
		$this->assertFalse( is_public_ip( '::' ) );
		$this->assertFalse( is_public_ip( 'fd00::1' ) );
	}

	// resolve_host().

	public function test_resolve_host_uses_pre_filter() {
		add_filter(
			'oauth2.cimd.pre_resolve_host',
			function ( $pre, $host ) {
				return [ $host . '-ip' ];
			},
			10,
			2
		);

		$this->assertSame( [ 'client.example.com-ip' ], resolve_host( 'client.example.com' ) );
	}

	public function test_resolve_host_pre_filter_can_return_empty_array() {
		add_filter( 'oauth2.cimd.pre_resolve_host', '__return_empty_array' );

		$this->assertSame( [], resolve_host( 'client.example.com' ) );
	}

	public function test_resolve_host_returns_ip_literals() {
		$this->assertSame( [ '93.184.216.34' ], resolve_host( '93.184.216.34' ) );
		$this->assertSame( [ '2606:2800:220:1::1' ], resolve_host( '[2606:2800:220:1::1]' ) );
	}

	// fetch_document().

	public function test_fetch_document_returns_validation_error() {
		$this->mock_http( $this->http_response( '{}' ) );

		$this->assertCimdError( 'oauth2.cimd.invalid_client_id', 400, fetch_document( 'http://client.example.com/id' ) );
		$this->assertSame( 0, $this->request_count );
	}

	public function test_fetch_document_rejects_private_v4() {
		$this->mock_dns( [ '10.0.0.5' ] );
		$this->mock_http( $this->http_response( '{}' ) );

		$this->assertCimdError( 'oauth2.cimd.unsafe_host', 400, fetch_document( static::URL ), false );
		$this->assertSame( 0, $this->request_count );
	}

	public function test_fetch_document_rejects_unique_local_v6() {
		$this->mock_dns( [ 'fd12:3456:789a::1' ] );
		$this->mock_http( $this->http_response( '{}' ) );

		$this->assertCimdError( 'oauth2.cimd.unsafe_host', 400, fetch_document( static::URL ), false );
		$this->assertSame( 0, $this->request_count );
	}

	public function test_fetch_document_rejects_mixed_public_and_private_addresses() {
		$this->mock_dns( [ '93.184.216.34', '169.254.169.254' ] );
		$this->mock_http( $this->http_response( '{}' ) );

		$this->assertCimdError( 'oauth2.cimd.unsafe_host', 400, fetch_document( static::URL ), false );
		$this->assertSame( 0, $this->request_count );
	}

	public function test_fetch_document_with_no_dns_result_is_transient() {
		$this->mock_dns( [] );
		$this->mock_http( $this->http_response( '{}' ) );

		$this->assertCimdError( 'oauth2.cimd.fetch_failed', 503, fetch_document( static::URL ), true );
		$this->assertSame( 0, $this->request_count );
	}

	public function test_fetch_document_transport_error_is_transient() {
		$this->mock_dns();
		$this->mock_http( new WP_Error( 'http_request_failed', 'Timed out' ) );

		$this->assertCimdError( 'oauth2.cimd.fetch_failed', 503, fetch_document( static::URL ), true );
	}

	public function test_fetch_document_redirect_is_terminal() {
		$this->mock_dns();
		$this->mock_http( $this->http_response( '', [ 'location' => 'https://other.example.com/' ], 302 ) );

		$this->assertCimdError( 'oauth2.cimd.fetch_failed', 400, fetch_document( static::URL ), false );
	}

	public function test_fetch_document_404_is_terminal() {
		$this->mock_dns();
		$this->mock_http( $this->http_response( 'Not found', [], 404 ) );

		$this->assertCimdError( 'oauth2.cimd.fetch_failed', 400, fetch_document( static::URL ), false );
	}

	public function test_fetch_document_rejects_oversized_body() {
		$this->mock_dns();
		$this->mock_http( $this->http_response( str_repeat( 'a', 5121 ) ) );

		$this->assertCimdError( 'oauth2.cimd.document_too_large', 400, fetch_document( static::URL ), false );
	}

	public function test_fetch_document_accepts_a_body_of_exactly_5120_bytes() {
		$body = '{"a":"' . str_repeat( 'a', 5120 - strlen( '{"a":""}' ) ) . '"}';
		$this->assertSame( 5120, strlen( $body ) );

		$this->mock_dns();
		$this->mock_http( $this->http_response( $body ) );

		$result = fetch_document( static::URL );
		$this->assertIsArray( $result );
		$this->assertArrayHasKey( 'a', $result['document'] );
	}

	public function test_fetch_document_rejects_wrong_content_type() {
		$result = $this->fetch_with_headers( [ 'content-type' => 'text/html' ] );

		$this->assertCimdError( 'oauth2.cimd.invalid_document', 400, $result, false );
	}

	public function test_fetch_document_rejects_missing_content_type() {
		$this->mock_dns();
		$response = $this->http_response( '{"a":1}' );
		unset( $response['headers']['content-type'] );
		$this->mock_http( $response );

		$this->assertCimdError( 'oauth2.cimd.invalid_document', 400, fetch_document( static::URL ), false );
	}

	public function test_fetch_document_accepts_json_content_type_parameters_and_case() {
		$result = $this->fetch_with_headers( [ 'content-type' => 'Application/JSON; charset=utf-8' ] );

		$this->assertSame( [ 'client_id' => 'x' ], $result['document'] );
	}

	public function test_fetch_document_accepts_structured_syntax_suffix() {
		$result = $this->fetch_with_headers( [ 'content-type' => 'application/vnd.foo+json' ] );

		$this->assertSame( [ 'client_id' => 'x' ], $result['document'] );
	}

	public function test_fetch_document_rejects_json_list() {
		$this->assertCimdError( 'oauth2.cimd.invalid_document', 400, $this->fetch_with_headers( [], '["a","b"]' ), false );
	}

	public function test_fetch_document_rejects_empty_json_containers_and_scalars() {
		$this->assertCimdError( 'oauth2.cimd.invalid_document', 400, $this->fetch_with_headers( [], '[]' ), false );
		$this->assertCimdError( 'oauth2.cimd.invalid_document', 400, $this->fetch_with_headers( [], '{}' ), false );
		$this->assertCimdError( 'oauth2.cimd.invalid_document', 400, $this->fetch_with_headers( [], '"text"' ), false );
		$this->assertCimdError( 'oauth2.cimd.invalid_document', 400, $this->fetch_with_headers( [], 'not json' ), false );
	}

	public function test_fetch_document_cache_ttl_defaults_to_minimum() {
		$before = time();
		$result = $this->fetch_with_headers();

		$this->assertGreaterThanOrEqual( $before + 300, $result['expires'] );
		$this->assertLessThanOrEqual( time() + 300, $result['expires'] );
	}

	public function test_fetch_document_max_age_below_minimum_is_raised() {
		$before = time();
		$result = $this->fetch_with_headers( [ 'cache-control' => 'max-age=10' ] );

		$this->assertGreaterThanOrEqual( $before + 300, $result['expires'] );
		$this->assertLessThanOrEqual( time() + 300, $result['expires'] );
	}

	public function test_fetch_document_max_age_above_maximum_is_lowered() {
		$before = time();
		$result = $this->fetch_with_headers( [ 'cache-control' => 'public, max-age=86400' ] );

		$this->assertGreaterThanOrEqual( $before + 3600, $result['expires'] );
		$this->assertLessThanOrEqual( time() + 3600, $result['expires'] );
	}

	public function test_fetch_document_max_age_in_range_is_used() {
		$before = time();
		$result = $this->fetch_with_headers( [ 'cache-control' => 'Public, Max-Age=1200' ] );

		$this->assertGreaterThanOrEqual( $before + 1200, $result['expires'] );
		$this->assertLessThanOrEqual( time() + 1200, $result['expires'] );
	}

	public function test_fetch_document_no_store_overrides_max_age() {
		$before = time();
		$result = $this->fetch_with_headers( [ 'cache-control' => 'no-store, max-age=1200' ] );

		$this->assertGreaterThanOrEqual( $before + 300, $result['expires'] );
		$this->assertLessThanOrEqual( time() + 300, $result['expires'] );
	}

	public function test_fetch_document_no_cache_overrides_max_age() {
		$before = time();
		$result = $this->fetch_with_headers( [ 'cache-control' => 'max-age=1200, no-cache' ] );

		$this->assertGreaterThanOrEqual( $before + 300, $result['expires'] );
		$this->assertLessThanOrEqual( time() + 300, $result['expires'] );
	}

	public function test_fetch_document_cache_ttl_filter() {
		$seen = [];
		add_filter(
			'oauth2.cimd.cache_ttl',
			function ( $ttl, $response ) use ( &$seen ) {
				$seen = [ $ttl, $response ];
				return 60;
			},
			10,
			2
		);

		$before = time();
		$result = $this->fetch_with_headers( [ 'cache-control' => 'max-age=1200' ] );

		$this->assertSame( 1200, $seen[0] );
		$this->assertSame( 200, $seen[1]['response']['code'] );
		$this->assertGreaterThanOrEqual( $before + 60, $result['expires'] );
		$this->assertLessThanOrEqual( time() + 60, $result['expires'] );
	}

	public function test_fetch_document_cache_ttl_filter_result_is_not_negative() {
		add_filter(
			'oauth2.cimd.cache_ttl',
			function () {
				return -100;
			}
		);

		$before = time();
		$result = $this->fetch_with_headers();

		$this->assertGreaterThanOrEqual( $before, $result['expires'] );
		$this->assertLessThanOrEqual( time(), $result['expires'] );
	}

	public function test_fetch_document_request_arguments() {
		$this->fetch_with_headers();

		$this->assertSame( 0, $this->request_args['redirection'] );
		$this->assertSame( 5121, $this->request_args['limit_response_size'] );
		$this->assertSame( 5, $this->request_args['timeout'] );
		$this->assertTrue( $this->request_args['sslverify'] );
		$this->assertTrue( $this->request_args['reject_unsafe_urls'] );
		$this->assertSame( [], $this->request_args['cookies'] );
		$this->assertSame( 'application/json', $this->request_args['headers']['Accept'] );
	}

	public function test_fetch_document_does_not_validate_the_document() {
		$result = $this->fetch_with_headers( [], '{"client_id":"https://other.example.com/id"}' );

		$this->assertSame( [ 'client_id' => 'https://other.example.com/id' ], $result['document'] );
	}

	public function test_fetch_document_registers_the_pin_only_during_the_request() {
		$during = null;
		$this->mock_dns();
		add_filter(
			'pre_http_request',
			function () use ( &$during ) {
				$during = has_action( 'http_api_curl' );
				return $this->http_response( '{"a":1}' );
			}
		);

		$this->assertFalse( has_action( 'http_api_curl' ) );
		$this->assertIsArray( fetch_document( static::URL ) );
		$this->assertNotFalse( $during );
		$this->assertFalse( has_action( 'http_api_curl' ) );
	}

	public function test_fetch_document_removes_the_pin_after_a_transport_error() {
		$this->mock_dns();
		$this->mock_http( new WP_Error( 'http_request_failed', 'Timed out' ) );

		$this->assertWPError( fetch_document( static::URL ) );
		$this->assertFalse( has_action( 'http_api_curl' ) );
	}

	public function test_fetch_document_removes_the_pin_after_a_bad_response() {
		$this->mock_dns();
		$this->mock_http( $this->http_response( '', [], 500 ) );

		$this->assertWPError( fetch_document( static::URL ) );
		$this->assertFalse( has_action( 'http_api_curl' ) );
	}

	public function test_fetch_document_removes_the_pin_when_the_request_throws() {
		$this->mock_dns();
		add_filter(
			'pre_http_request',
			function () {
				throw new \RuntimeException( 'boom' );
			}
		);

		try {
			fetch_document( static::URL );
			$this->fail( 'The exception should propagate.' );
		} catch ( \RuntimeException $e ) {
			$this->assertSame( 'boom', $e->getMessage() );
		}

		$this->assertFalse( has_action( 'http_api_curl' ) );
	}

	public function test_fetch_document_pin_ignores_other_urls() {
		$pin = null;
		$this->mock_dns( [ '2606:2800:220:1::1' ] );
		add_filter(
			'pre_http_request',
			function () use ( &$pin ) {
				global $wp_filter;
				$pin = array_values( $wp_filter['http_api_curl']->callbacks[10] )[0]['function'];
				return $this->http_response( '{"a":1}' );
			}
		);

		fetch_document( static::URL );

		$handle = curl_init();
		$this->assertNull( $pin( $handle, [], 'https://other.example.com/id' ) );
		$this->assertNull( $pin( $handle, [], static::URL ) );
	}

	// validate_document().

	public function test_validate_document_happy_path_is_normalised() {
		$result = validate_document(
			$this->document(
				[
					'client_name'                => '  <b>Example</b> Client ',
					'redirect_uris'              => [
						3 => 'https://client.example.com/callback',
						7 => 'http://localhost:8080/cb',
					],
					'grant_types'                => [ 'refresh_token', 'authorization_code' ],
					'response_types'             => [ 'code', 'token' ],
					'token_endpoint_auth_method' => 'none',
					'client_uri'                 => 'https://client.example.com/',
					'unknown'                    => 'ignored',
				]
			),
			static::URL
		);

		$this->assertSame(
			[
				'client_id'                  => static::URL,
				'client_name'                => 'Example Client',
				'redirect_uris'              => [ 'https://client.example.com/callback', 'http://localhost:8080/cb' ],
				'grant_types'                => [ 'authorization_code' ],
				'response_types'             => [ 'code' ],
				'token_endpoint_auth_method' => 'none',
			],
			$result
		);
	}

	public function test_validate_document_applies_defaults() {
		$result = validate_document( $this->document(), static::URL );

		$this->assertSame( [ 'authorization_code' ], $result['grant_types'] );
		$this->assertSame( [ 'code' ], $result['response_types'] );
		$this->assertSame( 'none', $result['token_endpoint_auth_method'] );
	}

	public function test_validate_document_rejects_non_array() {
		$this->assertCimdError( 'oauth2.cimd.invalid_document', 400, validate_document( 'nope', static::URL ), false );
	}

	public function test_validate_document_requires_matching_client_id() {
		$this->assertCimdError( 'oauth2.cimd.invalid_document', 400, validate_document( $this->document( [ 'client_id' => static::URL . '/' ] ), static::URL ), false );
		$this->assertCimdError( 'oauth2.cimd.invalid_document', 400, validate_document( $this->document( [ 'client_id' => 'HTTPS://client.example.com/oauth/client.json' ] ), static::URL ), false );
		$this->assertCimdError( 'oauth2.cimd.invalid_document', 400, validate_document( $this->document( [ 'client_id' => [ static::URL ] ] ), static::URL ), false );

		$document = $this->document();
		unset( $document['client_id'] );
		$this->assertCimdError( 'oauth2.cimd.invalid_document', 400, validate_document( $document, static::URL ), false );
	}

	public function test_validate_document_rejects_client_secret() {
		$this->assertCimdError( 'oauth2.cimd.invalid_document', 400, validate_document( $this->document( [ 'client_secret' => 'shh' ] ), static::URL ), false );
		$this->assertCimdError( 'oauth2.cimd.invalid_document', 400, validate_document( $this->document( [ 'client_secret' => null ] ), static::URL ), false );
		$this->assertCimdError( 'oauth2.cimd.invalid_document', 400, validate_document( $this->document( [ 'client_secret_expires_at' => 0 ] ), static::URL ), false );
	}

	/**
	 * @dataProvider invalid_redirect_uris_provider
	 *
	 * @param mixed $redirect_uris Invalid redirect_uris value.
	 */
	public function test_validate_document_rejects_invalid_redirect_uris( $redirect_uris ) {
		$result = validate_document( $this->document( [ 'redirect_uris' => $redirect_uris ] ), static::URL );

		$this->assertCimdError( 'oauth2.cimd.invalid_document', 400, $result, false );
	}

	public function invalid_redirect_uris_provider() {
		return [
			'string'             => [ 'https://client.example.com/callback' ],
			'empty'              => [ [] ],
			'non-string entry'   => [ [ 'https://client.example.com/callback', 5 ] ],
			'relative'           => [ [ '/callback' ] ],
			'no scheme'          => [ [ 'client.example.com/callback' ] ],
			'no host'            => [ [ 'https:///callback' ] ],
			'fragment'           => [ [ 'https://client.example.com/callback#x' ] ],
			'empty fragment'     => [ [ 'https://client.example.com/callback#' ] ],
			'http non-loopback'  => [ [ 'http://client.example.com/callback' ] ],
			'http lookalike'     => [ [ 'http://localhost.example.com/callback' ] ],
			'custom scheme'      => [ [ 'com.example.app:/callback' ] ],
			'javascript'         => [ [ 'javascript://localhost/%0aalert(1)' ] ],
			'one bad of several' => [ [ 'https://client.example.com/callback', 'http://client.example.com/callback' ] ],
		];
	}

	public function test_validate_document_missing_redirect_uris() {
		$document = $this->document();
		unset( $document['redirect_uris'] );

		$this->assertCimdError( 'oauth2.cimd.invalid_document', 400, validate_document( $document, static::URL ), false );
	}

	/**
	 * @dataProvider loopback_redirect_provider
	 *
	 * @param string $redirect_uri Loopback redirect URI.
	 */
	public function test_validate_document_accepts_loopback_http_redirects( $redirect_uri ) {
		$result = validate_document( $this->document( [ 'redirect_uris' => [ $redirect_uri ] ] ), static::URL );

		$this->assertSame( [ $redirect_uri ], $result['redirect_uris'] );
	}

	public function loopback_redirect_provider() {
		return [
			'localhost' => [ 'http://localhost/cb' ],
			'127.0.0.1' => [ 'http://127.0.0.1:3000/cb' ],
			'[::1]'     => [ 'http://[::1]:3000/cb' ],
		];
	}

	public function test_validate_document_auth_method_none_forms_are_accepted() {
		foreach ( [
			[ 'token_endpoint_auth_method' => 'none' ],
			[ 'token_endpoint_auth_methods_supported' => [ 'none' ] ],
			[ 'token_endpoint_auth_methods_supported' => [ 'none', 'private_key_jwt' ] ],
			[
				'token_endpoint_auth_method'            => 'none',
				'token_endpoint_auth_methods_supported' => [ 'none' ],
			],
		] as $fields ) {
			$result = validate_document( $this->document( $fields ), static::URL );
			$this->assertIsArray( $result, wp_json_encode( $fields ) );
			$this->assertSame( 'none', $result['token_endpoint_auth_method'] );
		}
	}

	public function test_validate_document_rejects_singular_not_in_plural() {
		$result = validate_document(
			$this->document(
				[
					'token_endpoint_auth_method'            => 'none',
					'token_endpoint_auth_methods_supported' => [ 'private_key_jwt' ],
				]
			),
			static::URL
		);

		$this->assertCimdError( 'oauth2.cimd.invalid_document', 400, $result, false );
	}

	/**
	 * @dataProvider shared_secret_method_provider
	 *
	 * @param string $method Shared-secret method.
	 */
	public function test_validate_document_rejects_shared_secret_methods( $method ) {
		$singular = validate_document( $this->document( [ 'token_endpoint_auth_method' => $method ] ), static::URL );
		$plural   = validate_document( $this->document( [ 'token_endpoint_auth_methods_supported' => [ 'none', $method ] ] ), static::URL );

		$this->assertCimdError( 'oauth2.cimd.invalid_document', 400, $singular, false );
		$this->assertCimdError( 'oauth2.cimd.invalid_document', 400, $plural, false );
	}

	public function shared_secret_method_provider() {
		return [
			'basic' => [ 'client_secret_basic' ],
			'post'  => [ 'client_secret_post' ],
			'jwt'   => [ 'client_secret_jwt' ],
		];
	}

	public function test_validate_document_requires_none_method() {
		$singular = validate_document( $this->document( [ 'token_endpoint_auth_method' => 'private_key_jwt' ] ), static::URL );
		$plural   = validate_document( $this->document( [ 'token_endpoint_auth_methods_supported' => [ 'private_key_jwt' ] ] ), static::URL );
		$empty    = validate_document( $this->document( [ 'token_endpoint_auth_methods_supported' => [] ] ), static::URL );

		$this->assertCimdError( 'oauth2.cimd.unsupported_auth_method', 400, $singular, false );
		$this->assertCimdError( 'oauth2.cimd.unsupported_auth_method', 400, $plural, false );
		$this->assertCimdError( 'oauth2.cimd.unsupported_auth_method', 400, $empty, false );
	}

	public function test_validate_document_rejects_jwks_and_jwks_uri_together() {
		$result = validate_document(
			$this->document(
				[
					'jwks'     => [ 'keys' => [] ],
					'jwks_uri' => 'https://client.example.com/jwks.json',
				]
			),
			static::URL
		);

		$this->assertCimdError( 'oauth2.cimd.invalid_document', 400, $result, false );
	}

	public function test_validate_document_accepts_public_jwks() {
		$result = validate_document(
			$this->document( [ 'jwks' => [ 'keys' => [ [ 'kty' => 'RSA', 'n' => 'abc', 'e' => 'AQAB' ] ] ] ] ),
			static::URL
		);

		$this->assertIsArray( $result );
	}

	public function test_validate_document_rejects_private_jwks_member() {
		$result = validate_document(
			$this->document(
				[
					'jwks' => [
						'keys' => [
							[ 'kty' => 'RSA', 'n' => 'abc', 'e' => 'AQAB' ],
							[ 'kty' => 'RSA', 'n' => 'abc', 'e' => 'AQAB', 'd' => 'secret' ],
						],
					],
				]
			),
			static::URL
		);

		$this->assertCimdError( 'oauth2.cimd.invalid_document', 400, $result, false );
	}

	public function test_validate_document_rejects_bad_or_empty_grant_types() {
		foreach ( [ 'authorization_code', [ 5 ], [], [ 'implicit' ], [ 'client_credentials', 'refresh_token' ] ] as $grant_types ) {
			$result = validate_document( $this->document( [ 'grant_types' => $grant_types ] ), static::URL );
			$this->assertCimdError( 'oauth2.cimd.invalid_document', 400, $result, false );
		}
	}

	public function test_validate_document_rejects_bad_or_empty_response_types() {
		foreach ( [ 'code', [ 5 ], [], [ 'token' ], [ 'id_token', 'code id_token' ] ] as $response_types ) {
			$result = validate_document( $this->document( [ 'response_types' => $response_types ] ), static::URL );
			$this->assertCimdError( 'oauth2.cimd.invalid_document', 400, $result, false );
		}
	}

	public function test_validate_document_name_falls_back_to_host() {
		foreach ( [ null, '', '   ', '<script></script>', 42, [ 'x' ] ] as $name ) {
			$result = validate_document( $this->document( [ 'client_name' => $name ] ), static::URL );
			$this->assertSame( 'client.example.com', $result['client_name'] );
		}

		$document = $this->document();
		unset( $document['client_name'] );
		$this->assertSame( 'client.example.com', validate_document( $document, static::URL )['client_name'] );
	}

	public function test_validate_document_name_is_cut_to_200_characters() {
		$result = validate_document( $this->document( [ 'client_name' => str_repeat( 'é', 250 ) ] ), static::URL );

		$this->assertSame( 200, mb_strlen( $result['client_name'], 'UTF-8' ) );
	}
}
