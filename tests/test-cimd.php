<?php
/**
 * Tests for OAuth Client ID Metadata Document support.
 *
 * @package WP\OAuth2\Tests
 */

namespace WP\OAuth2\Tests;

require_once __DIR__ . '/class-test-case.php';

use WP_Error;
use WpOrg\Requests\Capability;
use WpOrg\Requests\Exception as RequestsException;
use WpOrg\Requests\Requests;
use WpOrg\Requests\Transport\Fsockopen;

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
	 * @param bool           $pin      Whether to fire http_api_curl before returning.
	 */
	protected function mock_http( $response, $pin = true ) {
		remove_all_filters( 'pre_http_request' );
		add_filter(
			'pre_http_request',
			function ( $pre, $args, $url ) use ( $response, $pin ) {
				$this->request_args = $args;
				++$this->request_count;
				if ( $pin ) {
					$this->fire_pin( $url );
				}
				return $response;
			},
			10,
			3
		);
	}

	/**
	 * Fire http_api_curl as the curl transport would, with a real handle.
	 *
	 * @param string $url Request URL.
	 */
	protected function fire_pin( $url ) {
		$handle = curl_init();
		do_action_ref_array( 'http_api_curl', [ &$handle, [], $url ] );
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
		$this->assertTrue( validate_client_id_url( 'https://client.example.com:8080/a/b' ) );
		$this->assertTrue( validate_client_id_url( 'https://client.example.com:443/a/b' ) );
		$this->assertTrue( validate_client_id_url( 'https://Client-1.Example.com/a/b' ) );
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
			'percent-encoded host' => [ 'https://a%2eexample.com/id' ],
			'idn host'            => [ 'https://bücher.example/id' ],
			'ipv6 literal'        => [ 'https://[::1]/id' ],
			'ipv4 literal'        => [ 'https://1.2.3.4/id' ],
			'hex host'            => [ 'https://0x7f000001/id' ],
			'decimal host'        => [ 'https://2130706433/id' ],
			'octal host'          => [ 'https://0177.0.0.1/id' ],
			'short ipv4 host'     => [ 'https://127.1/id' ],
			'numeric last label'  => [ 'https://client.example.com.1/id' ],
			'trailing dot host'   => [ 'https://client.example.com./id' ],
			'underscore host'     => [ 'https://a_b.example.com/id' ],
			'disallowed port'     => [ 'https://client.example.com:8443/id' ],
			'ssh port'            => [ 'https://client.example.com:22/id' ],
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

	public function test_validate_client_id_url_port_allowlist_is_filterable() {
		$seen = [];
		add_filter(
			'http_allowed_safe_ports',
			function ( $ports, $host, $url ) use ( &$seen ) {
				$seen = [ $ports, $host, $url ];
				return [ 443, 8443 ];
			},
			10,
			3
		);

		$this->assertTrue( validate_client_id_url( 'https://client.example.com:8443/id' ) );
		$this->assertSame( [ 80, 443, 8080 ], $seen[0] );
		$this->assertSame( 'client.example.com', $seen[1] );
		$this->assertSame( 'https://client.example.com:8443/id', $seen[2] );
		$this->assertCimdError( 'oauth2.cimd.invalid_client_id', 400, validate_client_id_url( 'https://client.example.com:8080/id' ) );

		remove_all_filters( 'http_allowed_safe_ports' );
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
			'::/96'            => [ '::808:808' ],
			'fec0::/10'        => [ 'fec0::1' ],
			'3fff::/20'        => [ '3fff::1' ],
			'3fff::/20 end'    => [ '3fff:0fff:ffff::1' ],
			'5f00::/16'        => [ '5f00::1' ],
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
			'just outside 3fff'  => [ '3fff:1000::1' ],
			'just outside 5f00'  => [ '5f01::1' ],
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

	/**
	 * @dataProvider transient_status_provider
	 *
	 * @param int $code Status code from the document server.
	 */
	public function test_fetch_document_server_errors_are_transient( $code ) {
		$this->mock_dns();
		$this->mock_http( $this->http_response( '', [], $code ) );

		$this->assertCimdError( 'oauth2.cimd.fetch_failed', 503, fetch_document( static::URL ), true );
	}

	public function transient_status_provider() {
		return [
			'429' => [ 429 ],
			'500' => [ 500 ],
			'502' => [ 502 ],
			'503' => [ 503 ],
			'599' => [ 599 ],
		];
	}

	/**
	 * @dataProvider terminal_status_provider
	 *
	 * @param int $code Status code from the document server.
	 */
	public function test_fetch_document_other_statuses_are_terminal( $code ) {
		$this->mock_dns();
		$this->mock_http( $this->http_response( '{"a":1}', [], $code ) );

		$this->assertCimdError( 'oauth2.cimd.fetch_failed', 400, fetch_document( static::URL ), false );
	}

	public function terminal_status_provider() {
		return [
			'201' => [ 201 ],
			'301' => [ 301 ],
			'400' => [ 400 ],
			'401' => [ 401 ],
			'403' => [ 403 ],
			'410' => [ 410 ],
			'499' => [ 499 ],
		];
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
		$this->assertFalse( $this->request_args['reject_unsafe_urls'] );
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
			function ( $pre, $args, $url ) use ( &$during ) {
				global $wp_filter;
				$during = array_keys( $wp_filter['http_api_curl']->callbacks );
				$this->fire_pin( $url );
				return $this->http_response( '{"a":1}' );
			},
			10,
			3
		);

		$this->assertFalse( has_action( 'http_api_curl' ) );
		$this->assertIsArray( fetch_document( static::URL ) );
		$this->assertSame( [ PHP_INT_MAX ], $during );
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

	/**
	 * Fetch while capturing the pin callback that is registered for the request.
	 *
	 * @return callable
	 */
	protected function capture_pin() {
		$pin = null;
		$this->mock_dns( [ '2606:2800:220:1::1' ] );
		add_filter(
			'pre_http_request',
			function () use ( &$pin ) {
				global $wp_filter;
				$pin = array_values( $wp_filter['http_api_curl']->callbacks[ PHP_INT_MAX ] )[0]['function'];
				return $this->http_response( '{"a":1}' );
			}
		);

		fetch_document( static::URL );
		$this->assertIsCallable( $pin );

		return $pin;
	}

	public function test_pin_callback_accepts_the_request_url() {
		$pin    = $this->capture_pin();
		$handle = curl_init();

		$this->assertNull( $pin( $handle, [], static::URL ) );
	}

	public function test_pin_callback_throws_when_it_runs_a_second_time() {
		$pin    = $this->capture_pin();
		$handle = curl_init();

		$this->assertNull( $pin( $handle, [], static::URL ) );

		$this->expectException( RequestsException::class );
		$pin( $handle, [], static::URL );
	}

	public function test_fetch_document_maps_a_second_pin_call_to_unsafe_transport() {
		$this->mock_dns();
		add_filter(
			'pre_http_request',
			function ( $pre, $args, $url ) {
				$this->fire_pin( $url );
				try {
					$this->fire_pin( $url );
				} catch ( RequestsException $e ) {
					return new WP_Error( 'http_request_failed', $e->getMessage() );
				}

				return $this->http_response( '{"a":1}' );
			},
			10,
			3
		);

		$this->assertCimdError( 'oauth2.cimd.unsafe_transport', 500, fetch_document( static::URL ), false );
		$this->assertFalse( has_action( 'http_api_curl' ) );
	}

	public function test_pin_callback_throws_for_another_url() {
		$pin    = $this->capture_pin();
		$handle = curl_init();

		$this->expectException( RequestsException::class );
		$pin( $handle, [], 'https://other.example.com/id' );
	}

	public function test_fetch_document_discards_a_response_when_the_pin_never_ran() {
		$this->mock_dns();
		$this->mock_http( $this->http_response( '{"client_id":"x"}' ), false );

		$this->assertCimdError( 'oauth2.cimd.unsafe_transport', 500, fetch_document( static::URL ), false );
		$this->assertSame( 1, $this->request_count );
	}

	public function test_fetch_document_maps_a_pin_failure_to_unsafe_transport() {
		$this->mock_dns();
		add_filter(
			'pre_http_request',
			function () {
				$handle = curl_init();
				try {
					do_action_ref_array( 'http_api_curl', [ &$handle, [], 'https://other.example.com/id' ] );
				} catch ( RequestsException $e ) {
					return new WP_Error( 'http_request_failed', $e->getMessage() );
				}

				return $this->http_response( '{"a":1}' );
			}
		);

		$this->assertCimdError( 'oauth2.cimd.unsafe_transport', 500, fetch_document( static::URL ), false );
		$this->assertFalse( has_action( 'http_api_curl' ) );
	}

	public function test_fetch_document_fails_closed_without_the_curl_transport() {
		$this->mock_dns();
		$this->mock_http( $this->http_response( '{"a":1}' ) );

		$key = serialize( [ Capability::SSL => true ] );
		Requests::has_capabilities( [ Capability::SSL => true ] );
		$original = Requests::$transport[ $key ];

		Requests::$transport[ $key ] = Fsockopen::class;
		try {
			$result = fetch_document( static::URL );
		} finally {
			Requests::$transport[ $key ] = $original;
		}

		$this->assertCimdError( 'oauth2.cimd.unsafe_transport', 500, $result, false );
		$this->assertSame( 0, $this->request_count );
	}

	public function test_fetch_document_fails_closed_when_no_transport_is_available() {
		$this->mock_dns();
		$this->mock_http( $this->http_response( '{"a":1}' ) );

		$key = serialize( [ Capability::SSL => true ] );
		Requests::has_capabilities( [ Capability::SSL => true ] );
		$original = Requests::$transport[ $key ];

		Requests::$transport[ $key ] = '';
		try {
			$result = fetch_document( static::URL );
		} finally {
			Requests::$transport[ $key ] = $original;
		}

		$this->assertCimdError( 'oauth2.cimd.unsafe_transport', 500, $result, false );
	}

	public function test_fetch_document_uses_curl_transport_in_this_environment() {
		$this->mock_dns();
		$this->mock_http( $this->http_response( '{"a":1}' ) );

		$this->assertIsArray( fetch_document( static::URL ) );
	}

	// validate_document().

	public function test_validate_document_happy_path_is_normalised() {
		$result = validate_document(
			$this->document(
				[
					'client_name'                => '  <b>Example</b> Client ',
					'redirect_uris'              => [
						'https://client.example.com/callback',
						'http://localhost:8080/cb',
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
			'object'             => [ [ 'named' => 'https://client.example.com/callback' ] ],
			'null'               => [ null ],
			'number'             => [ 5 ],
			'sparse list'        => [ [ 1 => 'https://client.example.com/callback' ] ],
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
			'[::1]:8080' => [ 'http://[::1]:8080/cb' ],
			'LOCALHOST' => [ 'http://LOCALHOST/cb' ],
			'expanded ::1' => [ 'http://[0:0:0:0:0:0:0:1]/cb' ],
			'127.8.9.10' => [ 'http://127.8.9.10/cb' ],
			'127.255.255.255' => [ 'http://127.255.255.255/cb' ],
		];
	}

	/**
	 * @dataProvider non_loopback_http_redirect_provider
	 *
	 * @param string $redirect_uri Non-loopback http redirect URI.
	 */
	public function test_validate_document_rejects_http_redirects_outside_loopback( $redirect_uri ) {
		$result = validate_document( $this->document( [ 'redirect_uris' => [ $redirect_uri ] ] ), static::URL );

		$this->assertCimdError( 'oauth2.cimd.invalid_document', 400, $result, false );
	}

	public function non_loopback_http_redirect_provider() {
		return [
			'126.255.255.255' => [ 'http://126.255.255.255/cb' ],
			'128.0.0.1'       => [ 'http://128.0.0.1/cb' ],
			'127.1 shorthand' => [ 'http://127.1/cb' ],
			'::2'             => [ 'http://[::2]/cb' ],
			'0.0.0.0'         => [ 'http://0.0.0.0/cb' ],
			'[::]'            => [ 'http://[::]/cb' ],
			'[::ffff:127.0.0.1]' => [ 'http://[::ffff:127.0.0.1]/cb' ],
			'localhost suffix' => [ 'http://localhost.example.com/cb' ],
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

	/**
	 * Fields whose wrong types must be rejected rather than defaulted.
	 *
	 * @dataProvider wrongly_typed_field_provider
	 *
	 * @param string $field Document field.
	 * @param mixed  $value Wrongly typed value.
	 * @param array  $extra Other fields to set.
	 */
	public function test_validate_document_rejects_wrongly_typed_fields( $field, $value, array $extra = [] ) {
		$result = validate_document( $this->document( array_merge( $extra, [ $field => $value ] ) ), static::URL );

		$this->assertCimdError( 'oauth2.cimd.invalid_document', 400, $result, false );
	}

	public function wrongly_typed_field_provider() {
		$cases = [
			'singular array'                  => [ 'token_endpoint_auth_method', [ 'client_secret_basic' ] ],
			'singular null'                   => [ 'token_endpoint_auth_method', null ],
			'singular number'                 => [ 'token_endpoint_auth_method', 5 ],
			'plural string'                   => [ 'token_endpoint_auth_methods_supported', 'client_secret_post' ],
			'plural with non-string'          => [ 'token_endpoint_auth_methods_supported', [ 1 ], [ 'token_endpoint_auth_method' => 'none' ] ],
			'plural with non-string and none' => [ 'token_endpoint_auth_methods_supported', [ 'none', 1 ] ],
		];

		foreach ( [ 'token_endpoint_auth_methods_supported', 'grant_types', 'response_types' ] as $field ) {
			$cases[ $field . ' null' ]   = [ $field, null ];
			$cases[ $field . ' scalar' ] = [ $field, 'none' ];
			$cases[ $field . ' number' ] = [ $field, 5 ];
			$cases[ $field . ' bool' ]   = [ $field, true ];
			$cases[ $field . ' object' ] = [ $field, [ 'named' => 'none' ] ];
			$cases[ $field . ' sparse' ] = [ $field, [ 1 => 'none' ] ];
			$cases[ $field . ' nested' ] = [ $field, [ [ 'none' ] ] ];
		}

		return $cases;
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

	/**
	 * @dataProvider invalid_jwks_provider
	 *
	 * @param mixed $jwks Invalid jwks value.
	 */
	public function test_validate_document_rejects_invalid_jwks( $jwks ) {
		$result = validate_document( $this->document( [ 'jwks' => $jwks ] ), static::URL );

		$this->assertCimdError( 'oauth2.cimd.invalid_document', 400, $result, false );
	}

	public function invalid_jwks_provider() {
		$public = [
			'kty' => 'RSA',
			'n'   => 'abc',
			'e'   => 'AQAB',
		];

		return [
			'null'               => [ null ],
			'string'             => [ 'keys' ],
			'list'               => [ [ $public ] ],
			'empty object'       => [ [] ],
			'no keys'            => [ [ 'other' => 1 ] ],
			'keys null'          => [ [ 'keys' => null ] ],
			'keys object'        => [ [ 'keys' => [ 'a' => $public ] ] ],
			'keys string'        => [ [ 'keys' => 'x' ] ],
			'key not an object'  => [ [ 'keys' => [ 'x' ] ] ],
			'key is a list'      => [ [ 'keys' => [ [ 'RSA' ] ] ] ],
			'private d'          => [ [ 'keys' => [ array_merge( $public, [ 'd' => 'x' ] ) ] ] ],
			'private p'          => [ [ 'keys' => [ array_merge( $public, [ 'p' => 'x' ] ) ] ] ],
			'private q'          => [ [ 'keys' => [ array_merge( $public, [ 'q' => 'x' ] ) ] ] ],
			'private dp'         => [ [ 'keys' => [ array_merge( $public, [ 'dp' => 'x' ] ) ] ] ],
			'private dq'         => [ [ 'keys' => [ array_merge( $public, [ 'dq' => 'x' ] ) ] ] ],
			'private qi'         => [ [ 'keys' => [ array_merge( $public, [ 'qi' => 'x' ] ) ] ] ],
			'symmetric k'        => [ [ 'keys' => [ [ 'kty' => 'oct', 'k' => 'c2VjcmV0' ] ] ] ],
			'oct without k'      => [ [ 'keys' => [ [ 'kty' => 'oct' ] ] ] ],
		];
	}

	/**
	 * @dataProvider invalid_jwks_uri_provider
	 *
	 * @param mixed $jwks_uri Invalid jwks_uri value.
	 */
	public function test_validate_document_rejects_invalid_jwks_uri( $jwks_uri ) {
		$result = validate_document( $this->document( [ 'jwks_uri' => $jwks_uri ] ), static::URL );

		$this->assertCimdError( 'oauth2.cimd.invalid_document', 400, $result, false );
	}

	public function invalid_jwks_uri_provider() {
		return [
			'null'   => [ null ],
			'array'  => [ [ 'https://client.example.com/jwks.json' ] ],
			'http'   => [ 'http://client.example.com/jwks.json' ],
			'relative' => [ '/jwks.json' ],
			'no host' => [ 'https://' ],
			'empty host' => [ 'https:///x' ],
			'port only' => [ 'https://:443/' ],
			'uppercase scheme' => [ 'HTTPS://client.example.com/jwks.json' ],
		];
	}

	public function test_validate_document_accepts_https_jwks_uri() {
		$result = validate_document( $this->document( [ 'jwks_uri' => 'https://client.example.com/jwks.json' ] ), static::URL );

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

	/**
	 * Defines the proxy constants, so it runs in its own process.
	 *
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_fetch_document_fails_closed_when_the_request_would_use_a_proxy() {
		define( 'WP_PROXY_HOST', 'proxy.example.net' );
		define( 'WP_PROXY_PORT', '3128' );

		$this->mock_dns();
		$this->mock_http( $this->http_response( '{"a":1}' ) );

		$this->assertCimdError( 'oauth2.cimd.unsafe_transport', 500, fetch_document( static::URL ), false );
		$this->assertSame( 0, $this->request_count );
	}

	/**
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_fetch_document_allows_a_request_that_bypasses_the_configured_proxy() {
		define( 'WP_PROXY_HOST', 'proxy.example.net' );
		define( 'WP_PROXY_PORT', '3128' );
		add_filter( 'pre_http_send_through_proxy', '__return_false' );

		$this->mock_dns();
		$this->mock_http( $this->http_response( '{"a":1}' ) );

		$this->assertIsArray( fetch_document( static::URL ) );
		remove_all_filters( 'pre_http_send_through_proxy' );
	}
}
