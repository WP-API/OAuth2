<?php
/**
 * Helpers for tests that mock client ID metadata document fetches.
 *
 * @package WP\OAuth2\Tests
 */

namespace WP\OAuth2\Tests;

use WP_Error;

use function WP\OAuth2\CIMD\set_host_resolver;

/**
 * Mocks DNS and HTTP for fetches of a client ID metadata document.
 *
 * Classes using it define the URL constant of the document they serve.
 */
trait CIMD_Test_Helpers {

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

	/**
	 * Remove the mocks. Call from tear_down().
	 */
	protected function reset_cimd_mocks() {
		remove_all_filters( 'pre_http_request' );
		remove_all_filters( 'oauth2.cimd.admit_url' );
		remove_all_filters( 'oauth2.cimd.auto_approve' );
		remove_all_filters( 'oauth2.cimd.rate_limit' );
		set_host_resolver( null );
		remove_all_actions( 'http_api_curl' );
		remove_all_actions( 'requests-curl.before_send' );
		$this->request_args  = null;
		$this->request_count = 0;
	}

	/**
	 * Mock DNS so that the host resolves to the given addresses.
	 *
	 * @param string[] $ips Addresses to return.
	 */
	protected function mock_dns( array $ips = [ '93.184.216.34' ] ) {
		set_host_resolver(
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
	 * Fire http_api_curl and then requests-curl.before_send as the curl transport would, with a real handle.
	 *
	 * @param string $url Request URL.
	 */
	protected function fire_pin( $url ) {
		$handle = curl_init();
		do_action_ref_array( 'http_api_curl', [ &$handle, [], $url ] );
		do_action_ref_array( 'requests-curl.before_send', [ &$handle ] );
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
}
