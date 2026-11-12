<?php
/**
 * Tests for PKCE handling in the authorization_code and implicit grant types.
 *
 * @package WP\OAuth2\Tests
 */

namespace WP\OAuth2\Tests;

require_once __DIR__ . '/class-test-case.php';

use WP\OAuth2\Client;
use WP\OAuth2\PKCE;
use WP\OAuth2\Types\Authorization_Code;
use WP\OAuth2\Types\Implicit;

use function WP\OAuth2\Well_Known\get_authorization_server_metadata;
use function WP\OAuth2\Well_Known\get_metadata_for_site;
use function WP\OAuth2\Well_Known\get_protected_resource_metadata;

/**
 * Thrown from a 'wp_redirect' filter to capture the final redirect location
 * and escape before the real exit(), without swallowing any other exception
 * a bug elsewhere in the request might throw.
 */
class Redirect_Interrupt extends \RuntimeException {}

/**
 * Exposes the protected methods under test without going through
 * $_GET/$_POST/exit, so they can be driven with plain arrays.
 */
class Test_Exposed_Authorization_Code_Type extends Authorization_Code {
	public function validate_extra_params_public( Client $client, array $request ) {
		return $this->validate_extra_params( $client, $request );
	}

	public function get_error_redirect_url_public( $redirect_uri, $error, $description, $state = null ) {
		return $this->get_error_redirect_url( $redirect_uri, $error, $description, $state );
	}
}

/**
 * Exposes the protected methods under test for the implicit grant.
 */
class Test_Exposed_Implicit_Type extends Implicit {
	public function validate_extra_params_public( Client $client, array $request ) {
		return $this->validate_extra_params( $client, $request );
	}

	public function get_error_redirect_url_public( $redirect_uri, $error, $description, $state = null ) {
		return $this->get_error_redirect_url( $redirect_uri, $error, $description, $state );
	}
}

/**
 * Test cases for PKCE parameter handling in the authorization_code grant.
 */
class Test_Types_Authorization_Code extends Test_Case {

	/**
	 * @var Client
	 */
	protected $client;

	/**
	 * @var Test_Exposed_Authorization_Code_Type
	 */
	protected $type;

	public function set_up() {
		parent::set_up();
		$this->client = $this->create_client();
		$this->type   = new Test_Exposed_Authorization_Code_Type();
	}

	public function test_no_challenge_returns_empty_array() {
		$this->assertSame( [], $this->type->validate_extra_params_public( $this->client, [] ) );
	}

	/**
	 * RFC 7636 section 4.4: the server stores the challenge and method with the authorization code.
	 *
	 * @link https://datatracker.ietf.org/doc/html/rfc7636#section-4.4
	 */
	public function test_valid_s256_challenge_returns_both_keys() {
		$pair   = $this->make_pkce_pair( PKCE::METHOD_S256 );
		$result = $this->type->validate_extra_params_public(
			$this->client,
			[
				'code_challenge'        => $pair['code_challenge'],
				'code_challenge_method' => 'S256',
			]
		);

		$this->assertSame( $pair['code_challenge'], $result['code_challenge'] );
		$this->assertSame( 'S256', $result['code_challenge_method'] );
	}

	/**
	 * RFC 7636 section 4.4.1: an unsupported transform method gets an invalid_request error.
	 *
	 * @link https://datatracker.ietf.org/doc/html/rfc7636#section-4.4.1
	 */
	public function test_unsupported_method_is_rejected() {
		$result = $this->type->validate_extra_params_public(
			$this->client,
			[
				'code_challenge'        => str_repeat( 'a', 43 ),
				'code_challenge_method' => 'md5',
			]
		);

		$this->assertWPError( $result );
		$this->assertSame( 'invalid_request', $result->get_error_data()['error'] );
	}

	/**
	 * RFC 7636 section 4.4.1: an unsupported transform method gets an invalid_request error.
	 *
	 * @link https://datatracker.ietf.org/doc/html/rfc7636#section-4.4.1
	 */
	public function test_plain_is_unsupported_when_allow_plain_is_false() {
		add_filter( 'oauth2.pkce.allow_plain', '__return_false' );

		$result = $this->type->validate_extra_params_public(
			$this->client,
			[
				'code_challenge'        => PKCE::generate_verifier(),
				'code_challenge_method' => 'plain',
			]
		);

		remove_filter( 'oauth2.pkce.allow_plain', '__return_false' );

		$this->assertWPError( $result );
		$this->assertEquals( 'oauth2.types.authorization_code.validate_extra_params.unsupported_method', $result->get_error_code() );
		$this->assertStringContainsString( 'S256', $result->get_error_message() );
		$this->assertStringNotContainsString( 'plain', $result->get_error_message() );
	}

	/**
	 * RFC 7636 section 4.3: an omitted method defaults to "plain", so it is refused when plain is not allowed.
	 *
	 * @link https://datatracker.ietf.org/doc/html/rfc7636#section-4.3
	 */
	public function test_omitted_method_is_unsupported_when_allow_plain_is_false() {
		add_filter( 'oauth2.pkce.allow_plain', '__return_false' );

		$result = $this->type->validate_extra_params_public(
			$this->client,
			[
				'code_challenge' => PKCE::generate_verifier(),
			]
		);

		remove_filter( 'oauth2.pkce.allow_plain', '__return_false' );

		$this->assertWPError( $result );
		$this->assertEquals( 'oauth2.types.authorization_code.validate_extra_params.unsupported_method', $result->get_error_code() );
	}

	/**
	 * RFC 7636 section 4.3: the method is "S256" or "plain", and defaults to "plain" when omitted.
	 *
	 * @link https://datatracker.ietf.org/doc/html/rfc7636#section-4.3
	 */
	public function test_wrongly_cased_method_is_rejected() {
		$result = $this->type->validate_extra_params_public(
			$this->client,
			[
				'code_challenge'        => str_repeat( 'a', 43 ),
				'code_challenge_method' => 's256',
			]
		);

		$this->assertWPError( $result );
	}

	/**
	 * RFC 6749 section 4.1.2.1: an invalid, repeated or malformed parameter gets an invalid_request redirect.
	 *
	 * @link https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
	 */
	public function test_malformed_challenge_is_rejected() {
		$result = $this->type->validate_extra_params_public(
			$this->client,
			[
				'code_challenge'        => 'too-short',
				'code_challenge_method' => 'S256',
			]
		);

		$this->assertWPError( $result );
	}

	/**
	 * RFC 6749 section 4.1.2.1: an invalid, repeated or malformed parameter gets an invalid_request redirect.
	 *
	 * @link https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
	 */
	public function test_method_without_challenge_is_rejected() {
		$result = $this->type->validate_extra_params_public(
			$this->client,
			[ 'code_challenge_method' => 'S256' ]
		);

		$this->assertWPError( $result );
		$this->assertSame( 'invalid_request', $result->get_error_data()['error'] );
	}

	/**
	 * RFC 7636 section 4.3: the method is "S256" or "plain", and defaults to "plain" when omitted.
	 *
	 * @link https://datatracker.ietf.org/doc/html/rfc7636#section-4.3
	 */
	public function test_omitted_method_normalizes_to_plain() {
		$verifier = PKCE::generate_verifier();
		$result   = $this->type->validate_extra_params_public(
			$this->client,
			[ 'code_challenge' => $verifier ]
		);

		$this->assertSame( 'plain', $result['code_challenge_method'] );
	}

	/**
	 * RFC 6749 section 4.1.2.1: an invalid, repeated or malformed parameter gets an invalid_request redirect.
	 *
	 * @link https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
	 */
	public function test_array_valued_challenge_is_rejected() {
		$result = $this->type->validate_extra_params_public(
			$this->client,
			[ 'code_challenge' => [ 'x' ] ]
		);

		$this->assertWPError( $result );
		$this->assertSame( 'invalid_request', $result->get_error_data()['error'] );
	}

	/**
	 * RFC 6749 section 4.1.2.1: an invalid, repeated or malformed parameter gets an invalid_request redirect.
	 *
	 * @link https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
	 */
	public function test_array_valued_method_is_rejected() {
		$result = $this->type->validate_extra_params_public(
			$this->client,
			[
				'code_challenge'        => str_repeat( 'a', 43 ),
				'code_challenge_method' => [ 'S256' ],
			]
		);

		$this->assertWPError( $result );
		$this->assertSame( 'invalid_request', $result->get_error_data()['error'] );
	}

	/**
	 * RFC 7636 section 4.4.1: a server that requires PKCE returns invalid_request when the challenge is missing.
	 *
	 * @link https://datatracker.ietf.org/doc/html/rfc7636#section-4.4.1
	 */
	public function test_pkce_required_client_without_challenge_is_rejected() {
		$client = $this->create_client( [ 'pkce_required' => true ] );
		$result = $this->type->validate_extra_params_public( $client, [] );

		$this->assertWPError( $result );
		$this->assertEquals( 'oauth2.types.authorization_code.check_pkce_requirement.pkce_required', $result->get_error_code() );
	}

	/**
	 * RFC 9700 section 2.1.1: S256 is the method to use, since plain does not protect the challenge.
	 *
	 * @link https://datatracker.ietf.org/doc/html/rfc9700#section-2.1.1
	 */
	public function test_pkce_required_client_with_plain_is_rejected() {
		$client   = $this->create_client( [ 'pkce_required' => true ] );
		$verifier = PKCE::generate_verifier();
		$result   = $this->type->validate_extra_params_public(
			$client,
			[
				'code_challenge'        => $verifier,
				'code_challenge_method' => 'plain',
			]
		);

		$this->assertWPError( $result );
		$this->assertEquals( 'oauth2.types.authorization_code.check_pkce_requirement.weak_method', $result->get_error_code() );
	}

	/**
	 * RFC 7636 section 4.3: the method is "S256" or "plain", and defaults to "plain" when omitted.
	 *
	 * @link https://datatracker.ietf.org/doc/html/rfc7636#section-4.3
	 */
	public function test_pkce_required_client_with_s256_is_accepted() {
		$client = $this->create_client( [ 'pkce_required' => true ] );
		$pair   = $this->make_pkce_pair( PKCE::METHOD_S256 );
		$result = $this->type->validate_extra_params_public(
			$client,
			[
				'code_challenge'        => $pair['code_challenge'],
				'code_challenge_method' => 'S256',
			]
		);

		$this->assertIsArray( $result );
	}

	/**
	 * RFC 6749 section 4.1.2.1: the error redirect goes to the client and carries the exact state it sent.
	 *
	 * @link https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
	 */
	public function test_error_redirect_url_uses_query_string() {
		$url = $this->type->get_error_redirect_url_public( 'https://example.com/callback', 'invalid_request', 'Bad request.' );
		$this->assertStringContainsString( 'https://example.com/callback?', $url );
		$this->assertStringContainsString( 'error=invalid_request', $url );
	}

	/**
	 * RFC 6749 section 4.1.2.1: the error redirect goes to the client and carries the exact state it sent.
	 *
	 * @link https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
	 */
	public function test_error_redirect_url_omits_state_when_absent() {
		$url = $this->type->get_error_redirect_url_public( 'https://example.com/callback', 'invalid_request', 'Bad request.' );
		$this->assertStringNotContainsString( 'state=', $url );
	}

	/**
	 * RFC 6749 section 4.1.2.1: the error redirect goes to the client and carries the exact state it sent.
	 *
	 * @link https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
	 */
	public function test_error_redirect_url_includes_state_when_present() {
		$url = $this->type->get_error_redirect_url_public( 'https://example.com/callback', 'invalid_request', 'Bad request.', 'xyz' );
		$this->assertStringContainsString( 'state=xyz', $url );
	}

	/**
	 * RFC 6749 section 4.1.2.1: the error redirect goes to the client and carries the exact state it sent.
	 *
	 * @link https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
	 */
	public function test_error_redirect_url_keeps_zero_state() {
		$url = $this->type->get_error_redirect_url_public( 'https://example.com/callback', 'invalid_request', 'Bad request.', '0' );
		$this->assertStringContainsString( 'state=0', $url );
	}

	/**
	 * Regression test: an authorize-time PKCE error must redirect to the
	 * client's registered callback, not silently fall back to wp-admin.
	 *
	 * wp_safe_redirect() rejects a callback on a host other than the current
	 * site (there is no allowed_redirect_hosts filter registered anywhere in
	 * this plugin) and substitutes admin_url() instead, so the client would
	 * never learn the request failed. wp_redirect() and wp_safe_redirect()
	 * both funnel through the 'wp_redirect' filter, so hooking it captures
	 * the final location actually sent, whichever function was used, and
	 * lets the test escape before handle_authorisation()'s exit.
	 *
	 * @link https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
	 */
	public function test_pkce_error_redirects_to_client_callback_not_wp_admin() {
		$client             = $this->create_client( [ 'pkce_required' => true ] );
		$_GET['client_id']  = $client->get_id();
		$captured_location = null;

		add_filter(
			'wp_redirect',
			function ( $location ) use ( &$captured_location ) {
				$captured_location = $location;
				throw new Redirect_Interrupt();
			}
		);

		try {
			( new Authorization_Code() )->handle_authorisation();
			$this->fail( 'Expected handle_authorisation() to redirect on a PKCE error.' );
		} catch ( Redirect_Interrupt $e ) {
			// Expected: escapes before the real exit(); see filter above.
		}

		unset( $_GET['client_id'] );

		$this->assertNotNull( $captured_location );
		$this->assertStringStartsWith( 'https://example.com/callback', $captured_location );
		$this->assertStringContainsString( 'error=invalid_request', $captured_location );
	}

	/**
	 * RFC 6749 section 4.1.2.1: with an invalid redirect URI, the server must not redirect.
	 *
	 * A PKCE error on a request whose redirect_uri is not registered must not
	 * send the user, or the error, to that URI.
	 *
	 * @link https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
	 */
	public function test_pkce_error_is_not_redirected_to_an_unregistered_uri() {
		$client = $this->create_client( [ 'pkce_required' => true ] );
		$_GET   = [
			'client_id'    => $client->get_id(),
			'redirect_uri' => 'https://attacker.example/callback',
		];
		add_filter( 'wp_redirect', function () {
			throw new Redirect_Interrupt();
		} );

		$result = ( new Authorization_Code() )->handle_authorisation();
		$_GET   = [];

		$this->assertWPError( $result );
		$this->assertSame( 'oauth2.types.authorization_code.handle_authorisation.invalid_redirect_uri', $result->get_error_code() );
	}

	/**
	 * RFC 7636 section 4.4: the server stores the challenge and method with the authorization code.
	 *
	 * Runs the whole consent flow, so the challenge has to survive from the
	 * authorize request, through the consent form post, into the minted code.
	 *
	 * @link https://datatracker.ietf.org/doc/html/rfc7636#section-4.4
	 */
	public function test_consent_flow_mints_a_code_bound_to_the_challenge() {
		$client = $this->create_client( [ 'pkce_required' => true ] );
		$pair   = $this->make_pkce_pair( PKCE::METHOD_S256 );
		wp_set_current_user( $this->factory->user->create() );

		$_GET  = [
			'client_id'             => $client->get_id(),
			'code_challenge'        => $pair['code_challenge'],
			'code_challenge_method' => 'S256',
		];
		$_POST = [
			'_wpnonce'  => wp_create_nonce( sprintf( 'oauth2_authorize:%s', $client->get_id() ) ),
			'wp-submit' => 'authorize',
		];

		$location = null;
		add_filter( 'wp_redirect', function ( $url ) use ( &$location ) {
			$location = $url;
			throw new Redirect_Interrupt();
		} );

		try {
			( new Authorization_Code() )->handle_authorisation();
			$this->fail( 'Expected a redirect back to the client.' );
		} catch ( Redirect_Interrupt $e ) {
			// Expected.
		} finally {
			$_GET  = [];
			$_POST = [];
		}

		parse_str( wp_parse_url( $location, PHP_URL_QUERY ), $args );
		$code = $client->get_authorization_code( $args['code'] );

		$this->assertSame( $pair['code_challenge'], $code->get_code_challenge() );
		$this->assertSame( 'S256', $code->get_code_challenge_method() );
	}

	/**
	 * Submit the consent form and capture the redirect back to the client.
	 *
	 * @param Client $client Client being authorised.
	 * @param string $submit Button pressed, `authorize` or `cancel`.
	 * @return string Redirect location.
	 */
	protected function submit_consent( Client $client, $submit ) {
		wp_set_current_user( $this->factory->user->create() );

		$_GET  = [
			'client_id' => $client->get_id(),
			'state'     => 'xyz',
		];
		$_POST = [
			'_wpnonce'  => wp_create_nonce( sprintf( 'oauth2_authorize:%s', $client->get_id() ) ),
			'wp-submit' => $submit,
		];

		$location = null;
		add_filter( 'wp_redirect', function ( $url ) use ( &$location ) {
			$location = $url;
			throw new Redirect_Interrupt();
		} );

		try {
			( new Authorization_Code() )->handle_authorisation();
			$this->fail( 'Expected a redirect back to the client.' );
		} catch ( Redirect_Interrupt $e ) {
			// Expected.
		} finally {
			$_GET  = [];
			$_POST = [];
		}

		return $location;
	}

	/**
	 * RFC 9207 section 2: a successful authorization response carries the issuer.
	 *
	 * @link https://datatracker.ietf.org/doc/html/rfc9207#section-2
	 */
	public function test_authorization_response_carries_the_issuer() {
		parse_str( wp_parse_url( $this->submit_consent( $this->client, 'authorize' ), PHP_URL_QUERY ), $args );

		$this->assertArrayHasKey( 'code', $args );
		$this->assertSame( 'xyz', $args['state'] );
		$this->assertSame( get_authorization_server_metadata()['issuer'], $args['iss'] );
	}

	/**
	 * RFC 9207 section 2: an error authorization response carries the issuer, including a cancelled request.
	 *
	 * @link https://datatracker.ietf.org/doc/html/rfc9207#section-2
	 */
	public function test_cancelled_response_carries_the_issuer() {
		parse_str( wp_parse_url( $this->submit_consent( $this->client, 'cancel' ), PHP_URL_QUERY ), $args );

		$this->assertSame( 'access_denied', $args['error'] );
		$this->assertSame( get_authorization_server_metadata()['issuer'], $args['iss'] );
	}

	/**
	 * RFC 9207 section 2: an error authorization response carries the issuer.
	 *
	 * @link https://datatracker.ietf.org/doc/html/rfc9207#section-2
	 */
	public function test_error_redirect_url_carries_the_issuer() {
		$url = $this->type->get_error_redirect_url_public( 'https://example.com/callback', 'invalid_request', 'Bad request.', 'xyz' );

		parse_str( wp_parse_url( $url, PHP_URL_QUERY ), $args );

		$this->assertSame( get_authorization_server_metadata()['issuer'], $args['iss'] );
		$this->assertSame( 'xyz', $args['state'] );
	}

	public function test_authorize_time_error_redirect_carries_the_issuer() {
		$client             = $this->create_client( [ 'pkce_required' => true ] );
		$_GET['client_id']  = $client->get_id();
		$captured_location = null;

		add_filter(
			'wp_redirect',
			function ( $location ) use ( &$captured_location ) {
				$captured_location = $location;
				throw new Redirect_Interrupt();
			}
		);

		try {
			( new Authorization_Code() )->handle_authorisation();
			$this->fail( 'Expected handle_authorisation() to redirect on a PKCE error.' );
		} catch ( Redirect_Interrupt $e ) {
			// Expected.
		} finally {
			$_GET = [];
		}

		parse_str( wp_parse_url( $captured_location, PHP_URL_QUERY ), $args );
		$this->assertSame( get_authorization_server_metadata()['issuer'], $args['iss'] );
	}

	public function test_redirect_args_filters_can_adjust_the_issuer() {
		add_filter( 'oauth2.redirect_args.authorized', function ( $args ) {
			$args['iss'] = 'https://issuer.example.com';
			return $args;
		} );

		parse_str( wp_parse_url( $this->submit_consent( $this->client, 'authorize' ), PHP_URL_QUERY ), $args );

		$this->assertSame( 'https://issuer.example.com', $args['iss'] );
	}

	public function test_the_metadata_filter_changes_the_issuer_of_the_response() {
		add_filter( 'oauth2.well_known_authorization_server_metadata', function ( $metadata ) {
			$metadata['issuer'] = 'https://metadata-issuer.example.com';
			return $metadata;
		} );

		parse_str( wp_parse_url( $this->submit_consent( $this->client, 'cancel' ), PHP_URL_QUERY ), $args );

		$this->assertSame( 'https://metadata-issuer.example.com', $args['iss'] );
	}

	public function test_the_metadata_filter_changes_the_metadata_the_protected_resource_and_the_response() {
		add_filter( 'oauth2.well_known_authorization_server_metadata', function ( $metadata ) {
			$metadata['issuer'] = 'https://issuer.example.com/custom';
			return $metadata;
		} );

		parse_str( wp_parse_url( $this->submit_consent( $this->client, 'cancel' ), PHP_URL_QUERY ), $args );

		$this->assertSame( 'https://issuer.example.com/custom', get_authorization_server_metadata()['issuer'] );
		$this->assertSame( [ 'https://issuer.example.com/custom' ], get_protected_resource_metadata()['authorization_servers'] );
		$this->assertSame( 'https://issuer.example.com/custom', $args['iss'] );
	}

	public function test_a_subsite_response_carries_the_issuer_of_that_subsite() {
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Requires a multisite install.' );
		}

		$site_id = $this->factory->blog->create( [ 'path' => '/blog/' ] );
		switch_to_blog( $site_id );
		try {
			$client   = $this->create_client();
			$location = $this->submit_consent( $client, 'authorize' );
		} finally {
			restore_current_blog();
		}

		parse_str( wp_parse_url( $location, PHP_URL_QUERY ), $args );

		$this->assertSame( get_metadata_for_site( $site_id )['issuer'], $args['iss'] );
		$this->assertSame( get_home_url( $site_id ), $args['iss'] );
		$this->assertNotSame( home_url(), $args['iss'] );
	}

	public function test_redirect_args_filter_sees_the_issuer() {
		$seen = null;
		add_filter( 'oauth2.redirect_args.cancelled', function ( $args ) use ( &$seen ) {
			$seen = $args['iss'] ?? null;
			return $args;
		} );

		$this->submit_consent( $this->client, 'cancel' );

		$this->assertSame( get_authorization_server_metadata()['issuer'], $seen );
	}
}

/**
 * Test cases for the implicit grant's PKCE-required bypass fix.
 */
class Test_Types_Implicit extends Test_Case {

	/**
	 * @var Client
	 */
	protected $client;

	/**
	 * @var Test_Exposed_Implicit_Type
	 */
	protected $type;

	public function set_up() {
		parent::set_up();
		$this->client = $this->create_client();
		$this->type   = new Test_Exposed_Implicit_Type();
	}

	public function test_non_pkce_client_is_allowed() {
		$this->assertSame( [], $this->type->validate_extra_params_public( $this->client, [] ) );
	}

	/**
	 * RFC 9700 section 2.1.2: the implicit grant cannot bind a code_challenge, so PKCE clients must use the code grant.
	 *
	 * @link https://datatracker.ietf.org/doc/html/rfc9700#section-2.1.2
	 */
	public function test_pkce_required_client_is_refused() {
		$client = $this->create_client( [ 'pkce_required' => true ] );
		$result = $this->type->validate_extra_params_public( $client, [] );

		$this->assertWPError( $result );
		$this->assertEquals( 'oauth2.types.implicit.validate_extra_params.pkce_required', $result->get_error_code() );
	}

	/**
	 * RFC 6749 section 4.2.2.1: implicit grant errors go in the redirect URI fragment.
	 *
	 * @link https://datatracker.ietf.org/doc/html/rfc6749#section-4.2.2.1
	 */
	public function test_error_redirect_url_uses_fragment() {
		$url = $this->type->get_error_redirect_url_public( 'https://example.com/callback', 'unauthorized_client', 'Nope.' );
		$this->assertStringContainsString( '#', $url );
		$this->assertStringContainsString( 'error=unauthorized_client', $url );
	}

	/**
	 * RFC 6749 section 4.2.2.1: implicit grant errors go in the redirect URI fragment.
	 *
	 * @link https://datatracker.ietf.org/doc/html/rfc6749#section-4.2.2.1
	 */
	public function test_error_redirect_url_encodes_fragment_values() {
		$url = $this->type->get_error_redirect_url_public( 'https://example.com/callback', 'unauthorized_client', 'A & B #c', 'x&y=z' );

		parse_str( wp_parse_url( $url, PHP_URL_FRAGMENT ), $args );
		$this->assertSame( 'A & B #c', $args['error_description'] );
		$this->assertSame( 'x&y=z', $args['state'] );
	}

	/**
	 * RFC 6749 section 4.2.2.1: implicit grant errors go in the redirect URI fragment, with the exact state.
	 *
	 * @link https://datatracker.ietf.org/doc/html/rfc6749#section-4.2.2.1
	 */
	public function test_error_redirect_url_keeps_zero_state() {
		$url = $this->type->get_error_redirect_url_public( 'https://example.com/callback', 'unauthorized_client', 'Nope.', '0' );
		$this->assertStringContainsString( 'state=0', $url );
	}

	/**
	 * RFC 9207 section 2: the issuer goes in the same fragment as the other response parameters.
	 *
	 * @link https://datatracker.ietf.org/doc/html/rfc9207#section-2
	 */
	public function test_error_redirect_url_carries_the_issuer_in_the_fragment() {
		$url = $this->type->get_error_redirect_url_public( 'https://example.com/callback', 'unauthorized_client', 'Nope.', 'xyz' );

		$this->assertStringNotContainsString( '?', $url );
		parse_str( wp_parse_url( $url, PHP_URL_FRAGMENT ), $args );
		$this->assertSame( get_authorization_server_metadata()['issuer'], $args['iss'] );
	}

	/**
	 * RFC 9207 section 2: the issuer goes in the same fragment as the other response parameters.
	 *
	 * @link https://datatracker.ietf.org/doc/html/rfc9207#section-2
	 */
	public function test_token_response_carries_the_issuer_in_the_fragment() {
		$client = $this->create_client( [ 'callback' => home_url( '/callback' ) ] );
		wp_set_current_user( $this->factory->user->create() );
		$_GET  = [
			'client_id' => $client->get_id(),
			'state'     => 'xyz',
		];
		$_POST = [
			'_wpnonce'  => wp_create_nonce( sprintf( 'oauth2_authorize:%s', $client->get_id() ) ),
			'wp-submit' => 'authorize',
		];

		$location = null;
		add_filter( 'wp_redirect', function ( $url ) use ( &$location ) {
			$location = $url;
			throw new Redirect_Interrupt();
		} );

		try {
			( new Implicit() )->handle_authorisation();
			$this->fail( 'Expected a redirect back to the client.' );
		} catch ( Redirect_Interrupt $e ) {
			// Expected.
		} finally {
			$_GET  = [];
			$_POST = [];
		}

		$this->assertStringNotContainsString( '?', $location );
		parse_str( wp_parse_url( $location, PHP_URL_FRAGMENT ), $args );
		$this->assertArrayHasKey( 'access_token', $args );
		$this->assertSame( get_authorization_server_metadata()['issuer'], $args['iss'] );
	}
}
