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

/**
 * Exposes the protected methods under test without going through
 * $_GET/$_POST/exit, so they can be driven with plain arrays.
 */
class Test_Exposed_Authorization_Code_Type extends Authorization_Code {
	public function gather_extra_params_public( Client $client, array $request ) {
		return $this->gather_extra_params( $client, $request );
	}

	public function get_error_redirect_url_public( $redirect_uri, $error, $description, $state = null ) {
		return $this->get_error_redirect_url( $redirect_uri, $error, $description, $state );
	}
}

/**
 * Exposes the protected methods under test for the implicit grant.
 */
class Test_Exposed_Implicit_Type extends Implicit {
	public function gather_extra_params_public( Client $client, array $request ) {
		return $this->gather_extra_params( $client, $request );
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
		$this->assertSame( [], $this->type->gather_extra_params_public( $this->client, [] ) );
	}

	public function test_valid_s256_challenge_returns_both_keys() {
		$pair   = $this->make_pkce_pair( PKCE::METHOD_S256 );
		$result = $this->type->gather_extra_params_public(
			$this->client,
			[
				'code_challenge'        => $pair['code_challenge'],
				'code_challenge_method' => 'S256',
			]
		);

		$this->assertSame( $pair['code_challenge'], $result['code_challenge'] );
		$this->assertSame( 'S256', $result['code_challenge_method'] );
	}

	public function test_unsupported_method_is_rejected() {
		$result = $this->type->gather_extra_params_public(
			$this->client,
			[
				'code_challenge'        => str_repeat( 'a', 43 ),
				'code_challenge_method' => 'md5',
			]
		);

		$this->assertWPError( $result );
		$this->assertSame( 'invalid_request', $result->get_error_data()['error'] );
	}

	public function test_wrongly_cased_method_is_rejected() {
		$result = $this->type->gather_extra_params_public(
			$this->client,
			[
				'code_challenge'        => str_repeat( 'a', 43 ),
				'code_challenge_method' => 's256',
			]
		);

		$this->assertWPError( $result );
	}

	public function test_malformed_challenge_is_rejected() {
		$result = $this->type->gather_extra_params_public(
			$this->client,
			[
				'code_challenge'        => 'too-short',
				'code_challenge_method' => 'S256',
			]
		);

		$this->assertWPError( $result );
	}

	public function test_method_without_challenge_is_ignored() {
		$result = $this->type->gather_extra_params_public(
			$this->client,
			[ 'code_challenge_method' => 'S256' ]
		);

		$this->assertSame( [], $result );
	}

	public function test_omitted_method_normalizes_to_plain() {
		$verifier = PKCE::generate_verifier();
		$result   = $this->type->gather_extra_params_public(
			$this->client,
			[ 'code_challenge' => $verifier ]
		);

		$this->assertSame( 'plain', $result['code_challenge_method'] );
	}

	public function test_array_valued_challenge_is_treated_as_absent() {
		$result = $this->type->gather_extra_params_public(
			$this->client,
			[ 'code_challenge' => [ 'x' ] ]
		);

		$this->assertSame( [], $result );
	}

	public function test_pkce_required_client_without_challenge_is_rejected() {
		$client = $this->create_client( [ 'pkce_required' => true ] );
		$result = $this->type->gather_extra_params_public( $client, [] );

		$this->assertWPError( $result );
		$this->assertEquals( 'oauth2.types.authorization_code.gather_extra_params.pkce_required', $result->get_error_code() );
	}

	public function test_pkce_required_client_with_plain_is_rejected() {
		$client   = $this->create_client( [ 'pkce_required' => true ] );
		$verifier = PKCE::generate_verifier();
		$result   = $this->type->gather_extra_params_public(
			$client,
			[
				'code_challenge'        => $verifier,
				'code_challenge_method' => 'plain',
			]
		);

		$this->assertWPError( $result );
		$this->assertEquals( 'oauth2.types.authorization_code.gather_extra_params.weak_method', $result->get_error_code() );
	}

	public function test_pkce_required_client_with_s256_is_accepted() {
		$client = $this->create_client( [ 'pkce_required' => true ] );
		$pair   = $this->make_pkce_pair( PKCE::METHOD_S256 );
		$result = $this->type->gather_extra_params_public(
			$client,
			[
				'code_challenge'        => $pair['code_challenge'],
				'code_challenge_method' => 'S256',
			]
		);

		$this->assertIsArray( $result );
	}

	public function test_error_redirect_url_uses_query_string() {
		$url = $this->type->get_error_redirect_url_public( 'https://example.com/callback', 'invalid_request', 'Bad request.' );
		$this->assertStringContainsString( 'https://example.com/callback?', $url );
		$this->assertStringContainsString( 'error=invalid_request', $url );
	}

	public function test_error_redirect_url_omits_state_when_absent() {
		$url = $this->type->get_error_redirect_url_public( 'https://example.com/callback', 'invalid_request', 'Bad request.' );
		$this->assertStringNotContainsString( 'state=', $url );
	}

	public function test_error_redirect_url_includes_state_when_present() {
		$url = $this->type->get_error_redirect_url_public( 'https://example.com/callback', 'invalid_request', 'Bad request.', 'xyz' );
		$this->assertStringContainsString( 'state=xyz', $url );
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
		$this->assertSame( [], $this->type->gather_extra_params_public( $this->client, [] ) );
	}

	public function test_pkce_required_client_is_refused() {
		$client = $this->create_client( [ 'pkce_required' => true ] );
		$result = $this->type->gather_extra_params_public( $client, [] );

		$this->assertWPError( $result );
		$this->assertEquals( 'oauth2.types.implicit.gather_extra_params.pkce_required', $result->get_error_code() );
	}

	public function test_error_redirect_url_uses_fragment() {
		$url = $this->type->get_error_redirect_url_public( 'https://example.com/callback', 'unauthorized_client', 'Nope.' );
		$this->assertStringContainsString( '#', $url );
		$this->assertStringContainsString( 'error=unauthorized_client', $url );
	}
}
