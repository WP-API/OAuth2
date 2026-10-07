<?php
/**
 * Tests that the OAuth state parameter is returned to the client unchanged.
 *
 * @package WP\OAuth2\Tests
 */

namespace WP\OAuth2\Tests;

require_once __DIR__ . '/class-test-case.php';

use WP\OAuth2\Client;
use WP\OAuth2\Types\Authorization_Code;
use WP\OAuth2\Types\Base;
use WP\OAuth2\Types\Implicit;

/**
 * Thrown from a 'wp_redirect' filter to capture the redirect location before exit().
 */
class State_Redirect_Interrupt extends \RuntimeException {}

/**
 * Test cases for state round-tripping in the authorize flow.
 */
class Test_State extends Test_Case {

	public function set_up() {
		parent::set_up();
		wp_set_current_user( self::factory()->user->create() );
		add_filter( 'wp_redirect', [ $this, 'interrupt_redirect' ] );
	}

	public function tear_down() {
		remove_filter( 'wp_redirect', [ $this, 'interrupt_redirect' ] );
		$_GET  = [];
		$_POST = [];
		parent::tear_down();
	}

	public function interrupt_redirect( $location ) {
		throw new State_Redirect_Interrupt( $location );
	}

	/**
	 * Approve an authorisation request and return the redirect location.
	 *
	 * @param Base   $type Grant type handler.
	 * @param Client $client Client being authorised.
	 * @param mixed  $state Raw state value, or null to omit it.
	 * @return string Redirect location.
	 */
	protected function authorize( Base $type, Client $client, $state ) {
		$_GET = [
			'client_id'    => $client->get_id(),
			'redirect_uri' => $client->get_redirect_uris()[0],
		];
		if ( null !== $state ) {
			$_GET['state'] = is_string( $state ) ? wp_slash( $state ) : $state;
		}
		$_POST = [
			'_wpnonce'  => wp_create_nonce( sprintf( 'oauth2_authorize:%s', $client->get_id() ) ),
			'wp-submit' => 'authorize',
		];

		try {
			$type->handle_authorisation();
		} catch ( State_Redirect_Interrupt $redirect ) {
			return $redirect->getMessage();
		}

		$this->fail( 'Expected a redirect.' );
	}

	public function state_provider() {
		return [
			'percent-encoded octets' => [ '%41%42' ],
			'tag-like text'          => [ '<b>x</b>' ],
			'zero'                   => [ '0' ],
			'reserved characters'    => [ 'a&b=c#d' ],
			'surrounding spaces'     => [ '  padded  ' ],
			'quotes and slashes'     => [ 'it\'s "a\\b"' ],
		];
	}

	/**
	 * @dataProvider state_provider
	 */
	public function test_authorization_code_returns_exact_state( $state ) {
		$client   = $this->create_client();
		$location = $this->authorize( new Authorization_Code(), $client, $state );

		parse_str( wp_parse_url( $location, PHP_URL_QUERY ), $args );
		$this->assertSame( $state, $args['state'] );
	}

	/**
	 * @dataProvider state_provider
	 */
	public function test_implicit_returns_exact_state( $state ) {
		// A same-site callback, since the implicit grant redirects with wp_safe_redirect().
		$client   = $this->create_client( [ 'callback' => home_url( '/callback' ) ] );
		$location = $this->authorize( new Implicit(), $client, $state );

		parse_str( wp_parse_url( $location, PHP_URL_FRAGMENT ), $args );
		$this->assertSame( $state, $args['state'] );
		$this->assertArrayHasKey( 'access_token', $args );
	}

	public function test_absent_state_is_not_returned() {
		$client   = $this->create_client();
		$location = $this->authorize( new Authorization_Code(), $client, null );

		parse_str( wp_parse_url( $location, PHP_URL_QUERY ), $args );
		$this->assertArrayNotHasKey( 'state', $args );
	}

	public function test_array_state_is_treated_as_absent() {
		$client   = $this->create_client();
		$location = $this->authorize( new Authorization_Code(), $client, [ 'x' ] );

		parse_str( wp_parse_url( $location, PHP_URL_QUERY ), $args );
		$this->assertArrayNotHasKey( 'state', $args );
	}
}
