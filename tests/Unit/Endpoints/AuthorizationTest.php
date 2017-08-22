<?php # -*- coding: utf-8 -*-

namespace WP\OAuth2\Tests\Unit\Endpoints;

use Brain\Monkey;
use Mockery;
use Patchwork;
use WP\OAuth2\Endpoints\Authorization as Testee;
use WP\OAuth2\Tests\TestCase;

/**
 * Test class for the authorzation endpoint.
 */
class AuthorizationTest extends TestCase {

	/**
	 * Loads all required files.
	 *
	 * @return void
	 */
	public static function setUpBeforeClass() {
		parent::setUpBeforeClass();
		self::autoload( 'inc/endpoints/class-authorization.php' );
	}

	/**
	 * Tests registering all the hooks.
	 */
	public function test_registering_hooks() {
		$testee = new Testee();

		Monkey\WP\Actions::expectAdded( 'login_form_' . Testee::LOGIN_ACTION, [ $testee, 'handle_request' ] );

		$testee->register_hooks();
	}

	/**
	 * Tests registering all the hooks.
	 */
	public function test_using_authorization_handler_for_specified_response_type() {
		$response_type = 'some-response-type-here';
		$_GET['response_type'] = $response_type;

		$testee = new Testee();

		Monkey\Functions::when( 'wp_unslash' )->returnArg();

		$handler = Mockery::mock( 'WP\\OAuth2\\Types\Type', [
			'get_response_type_code' => $response_type,
		] );
		$handler->shouldReceive( 'handle_authorisation' )->andReturn( 'no-wp-error' );

		$other_handler = Mockery::mock( 'WP\\OAuth2\\Types\Type', [
			'get_response_type_code' => 'other-response-type',
		] );

		Monkey\Functions::expect( 'WP\\OAuth2\\get_grant_types' )->andReturn( [
			clone $other_handler,
			$handler,
			clone $other_handler,
		] );

		Patchwork\redefine( 'exit', function() {} );

		$testee->register_hooks();
	}
}
