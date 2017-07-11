<?php # -*- coding: utf-8 -*-

namespace WP\OAuth2\Tests\Unit\Endpoints;

use Brain\Monkey;
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
}
