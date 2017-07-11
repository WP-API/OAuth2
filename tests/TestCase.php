<?php

namespace WP\OAuth2\Tests;

use Brain\Monkey;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\TestCase as PHPUnitTestCase;

/**
 * Abstract base class for all test case implementations.
 */
abstract class TestCase extends PHPUnitTestCase {

	use MockeryPHPUnitIntegration;

	/**
	 * Prepares the test environment before each test.
	 *
	 * @return void
	 */
	protected function setUp() {
		parent::setUp();
		Monkey::setUpWP();
	}

	/**
	 * Cleans up the test environment after each test.
	 *
	 * @return void
	 */
	protected function tearDown() {
		Monkey::tearDownWP();
		parent::tearDown();
	}

	/**
	 * Loads the given files if they haven't been loaded before.
	 *
	 * @param string|string[] $files One or more file paths, relative to the plugin root.
	 *
	 * @return void
	 */
	protected static function autoload( $files ) {
		$files = (array) $files;
		array_walk( $files, [ __CLASS__, 'autoload_file' ] );
	}

	/**
	 * Loads the given file if it hasn't been loaded before.
	 *
	 * @param string $file File paths, relative to the plugin root.
	 *
	 * @return void
	 */
	private static function autoload_file( $file ) {
		static $root_path;
		if ( ! $root_path ) {
			$root_path = dirname( __DIR__ ) . '/';
		}
		/** @noinspection PhpIncludeInspection */
		require_once $root_path . trim( $file, '\/' );
	}
}
