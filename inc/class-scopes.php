<?php
/**
 *
 * @package    WordPress
 * @subpackage JSON API
 */

namespace WP\OAuth2;

class Scopes {
	protected $capabilities;

	public function __construct() {
		$this->capabilities = [];
	}

	public function register( $id, $capabilities ) {
		$this->scopes[ $id ] = $capabilities;
	}
}
