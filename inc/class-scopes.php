<?php

namespace WP\OAuth2;

class Scopes {
	protected $capabilities;

	public function __construct() {
		$this->capabilities = array();
	}

	public function register( $id, $capabilities ) {
		$this->scopes[ $id ] = $capabilities;
	}
}
