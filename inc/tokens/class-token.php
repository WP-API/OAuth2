<?php

namespace WP\OAuth2\Tokens;

abstract class Token {
	protected function __construct( $key, $value ) {
		$this->key = $key;
		$this->value = $value;
	}

	public function get_key() {
		return $this->key;
	}

	/**
	 * Check if the token is valid.
	 *
	 * @return bool True if the token is valid, false otherwise.
	 */
	public function is_valid() {
		return true;
	}

	/**
	 * Get the meta key for the token.
	 *
	 * @return string Meta key, including type-specific prefix.
	 */
	public function get_meta_key() {
		return static::get_meta_prefix() . $this->get_key();
	}
	public abstract function to_meta_value();
}
