<?php

namespace WP\OAuth2\Tokens;

abstract class Token {

	/**
	 * @var string
	 */
	protected $key;

	/**
	 * @var mixed
	 */
	protected $value;

	/**
	 * @param string $key
	 * @param mixed $value
	 */
	protected function __construct( $key, $value ) {
		$this->key = $key;
		$this->value = $value;
	}

	/**
	 * Get the meta prefix.
	 *
	 * @return string Meta prefix.
	 */
	abstract protected function get_meta_prefix();

	/**
	 * Check if the token is valid.
	 *
	 * @return bool True if the token is valid, false otherwise.
	 */
	abstract public function is_valid();

	/**
	 * Get the token's key.
	 *
	 * @return string Token
	 */
	public function get_key() {
		return $this->key;
	}

	/**
	 * Get the token's value.
	 *
	 * @return mixed Token value, specific to the token type.
	 */
	public function get_value() {
		return $this->value;
	}

	/**
	 * Get the meta key for the token.
	 *
	 * @return string Meta key, including type-specific prefix.
	 */
	public function get_meta_key() {
		return $this->get_meta_prefix() . $this->get_key();
	}
}
