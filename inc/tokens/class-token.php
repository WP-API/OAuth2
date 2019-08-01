<?php
/**
 *
 * @package WordPress
 * @subpackage JSON API
 */

namespace WP\OAuth2\Tokens;

use WP_User;

abstract class Token {
	/**
	 * User the token belongs to.
	 *
	 * @var WP_User
	 */
	protected $user;

	/**
	 * @var string
	 */
	protected $key;

	/**
	 * @var mixed
	 */
	protected $value;

	/**
	 * @param WP_User $key
	 * @param mixed  $value
	 */
	protected function __construct( WP_User $user, $key, $value ) {
		$this->user  = $user;
		$this->key   = $key;
		$this->value = $value;
	}

	/**
	 * Get the ID for the user that the token represents.
	 *
	 * @return int
	 */
	public function get_user_id() {
		return $this->user->ID;
	}

	/**
	 * Get the user that the token represents.
	 *
	 * @return WP_User
	 */
	public function get_user() {
		return $this->user;
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
