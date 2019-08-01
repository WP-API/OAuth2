<?php
/**
 *
 * @package    WordPress
 * @subpackage JSON API
 */

namespace WP\OAuth2\Tokens;

use WP_Error;
use WP\OAuth2;
use WP\OAuth2\ClientInterface;
use WP_User;
use WP_User_Query;

class Access_Token extends Token {
	const META_PREFIX = '_oauth2_access_';
	const KEY_LENGTH  = 12;

	/**
	 * @return string Meta prefix.
	 */
	protected function get_meta_prefix() {
		return static::META_PREFIX;
	}

	/**
	 * Get client for the token.
	 *
	 * @return ClientInterface|null
	 */
	public function get_client() {
		return OAuth2\get_client( $this->value['client'] );
	}

	/**
	 * Get creation time for the token.
	 *
	 * @return int Creation timestamp.
	 */
	public function get_creation_time() {
		return $this->value['created'];
	}

	/**
	 * Get a meta value for the token.
	 *
	 * This is used to store additional information on the token itself, such
	 * as a description for the token.
	 *
	 * @param string $key     Meta key to fetch.
	 * @param mixed  $default Value to return if key is unavailable.
	 *
	 * @return mixed Value if available, or value of `$default` if not found.
	 */
	public function get_meta( $key, $default = null ) {
		if ( empty( $this->value['meta'] ) || ! isset( $this->value['meta'][ $key ] ) ) {
			return null;
		}

		return $this->value['meta'][ $key ];
	}

	/**
	 * Set a meta value for the token.
	 *
	 * This is used to store additional information on the token itself, such
	 * as a description for the token.
	 *
	 * @param string $key   Meta key to set.
	 * @param mixed  $value Value to set on the key.
	 *
	 * @return bool True if meta was set, false otherwise.
	 */
	public function set_meta( $key, $value ) {
		if ( empty( $this->value['meta'] ) ) {
			$this->value['meta'] = [];
		}
		$this->value['meta'][ $key ] = $value;

		return update_user_meta( $this->get_user_id(), wp_slash( $this->get_meta_key() ), wp_slash( $this->value ) );
	}

	/**
	 * Revoke the token.
	 *
	 * @return bool|WP_Error True if succeeded, error otherwise.
	 * @internal This may return other error codes in the future, as we may
	 *           need to also revoke refresh tokens.
	 */
	public function revoke() {
		$success = delete_user_meta( $this->get_user_id(), $this->get_meta_key() );
		if ( ! $success ) {
			return new WP_Error(
				'oauth2.tokens.access_token.revoke.could_not_revoke',
				__( 'Could not revoke the token.', 'oauth2' )
			);
		}

		return true;
	}

	/**
	 * Get a token by ID.
	 *
	 * @param string $id Token ID.
	 *
	 * @return static|null Token if ID is found, null otherwise.
	 */
	public static function get_by_id( $id ) {
		$key  = static::META_PREFIX . $id;
		$args = [
			'number'      => 1,
			'count_total' => false,

			// We use an EXISTS query here, limited by 1, so we can ignore
			// the performance warning.
			'meta_query'  => [ // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_query
				[
					'key'     => $key,
					'compare' => 'EXISTS',
				],
			],
		];

		$query   = new WP_User_Query( $args );
		$results = $query->get_results();
		if ( empty( $results ) ) {
			return null;
		}

		$user  = $results[0];
		$value = get_user_meta( $user->ID, wp_slash( $key ), false );
		if ( empty( $value ) ) {
			return null;
		}

		return new static( $user, $id, $value[0] );
	}

	/**
	 * Get all tokens for the specified user.
	 *
	 * @return static[] List of tokens.
	 */
	public static function get_for_user( WP_User $user ) {
		$meta   = get_user_meta( $user->ID );
		$tokens = [];
		foreach ( $meta as $key => $values ) {
			if ( strpos( $key, static::META_PREFIX ) !== 0 ) {
				continue;
			}

			$real_key = substr( $key, strlen( static::META_PREFIX ) );
			$value    = maybe_unserialize( $values[0] );
			$tokens[] = new static( $user, $real_key, $value );
		}

		return $tokens;
	}

	/**
	 * Creates a new token for the given client and user.
	 *
	 * @param Client  $client
	 * @param WP_User $user
	 *
	 * @return Access_Token|WP_Error Token instance, or error on failure.
	 */
	public static function create( ClientInterface $client, WP_User $user, $meta = [] ) {
		if ( ! $user->exists() ) {
			return new WP_Error(
				'oauth2.tokens.access_token.create.no_user',
				__( 'Invalid user to create token for.', 'oauth2' )
			);
		}

		$data     = [
			'client'  => $client->get_id(),
			'created' => time(),
			'meta'    => $meta,
		];
		$key      = wp_generate_password( static::KEY_LENGTH, false );
		$meta_key = static::META_PREFIX . $key;

		$result = add_user_meta( $user->ID, wp_slash( $meta_key ), wp_slash( $data ), true );
		if ( ! $result ) {
			return new WP_Error(
				'oauth2.tokens.access_token.create.could_not_create',
				__( 'Unable to create token.', 'oauth2' )
			);
		}

		return new static( $user, $key, $data );
	}

	/**
	 * Check if the token is valid.
	 *
	 * @return bool True if the token is valid, false otherwise.
	 */
	public function is_valid() {
		return true;
	}
}
