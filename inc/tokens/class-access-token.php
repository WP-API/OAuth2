<?php

namespace WP\OAuth2\Tokens;

use WP_Error;
use WP\OAuth2\Client;
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
	 * @return Client|null
	 */
	public function get_client() {
		return Client::get_by_id( $this->value['client'] );
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
	 * Revoke the token.
	 *
	 * @internal This may return other error codes in the future, as we may
	 *           need to also revoke refresh tokens.
	 * @return bool|WP_Error True if succeeded, error otherwise.
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
	 * @return static|null Token if ID is found, null otherwise.
	 */
	public static function get_by_id( $id ) {
		$key = static::META_PREFIX . $id;
		$args = [
			'number'      => 1,
			'count_total' => false,

			// We use an EXISTS query here, limited by 1, so we can ignore
			// the performance warning.
			'meta_query'  => [ // WPCS: tax_query OK
				[
					'key'     => $key,
					'compare' => 'EXISTS',
				],
			],
		];
		$query = new WP_User_Query( $args );
		$results = $query->get_results();
		if ( empty( $results ) ) {
			return null;
		}

		$user = $results[0];
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
		$meta = get_user_meta( $user->ID );
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
	public static function create( Client $client, WP_User $user ) {
		if ( ! $user->exists() ) {
			return new WP_Error(
				'oauth2.tokens.access_token.create.no_user',
				__( 'Invalid user to create token for.', 'oauth2' )
			);
		}

		$data = [
			'client'  => $client->get_id(),
			'created' => time(),
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
