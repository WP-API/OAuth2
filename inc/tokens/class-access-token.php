<?php

namespace WP\OAuth2\Tokens;

use WP_Error;
use WP\OAuth2\Client;
use WP_Query;
use WP_User;

class Access_Token extends Token {
	const META_PREFIX = '_oauth2_access_';
	const KEY_LENGTH = 12;

	/**
	 * @return string Meta prefix.
	 */
	protected function get_meta_prefix() {
		return static::META_PREFIX;
	}

	/**
	 * Get the ID for the user that the token represents.
	 *
	 * @return int
	 */
	public function get_user_id() {
		return (int) $this->value['user'];
	}

	/**
	 * Get the user that the token represents.
	 *
	 * @return WP_User|null
	 */
	public function get_user() {
		return get_user_by( 'id', $this->get_user_id() );
	}

	/**
	 * Get a token by ID.
	 *
	 * @param string $id Token ID.
	 * @return static|null Token if ID is found, null otherwise.
	 */
	public static function get_by_id( $id ) {
		$key = static::META_PREFIX . $id;
		$args = array(
			'post_type'      => Client::POST_TYPE,
			'post_status'    => 'publish',
			'posts_per_page' => 1,
			'no_found_rows'  => true,
			'meta_query'     => array(
				array(
					'key'     => $key,
					'compare' => 'EXISTS',
				),
			),
		);
		$query = new WP_Query( $args );
		if ( empty( $query->posts ) ) {
			return null;
		}

		$value = get_post_meta( $query->posts[0]->ID, wp_slash( $key ), false );
		if ( empty( $value ) ) {
			return null;
		}

		return new static( $key, $value[0] );
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

		$data = array(
			'user' => (int) $user->ID,
		);
		$key = wp_generate_password( static::KEY_LENGTH, false );
		$meta_key = static::META_PREFIX . $key;

		$result = add_post_meta( $client->get_post_id(), wp_slash( $meta_key ), wp_slash( $data ), true );
		if ( ! $result ) {
			return new WP_Error(
				'oauth2.tokens.access_token.create.could_not_create',
				__( 'Unable to create token.', 'oauth2' )
			);
		}

		return new static( $key, $data );
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
