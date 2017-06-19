<?php

namespace WP\OAuth2\Tokens;

use WP_Error;
use WP\OAuth2\Client;
use WP_User;

class Access_Token extends Token {
	const META_PREFIX = 'oauth2_access_';
	const KEY_LENGTH = 12;

	protected static function get_meta_prefix() {
		return static::META_PREFIX;
	}

	/**
	 * Get a token by ID.
	 *
	 * @param string $id Token ID.
	 * @return static|null Token if ID is found, null otherwise.
	 */
	public static function get_by_id( $id ) {
		$args = array(
			'post_type'      => Client::POST_TYPE,
			'post_status'    => 'publish',
			'posts_per_page' => 1,
			'no_found_rows'  => true,
			'meta_query'     => array(
				array(
					'key'     => static::META_PREFIX . $id,
					'compare' => 'EXISTS',
				),
			),
		);
		$query = new WP_Query( $args );
		if ( empty( $query->posts ) ) {
			return null;
		}

		return new static( $query->posts[0] );
	}

	public static function create( Client $client, WP_User $user ) {
		$data = array(
			'user' => $user->ID,
		);
		$key = wp_generate_password( static::KEY_LENGTH, false );
		$meta_key = static::META_PREFIX . $key;

		$result = add_post_meta( $client->get_id(), wp_slash( $meta_key ), wp_slash( $data ), true );
		if ( ! $result ) {
			return new WP_Error(
				'oauth2.tokens.access_token.create.could_not_create',
				__( 'Unable to create token.', 'oauth2' )
			);
		}

		return new static( $key, $data );
	}
}