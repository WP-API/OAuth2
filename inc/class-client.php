<?php

namespace WP\OAuth2;

use WP_Error;
use WP_Post;

class Client {
	const POST_TYPE            = 'oauth2_client';
	const CLIENT_ID_KEY        = '_oauth2_client_id';
	const CLIENT_SECRET_KEY    = '_oauth2_client_secret';
	const TYPE_KEY             = '_oauth2_client_type';
	const REDIRECT_URI_KEY     = '_oauth2_redirect_uri';
	const AUTH_CODE_KEY_PREFIX = '_oauth2_authcode_';
	const AUTH_CODE_LENGTH     = 12;
	const CLIENT_ID_LENGTH     = 12;
	const CLIENT_SECRET_LENGTH = 48;
	const AUTH_CODE_AGE        = 600; // 10 * MINUTE_IN_SECONDS

	protected $post;

	/**
	 * Constructor.
	 */
	protected function __construct( WP_Post $post ) {
		$this->post = $post;
	}

	/**
	 * Get the client's ID.
	 *
	 * @return string Client ID.
	 */
	public function get_id() {
		$result = get_post_meta( $this->get_post_id(), static::CLIENT_ID_KEY, false );
		if ( empty( $result ) ) {
			return null;
		}

		return $result[0];
	}

	/**
	 * Get the client's post ID.
	 *
	 * For internal (WordPress) use only. For external use, use get_key()
	 *
	 * @return int Client ID.
	 */
	public function get_post_id() {
		return $this->post->ID;
	}

	/**
	 * Get the client's name.
	 *
	 * @return string HTML string.
	 */
	public function get_name() {
		return get_the_title( $this->get_post_id() );
	}

	/**
	 * Get the client's type.
	 *
	 * @return string|null Type ID if available, null otherwise.
	 */
	public function get_type() {
		$result = get_post_meta( $this->get_post_id(), static::TYPE_KEY, false );
		if ( empty( $result ) ) {
			return null;
		}

		return $result[0];
	}

	/**
	 * Get registered URIs for the client.
	 *
	 * @return string[] List of valid redirect URIs.
	 */
	public function get_redirect_uris() {
		return get_post_meta( $this->get_post_id(), static::REDIRECT_URI_KEY, false );
	}

	/**
	 * Check if a redirect URI is valid for the client.
	 *
	 * @param string $url Supplied redirect URI to check.
	 * @return boolean True if the URI is valid, false otherwise.
	 */
	public function check_redirect_uri( $uri ) {
		return false;
	}

	public function generate_authorization_code( WP_User $user ) {
		$code = wp_generate_password( static::AUTH_CODE_LENGTH, false );
		$meta_key = static::AUTH_CODE_KEY_PREFIX . $code;
		$data = array(
			'user'       => $user->ID,
			'expiration' => static::AUTH_CODE_AGE,
		);
		$result = add_post_meta( $this->get_post_id(), wp_slash( $meta_key ), wp_slash( $data ), true );
		if ( ! $result ) {
			return new WP_Error();
		}

		return $code;
	}

	/**
	 * Issue token for a user.
	 *
	 * @param WP_User $user
	 */
	public function issue_token( WP_User $user ) {
		return Tokens\Access_Token::create( $this, $user );
	}

	/**
	 * Get a client by ID.
	 *
	 * @param int $id Client/post ID.
	 * @return static|null Client instance on success, null if invalid/not found.
	 */
	public static function get_by_id( $id ) {
		$post = get_post( $id );
		if ( ! $post ) {
			return null;
		}

		return new static( $post );
	}

	/**
	 * Create a new client.
	 *
	 * @param array $data {
	 * }
	 * @return static|WP_Error Client instance on success, error otherwise.
	 */
	public static function create( $data ) {
		$post_data = array(
			'post_type'    => static::POST_TYPE,
			'post_title'   => $data['name'],
			'post_content' => $data['description'],
			'post_author'  => $data['author'],
			'post_status'  => 'draft',
		);

		$post_id = wp_insert_post( wp_slash( $post_data ), true );
		if ( is_wp_error( $post_id ) ) {
			return $post_id;
		}

		// Generate ID and secret.
		$meta = array(
			static::CLIENT_ID_KEY     => wp_generate_password( static::CLIENT_ID_LENGTH, false ),
			static::CLIENT_SECRET_KEY => wp_generate_password( static::CLIENT_SECRET_LENGTH, false ),
		);

		foreach ( $meta as $key => $value ) {
			$result = update_post_meta( $post_id, wp_slash( $key ), wp_slash( $value ) );
			if ( ! $result ) {
				// Failed, rollback.
				return new WP_Error( 'oauth2.client.create.failed_meta', __( 'Could not save meta value.', 'oauth2' ) );
			}
		}

		return new static( $post );
	}

	/**
	 * Register the underlying post type.
	 */
	public static function register_type() {
		register_post_type( static::POST_TYPE, array(
			'public'          => false,
			'hierarchical'    => true,
			'capability_type' => array(
				'client',
				'clients',
			),
			'supports'        => array(
				'title',
				'editor',
				'revisions',
				'author',
				'thumbnail',
			),
		));
	}
}
