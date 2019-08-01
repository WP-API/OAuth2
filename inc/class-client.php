<?php
/**
 *
 * @package    WordPress
 * @subpackage JSON API
 */

namespace WP\OAuth2;

use WP\OAuth2\Tokens\Access_Token;
use WP\OAuth2\Tokens\Authorization_Code;
use WP_Error;
use WP_Post;
use WP_Query;
use WP_User;

class Client implements ClientInterface {
	const POST_TYPE            = 'oauth2_client';
	const CLIENT_SECRET_KEY    = '_oauth2_client_secret';
	const TYPE_KEY             = '_oauth2_client_type';
	const REDIRECT_URI_KEY     = '_oauth2_redirect_uri';
	const AUTH_CODE_KEY_PREFIX = '_oauth2_authcode_';
	const AUTH_CODE_LENGTH     = 12;
	const CLIENT_ID_LENGTH     = 12;
	const CLIENT_SECRET_LENGTH = 48;
	const AUTH_CODE_AGE        = 600; // 10 * MINUTE_IN_SECONDS

	/**
	 * @var WP_Post
	 */
	protected $post;

	/**
	 * Constructor.
	 *
	 * @param WP_Post $post
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
		return $this->post->post_name;
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
	 * Get the client's description.
	 *
	 * @param boolean $raw True to get raw database value for editing, false to get rendered value for display.
	 *
	 * @return string
	 */
	public function get_description( $raw = false ) {
		// Replicate the_content()'s filters.
		global $post;
		$current_post = $post;
		$the_post     = get_post( $this->get_post_id() );
		if ( $raw ) {
			// Skip the filtering and globals.
			return $the_post->post_content;
		}

		// Set up globals so the filters have context.
		$post = $the_post; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
		setup_postdata( $post );
		$content = get_the_content();

		/** This filter is documented in wp-includes/post-template.php */
		$content = apply_filters( 'the_content', $content );
		$content = str_replace( ']]>', ']]&gt;', $content );

		// Restore previous post.
		$post = $current_post; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
		if ( $post ) {
			setup_postdata( $post );
		}

		return $content;
	}

	/**
	 * Get the client's type.
	 *
	 * @return string Type ID if available, or an empty string.
	 */
	public function get_type() {
		return get_post_meta( $this->get_post_id(), static::TYPE_KEY, true );
	}

	/**
	 * Get the Client Secret Key.
	 *
	 * @return string The Secret Key if available, or an empty string.
	 */
	public function get_secret() {
		return get_post_meta( $this->get_post_id(), static::CLIENT_SECRET_KEY, true );
	}

	/**
	 * Get registered URI for the client.
	 *
	 * @return array List of valid redirect URIs.
	 */
	public function get_redirect_uris() {
		return (array) get_post_meta( $this->get_post_id(), static::REDIRECT_URI_KEY, true );
	}

	/**
	 * Validate a callback URL.
	 *
	 * Based on {@see wp_http_validate_url}, but less restrictive around ports
	 * and hosts. In particular, it allows any scheme, host or port rather than
	 * just HTTP with standard ports.
	 *
	 * @param string $url URL for the callback.
	 *
	 * @return bool True for a valid callback URL, false otherwise.
	 */
	public static function validate_callback( $url ) {
		if ( strpos( $url, ':' ) === false ) {
			return false;
		}

		$parsed_url = wp_parse_url( $url );
		if ( ! $parsed_url || empty( $parsed_url['host'] ) ) {
			return false;
		}

		if ( isset( $parsed_url['user'] ) || isset( $parsed_url['pass'] ) ) {
			return false;
		}

		if ( false !== strpbrk( $parsed_url['host'], ':#?[]' ) ) {
			return false;
		}

		return true;
	}

	/**
	 * Check if a redirect URI is valid for the client.
	 *
	 * @param string $uri Supplied redirect URI to check.
	 *
	 * @return boolean True if the URI is valid, false otherwise.
	 * @todo Implement this properly :)
	 *
	 */
	public function check_redirect_uri( $uri ) {
		if ( ! $this->validate_callback( $uri ) ) {
			return false;
		}

		$supplied       = wp_parse_url( $uri );
		$all_registered = $this->get_redirect_uris();

		foreach ( $all_registered as $registered_uri ) {
			$registered = wp_parse_url( $registered_uri );

			// Double-check registered URI is valid.
			if ( ! $registered ) {
				continue;
			}

			// Check all components except query and fragment
			$parts = [ 'scheme', 'host', 'port', 'user', 'pass', 'path' ];
			$valid = true;
			foreach ( $parts as $part ) {
				if ( isset( $registered[ $part ] ) !== isset( $supplied[ $part ] ) ) {
					$valid = false;
					break;
				}

				if ( ! isset( $registered[ $part ] ) ) {
					continue;
				}

				if ( $registered[ $part ] !== $supplied[ $part ] ) {
					$valid = false;
					break;
				}
			}

			/**
			 * Filter whether a callback is counted as valid. (deprecated).
			 * User rest_oauth_check_callback.
			 *
			 * @param boolean $valid          True if the callback URL is valid, false otherwise.
			 * @param string  $url            Supplied callback URL.
			 * @param string  $registered_uri URI being checked.
			 * @param Client  $client         OAuth 2 client object.
			 */
			$valid = apply_filters( 'rest_oauth.check_callback', $valid, $uri, $registered_uri, $this );

			if ( $valid ) {
				// Stop checking, we have a match.
				return true;
			}
		}

		return false;
	}

	/**
	 * @param WP_User $user
	 *
	 * @return Authorization_Code|WP_Error
	 */
	public function generate_authorization_code( WP_User $user ) {
		return Authorization_Code::create( $this, $user );
	}

	/**
	 * Get data stored for an authorization code.
	 *
	 * @param string $code Authorization code to fetch.
	 *
	 * @return Authorization_Code|WP_Error Data if available, error if invalid code.
	 */
	public function get_authorization_code( $code ) {
		return Authorization_Code::get_by_code( $this, $code );
	}

	/**
	 * @return bool|WP_Error
	 */
	public function regenerate_secret() {
		$result = update_post_meta( $this->get_post_id(), static::CLIENT_SECRET_KEY, wp_generate_password( static::CLIENT_SECRET_LENGTH, false ) );
		if ( ! $result ) {
			return new WP_Error( 'oauth2.client.create.failed_meta', __( 'Could not regenerate the client secret.', 'oauth2' ) );
		}

		return true;
	}

	/**
	 * Issue token for a user.
	 *
	 * @param \WP_User $user
	 * @param array    $meta
	 *
	 * @return Access_Token
	 */
	public function issue_token( WP_User $user, $meta = [] ) {
		return Tokens\Access_Token::create( $this, $user, $meta );
	}

	/**
	 * Get a client by ID.
	 *
	 * @param string $id Client ID.
	 *
	 * @return static|null Token if ID is found, null otherwise.
	 */
	public static function get_by_id( $id ) {
		$args  = [
			'post_type'      => static::POST_TYPE,
			'post_status'    => 'publish',
			'posts_per_page' => 1,
			'no_found_rows'  => true,

			// Query by slug.
			'name'           => $id,
		];
		$query = new WP_Query( $args );
		if ( empty( $query->posts ) ) {
			return null;
		}

		return new static( $query->posts[0] );
	}

	/**
	 * Get a client by post ID.
	 *
	 * @param int $id Client/post ID.
	 *
	 * @return static|null Client instance on success, null if invalid/not found.
	 */
	public static function get_by_post_id( $id ) {
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
	 *                    }
	 *
	 * @return WP_Error|Client Client instance on success, error otherwise.
	 */
	public static function create( $data ) {
		$client_id = wp_generate_password( static::CLIENT_ID_LENGTH, false );
		$post_data = [
			'post_type'    => static::POST_TYPE,
			'post_title'   => $data['name'],
			'post_content' => $data['description'],
			'post_name'    => $client_id,
			'post_status'  => 'draft',
		];

		$post_id = wp_insert_post( wp_slash( $post_data ), true );
		if ( is_wp_error( $post_id ) ) {
			return $post_id;
		}

		// Generate ID and secret.
		$meta = [
			static::REDIRECT_URI_KEY  => $data['meta']['callback'],
			static::TYPE_KEY          => $data['meta']['type'],
			static::CLIENT_SECRET_KEY => wp_generate_password( static::CLIENT_SECRET_LENGTH, false ),
		];

		foreach ( $meta as $key => $value ) {
			$result = update_post_meta( $post_id, wp_slash( $key ), wp_slash( $value ) );
			if ( ! $result ) {
				// Failed, rollback.
				return new WP_Error( 'oauth2.client.create.failed_meta', __( 'Could not save meta value.', 'oauth2' ) );
			}
		}

		$post = get_post( $post_id );

		return new static( $post );
	}

	/**
	 * @param array $data
	 *
	 * @return WP_Error|Client Client instance on success, error otherwise.
	 */
	public function update( $data ) {
		$post_data = [
			'ID'           => $this->get_post_id(),
			'post_type'    => static::POST_TYPE,
			'post_title'   => $data['name'],
			'post_content' => $data['description'],
		];

		$post_id = wp_update_post( wp_slash( $post_data ), true );
		if ( is_wp_error( $post_id ) ) {
			return $post_id;
		}

		$meta = [
			static::REDIRECT_URI_KEY => $data['meta']['callback'],
			static::TYPE_KEY         => $data['meta']['type'],
		];

		foreach ( $meta as $key => $value ) {
			update_post_meta( $post_id, wp_slash( $key ), wp_slash( $value ) );
		}

		$post = get_post( $post_id );

		return new static( $post );
	}

	/**
	 * Delete the client.
	 *
	 * @return bool
	 */
	public function delete() {
		return (bool) wp_delete_post( $this->get_post_id(), true );
	}

	/**
	 * Approve a client.
	 *
	 * @return bool|WP_Error True if client was updated, error otherwise.
	 */
	public function approve() {
		$data   = [
			'ID'          => $this->get_post_id(),
			'post_status' => 'publish',
		];
		$result = wp_update_post( wp_slash( $data ), true );

		return is_wp_error( $result ) ? $result : true;
	}

	/**
	 * Register the underlying post type.
	 */
	public static function register_type() {
		register_post_type(
			static::POST_TYPE,
			[
				'public'          => false,
				'hierarchical'    => true,
				'capability_type' => [
					'oauth2_client',
					'oauth2_clients',
				],
				'capabilities'    => [
					'edit_posts'        => 'edit_users',
					'edit_others_posts' => 'edit_users',
					'publish_posts'     => 'edit_users',
				],
				'supports'        => [
					'title',
					'editor',
					'revisions',
					'author',
					'thumbnail',
				],
			]
		);
	}
}
