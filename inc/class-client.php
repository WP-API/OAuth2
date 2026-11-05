<?php
/**
 *
 * @package    WordPress
 * @subpackage JSON API
 */

namespace WP\OAuth2;

use WP\OAuth2\CIMD;
use WP\OAuth2\Tokens\Access_Token;
use WP\OAuth2\Tokens\Authorization_Code;
use WP_Error;
use WP_Post;
use WP_Query;
use WP_User;

class Client implements ClientInterface {
	const POST_TYPE                      = 'oauth2_client';
	const UNAPPROVED_STATUSES            = [ 'draft', 'pending' ];
	const CLIENT_SECRET_KEY              = '_oauth2_client_secret';
	const TYPE_KEY                       = '_oauth2_client_type';
	const REDIRECT_URI_KEY               = '_oauth2_redirect_uri';
	const CLIENT_CREDENTIALS_ENABLED_KEY = '_oauth2_client_credentials_enabled';
	const PKCE_REQUIRED_KEY              = '_oauth2_pkce_required';
	const TOKEN_TTL_KEY                  = '_oauth2_client_token_ttl';
	const AUTH_CODE_KEY_PREFIX           = '_oauth2_authcode_';
	const AUTH_CODE_LENGTH               = 12;
	const CLIENT_ID_LENGTH               = 12;
	const CLIENT_SECRET_LENGTH           = 48;
	const AUTH_CODE_AGE                  = 600; // 10 * MINUTE_IN_SECONDS
	const KIND_KEY                       = '_oauth2_client_kind';
	const KIND_CIMD                      = 'cimd';
	const CIMD_CLIENT_ID_KEY             = '_oauth2_cimd_client_id';
	const CIMD_METADATA_KEY              = '_oauth2_cimd_metadata';
	const CIMD_EXPIRES_KEY               = '_oauth2_cimd_expires';
	const CIMD_GENERATION_KEY            = '_oauth2_cimd_generation';
	const CIMD_SECURITY_HASH_KEY         = '_oauth2_cimd_security_hash';
	const CIMD_FAILED_KEY                = '_oauth2_cimd_failed';

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
	 * @return string Client ID. The metadata document URL for a CIMD client.
	 */
	public function get_id() {
		if ( $this->is_cimd() ) {
			$url = get_post_meta( $this->get_post_id(), static::CIMD_CLIENT_ID_KEY, true );
			if ( '' !== $url && is_string( $url ) ) {
				return $url;
			}
		}

		return $this->post->post_name;
	}

	/**
	 * Check whether the client is a shadow record of a client ID metadata document.
	 *
	 * @return bool True for a CIMD client, false for a registered client.
	 */
	public function is_cimd() {
		return static::KIND_CIMD === get_post_meta( $this->get_post_id(), static::KIND_KEY, true );
	}

	/**
	 * Get the stored metadata of a CIMD client.
	 *
	 * @return array Normalised metadata, empty for a registered client.
	 */
	public function get_cimd_metadata() {
		$metadata = get_post_meta( $this->get_post_id(), static::CIMD_METADATA_KEY, true );

		return is_array( $metadata ) ? $metadata : [];
	}

	/**
	 * Get the time the stored metadata of a CIMD client expires.
	 *
	 * @return int Unix timestamp, 0 for a registered client.
	 */
	public function get_cimd_expires() {
		return (int) get_post_meta( $this->get_post_id(), static::CIMD_EXPIRES_KEY, true );
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
	 * Get the generation of a CIMD client.
	 *
	 * Tokens and authorization codes are stamped with it, and stop working when
	 * the shadow record is replaced or its security-relevant metadata changes.
	 *
	 * @return string Random token, empty for a registered client.
	 */
	public function get_cimd_generation() {
		$generation = get_post_meta( $this->get_post_id(), static::CIMD_GENERATION_KEY, true );

		return is_string( $generation ) ? $generation : '';
	}

	/**
	 * Check whether the last refresh of a CIMD client failed for good.
	 *
	 * @return bool True if a refresh failed in a way that retrying cannot fix.
	 */
	public function is_cimd_failed() {
		return (bool) get_post_meta( $this->get_post_id(), static::CIMD_FAILED_KEY, true );
	}

	/**
	 * Record that the last refresh of a CIMD client failed for good.
	 *
	 * @return bool True if the marker was stored.
	 */
	public function mark_cimd_failed() {
		return static::set_cimd_meta( $this->get_post_id(), static::CIMD_FAILED_KEY, time() );
	}

	/**
	 * Write a meta value and read it back to check that it was stored.
	 *
	 * @param int    $post_id Post ID.
	 * @param string $key     Meta key.
	 * @param mixed  $value   Unslashed value.
	 *
	 * @return bool True if the stored value equals the one written.
	 */
	protected static function set_cimd_meta( $post_id, $key, $value ) {
		update_post_meta( $post_id, $key, wp_slash( $value ) );

		return (string) get_post_meta( $post_id, $key, true ) === (string) $value;
	}

	/**
	 * Check whether the client is approved.
	 *
	 * @return bool True if the client is published.
	 */
	public function is_approved() {
		return 'publish' === $this->post->post_status;
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
		if ( $this->is_cimd() ) {
			return 'public';
		}

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
	 * Check whether the client must authenticate with its secret.
	 *
	 * Clients declared as private are confidential clients in RFC 6749 terms,
	 * so they have to prove they hold the secret they were issued.
	 *
	 * @link https://tools.ietf.org/html/rfc6749#section-3.2.1
	 *
	 * @return bool True if the secret must be verified, false otherwise.
	 */
	public function requires_secret() {
		if ( $this->is_cimd() ) {
			return false;
		}

		$requires_secret = ( 'private' === $this->get_type() );

		/**
		 * Filter whether a client must authenticate with its secret.
		 *
		 * @param bool   $requires_secret Whether the secret must be verified.
		 * @param Client $client          Client being checked.
		 */
		return (bool) apply_filters( 'oauth2.client.requires_secret', $requires_secret, $this );
	}

	/**
	 * Check if the provided secret matches the client's secret.
	 *
	 * @param string $secret Secret to check.
	 *
	 * @return bool True if the secret matches, false otherwise.
	 */
	public function check_secret( $secret ) {
		return hash_equals( $this->get_secret(), $secret );
	}

	/**
	 * Check whether the client_credentials grant is enabled for this client.
	 *
	 * @return bool True if enabled, false otherwise.
	 */
	public function is_client_credentials_enabled() {
		if ( $this->is_cimd() ) {
			return false;
		}

		return (bool) get_post_meta( $this->get_post_id(), static::CLIENT_CREDENTIALS_ENABLED_KEY, true );
	}

	/**
	 * Check whether this client requires PKCE for the authorization_code grant.
	 *
	 * @return bool True if PKCE is required, false otherwise.
	 */
	public function is_pkce_required() {
		if ( $this->is_cimd() ) {
			return true;
		}

		$required = (bool) get_post_meta( $this->get_post_id(), static::PKCE_REQUIRED_KEY, true );

		/**
		 * Filter whether PKCE is required for a client.
		 *
		 * @param bool   $required True if PKCE is required for this client.
		 * @param Client $client Client being checked.
		 */
		return apply_filters( 'oauth2.pkce.required', $required, $this );
	}

	/**
	 * Get the token TTL for client credentials tokens.
	 *
	 * @return int|null TTL in seconds, or null if tokens should not expire.
	 */
	public function get_token_ttl() {
		$ttl = get_post_meta( $this->get_post_id(), static::TOKEN_TTL_KEY, true );

		if ( '' === $ttl || false === $ttl ) {
			return null;
		}

		return (int) $ttl;
	}

	/**
	 * Get registered URI for the client.
	 *
	 * @return array List of valid redirect URIs.
	 */
	public function get_redirect_uris() {
		if ( $this->is_cimd() ) {
			return (array) ( $this->get_cimd_metadata()['redirect_uris'] ?? [] );
		}

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
		if ( $this->is_cimd() ) {
			return $this->check_cimd_redirect_uri( $uri );
		}

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
	 * Check a redirect URI against the URIs of a CIMD client.
	 *
	 * The URI must equal a registered URI exactly. A registered http URI on a
	 * loopback host also matches the same URI with any port.
	 *
	 * @param string $uri Supplied redirect URI to check.
	 *
	 * @return bool True if the URI is valid, false otherwise.
	 */
	protected function check_cimd_redirect_uri( $uri ) {
		if ( ! is_string( $uri ) || '' === $uri ) {
			return false;
		}

		$supplied = wp_parse_url( $uri );

		foreach ( $this->get_redirect_uris() as $registered_uri ) {
			if ( $uri === $registered_uri ) {
				return true;
			}

			$registered = wp_parse_url( $registered_uri );
			if ( ! is_array( $registered ) || ! is_array( $supplied ) ) {
				continue;
			}

			if ( 'http' !== ( $registered['scheme'] ?? null ) || ! isset( $registered['host'] ) || ! CIMD\is_loopback_host( $registered['host'] ) ) {
				continue;
			}

			$port = $supplied['port'] ?? null;
			if ( null !== $port && ( $port < 1 || $port > 65535 ) ) {
				continue;
			}

			// Rebuild the URI from the registered one so nothing else can differ.
			$expected = 'http://' . $registered['host'] . ( null !== $port ? ':' . $port : '' ) . ( $registered['path'] ?? '' ) . ( isset( $registered['query'] ) ? '?' . $registered['query'] : '' );
			if ( $uri === $expected ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * @param WP_User $user
	 * @param array   $data Optional extra data for the code, e.g. PKCE `code_challenge`
	 *                      and `code_challenge_method`. See Authorization_Code::create().
	 *
	 * @return Authorization_Code|WP_Error
	 */
	public function generate_authorization_code( WP_User $user, array $data = [] ) {
		return Authorization_Code::create( $this, $user, $data );
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
	 * Get the post slug of the shadow client for a client ID metadata document URL.
	 *
	 * @param string $url Client ID URL.
	 *
	 * @return string Post slug.
	 */
	protected static function get_cimd_slug( $url ) {
		return 'cimd-' . hash( 'sha256', $url );
	}

	/**
	 * Get a client by ID.
	 *
	 * Only reads the database. A CIMD client ID is a URL; its shadow client is
	 * found by hashed slug and has to store the same URL.
	 *
	 * @param string $id                 Client ID.
	 * @param bool   $include_unapproved Whether to also match draft and pending clients. Trashed clients never match.
	 *
	 * @return static|null Client if ID is found, null otherwise.
	 */
	public static function get_by_id( $id, $include_unapproved = false ) {
		$statuses = [ 'publish' ];
		if ( $include_unapproved ) {
			$statuses = array_merge( $statuses, static::UNAPPROVED_STATUSES );
		}

		$is_cimd_id = CIMD\is_cimd_client_id( $id );

		$args  = [
			'post_type'      => static::POST_TYPE,
			'post_status'    => $statuses,
			'posts_per_page' => 1,
			'no_found_rows'  => true,

			// Query by slug.
			'name'           => $is_cimd_id ? static::get_cimd_slug( $id ) : $id,
		];
		$query = new WP_Query( $args );
		if ( empty( $query->posts ) ) {
			return null;
		}

		$client = new static( $query->posts[0] );
		if ( $is_cimd_id ) {
			$stored = get_post_meta( $client->get_post_id(), static::CIMD_CLIENT_ID_KEY, true );
			if ( ! $client->is_cimd() || $stored !== $id ) {
				return null;
			}
		} elseif ( $client->is_cimd() ) {
			return null;
		}

		return $client;
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
			static::REDIRECT_URI_KEY               => $data['meta']['callback'],
			static::TYPE_KEY                       => $data['meta']['type'],
			static::CLIENT_SECRET_KEY              => wp_generate_password( static::CLIENT_SECRET_LENGTH, false ),
			static::CLIENT_CREDENTIALS_ENABLED_KEY => ! empty( $data['meta']['client_credentials_enabled'] ) ? '1' : '',
			static::PKCE_REQUIRED_KEY              => ! empty( $data['meta']['pkce_required'] ) ? '1' : '',
		];

		if ( isset( $data['meta']['token_ttl'] ) && '' !== $data['meta']['token_ttl'] ) {
			$meta[ static::TOKEN_TTL_KEY ] = (int) $data['meta']['token_ttl'];
		}

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

		// Map of meta key => data key. Built this way, rather than as a fixed
		// array of values, so that a caller omitting a key leaves the existing
		// meta value untouched instead of silently resetting it to empty/false.
		$fields         = [
			static::REDIRECT_URI_KEY               => 'callback',
			static::TYPE_KEY                       => 'type',
			static::CLIENT_CREDENTIALS_ENABLED_KEY => 'client_credentials_enabled',
			static::PKCE_REQUIRED_KEY              => 'pkce_required',
			static::TOKEN_TTL_KEY                  => 'token_ttl',
		];
		$boolean_fields = [ static::CLIENT_CREDENTIALS_ENABLED_KEY, static::PKCE_REQUIRED_KEY ];

		foreach ( $fields as $meta_key => $data_key ) {
			if ( ! array_key_exists( $data_key, $data['meta'] ) ) {
				continue;
			}

			$value = $data['meta'][ $data_key ];
			if ( in_array( $meta_key, $boolean_fields, true ) ) {
				$value = ! empty( $value ) ? '1' : '';
			} elseif ( static::TOKEN_TTL_KEY === $meta_key ) {
				$value = ( null === $value || '' === $value ) ? '' : (int) $value;
			}

			update_post_meta( $post_id, wp_slash( $meta_key ), wp_slash( $value ) );
		}

		$post = get_post( $post_id );

		return new static( $post );
	}

	/**
	 * Hash the metadata fields that decide who can use a CIMD client.
	 *
	 * @param array $metadata Normalised metadata.
	 *
	 * @return string SHA-256 hash.
	 */
	protected static function get_cimd_security_hash( array $metadata ) {
		$fields = [];
		foreach ( [ 'redirect_uris', 'grant_types', 'response_types', 'token_endpoint_auth_method' ] as $field ) {
			$value = $metadata[ $field ] ?? null;
			if ( is_array( $value ) && 'token_endpoint_auth_method' !== $field ) {
				sort( $value );
			}
			$fields[ $field ] = $value;
		}

		return hash( 'sha256', wp_json_encode( $fields ) );
	}

	/**
	 * Create or refresh the shadow client for a client ID metadata document.
	 *
	 * When the metadata has not changed, only the expiry is written.
	 *
	 * An existing shadow client keeps its status, except that a change to the
	 * redirect URIs, grant types, response types or authentication method gives
	 * it a new generation, and moves it back to draft when `$status` is not
	 * `publish`. Does not check capabilities.
	 *
	 * @param string $url      Client ID URL.
	 * @param array  $metadata Normalised metadata from CIMD\validate_document().
	 * @param int    $expires  Unix timestamp the metadata expires at.
	 * @param string $status   Post status for a new shadow client.
	 *
	 * @return static|WP_Error Client instance on success, error otherwise.
	 */
	public static function save_cimd( $url, array $metadata, $expires, $status = 'publish' ) {
		$slug  = static::get_cimd_slug( $url );
		$posts = get_posts(
			[
				'post_type'        => static::POST_TYPE,
				'post_status'      => [ 'publish', 'draft', 'pending', 'private', 'future' ],
				'name'             => $slug,
				'posts_per_page'   => 1,
				'suppress_filters' => true,
			]
		);

		$title    = isset( $metadata['client_name'] ) ? (string) $metadata['client_name'] : '';
		$hash     = static::get_cimd_security_hash( $metadata );
		$is_new   = empty( $posts );
		$old_hash = null;
		if ( $is_new ) {
			$post_id = wp_insert_post(
				wp_slash(
					[
						'post_type'    => static::POST_TYPE,
						'post_title'   => $title,
						'post_content' => '',
						'post_name'    => $slug,
						'post_status'  => $status,
					]
				),
				true
			);
			if ( is_wp_error( $post_id ) ) {
				return $post_id;
			}

			// WordPress adds a suffix when another post, such as an attachment, already uses the slug.
			if ( get_post( $post_id )->post_name !== $slug ) {
				wp_delete_post( $post_id, true );

				return new WP_Error( 'oauth2.cimd.slug_conflict', __( 'Another post already uses the slug of this client ID.', 'oauth2' ), [ 'status' => 500 ] );
			}
		} else {
			$post_id  = $posts[0]->ID;
			$old_hash = get_post_meta( $post_id, static::CIMD_SECURITY_HASH_KEY, true );
			if ( static::KIND_CIMD !== get_post_meta( $post_id, static::KIND_KEY, true ) || get_post_meta( $post_id, static::CIMD_CLIENT_ID_KEY, true ) !== $url ) {
				return new WP_Error( 'oauth2.client.cimd.conflict', __( 'A different client already uses the slug of this client ID.', 'oauth2' ), [ 'status' => 500 ] );
			}

			// Identical metadata only needs the expiry moved, so skip the other writes.
			if ( $old_hash === $hash && get_post_meta( $post_id, static::CIMD_METADATA_KEY, true ) === $metadata && '' !== get_post_meta( $post_id, static::CIMD_GENERATION_KEY, true ) ) {
				if ( (int) get_post_meta( $post_id, static::CIMD_EXPIRES_KEY, true ) !== (int) $expires ) {
					update_post_meta( $post_id, static::CIMD_EXPIRES_KEY, (int) $expires );
				}
				if ( get_post_meta( $post_id, static::CIMD_FAILED_KEY, true ) ) {
					delete_post_meta( $post_id, static::CIMD_FAILED_KEY );
				}

				return new static( $posts[0] );
			}

			if ( $posts[0]->post_title !== $title ) {
				$result = wp_update_post(
					wp_slash(
						[
							'ID'         => $post_id,
							'post_title' => $title,
						]
					),
					true
				);
				if ( is_wp_error( $result ) ) {
					return $result;
				}
			}
		}

		// The new generation is stored and checked before anything else changes, and the hash that
		// records the change is stored last, so a failed write is retried by the next refresh.
		$changed = $is_new || $old_hash !== $hash;
		if ( $changed ) {
			if ( ! static::set_cimd_meta( $post_id, static::CIMD_GENERATION_KEY, wp_generate_password( 32, false ) ) ) {
				if ( $is_new ) {
					wp_delete_post( $post_id, true );
				}

				return new WP_Error( 'oauth2.cimd.save_failed', __( 'The client could not be saved.', 'oauth2' ), [ 'status' => 500 ] );
			}

			if ( ! $is_new && 'publish' !== $status && 'publish' === $posts[0]->post_status ) {
				$result = wp_update_post(
					[
						'ID'          => $post_id,
						'post_status' => 'draft',
					],
					true
				);
				if ( is_wp_error( $result ) ) {
					return $result;
				}
			}
		}

		$meta = [
			static::KIND_KEY           => static::KIND_CIMD,
			static::TYPE_KEY           => 'public',
			static::CIMD_CLIENT_ID_KEY => $url,
			static::CIMD_METADATA_KEY  => $metadata,
			static::CIMD_EXPIRES_KEY   => (int) $expires,
		];
		foreach ( $meta as $key => $value ) {
			update_post_meta( $post_id, $key, wp_slash( $value ) );
		}
		if ( $changed ) {
			update_post_meta( $post_id, static::CIMD_SECURITY_HASH_KEY, $hash );
		}
		if ( get_post_meta( $post_id, static::CIMD_FAILED_KEY, true ) ) {
			delete_post_meta( $post_id, static::CIMD_FAILED_KEY );
		}

		return new static( get_post( $post_id ) );
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
		if ( is_wp_error( $result ) ) {
			return $result;
		}

		$this->post = get_post( $this->get_post_id() );

		return true;
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
