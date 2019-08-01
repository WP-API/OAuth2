<?php
/**
 *
 * @package WordPress
 * @subpackage JSON API
 */

namespace WP\OAuth2\Tokens;

use WP_Error;
use WP_Http;
use WP\OAuth2\Client;
use WP_User;

/**
 * Authorization Code object.
 *
 * Not technically a token, but similar.
 */
class Authorization_Code {
	const KEY_PREFIX = '_oauth2_authcode_';
	const KEY_LENGTH = 12;
	const MAX_AGE    = 600; // 10 * MINUTE_IN_SECONDS

	/**
	 * Actual code.
	 *
	 * @var string
	 */
	protected $code;

	/**
	 * Associated API client.
	 *
	 * @var Client
	 */
	protected $client;

	/**
	 * @param Client $client
	 * @param string $code
	 */
	public function __construct( Client $client, $code ) {
		$this->client = $client;
		$this->code   = $code;
	}

	/**
	 * Get the actual code.
	 *
	 * @return string Authorization code for passing to client.
	 */
	public function get_code() {
		return $this->code;
	}

	/**
	 * Get meta key.
	 *
	 * Authorization codes are stored as post meta on the client.
	 *
	 * @return string
	 */
	protected function get_meta_key() {
		return static::KEY_PREFIX . $this->code;
	}

	/**
	 * Get meta value.
	 *
	 * @return array|null Data if available, or null if code does not exist.
	 */
	protected function get_value() {
		$data = get_post_meta( $this->client->get_post_id(), wp_slash( $this->get_meta_key() ), false );
		if ( empty( $data ) ) {
			return null;
		}

		return $data[0];
	}

	/**
	 * Get the user for the authorization code.
	 *
	 * @return WP_User|WP_Error User object, or error if data is not valid.
	 */
	public function get_user() {
		$value = $this->get_value();
		if ( empty( $value ) || empty( $value['user'] ) ) {
			return new WP_Error(
				'oauth2.tokens.authorization_code.get_user.invalid_data',
				__( 'Authorization code data is not valid.', 'oauth2' )
			);
		}

		return get_user_by( 'id', (int) $value['user'] );
	}

	/**
	 * Get the expiration.
	 *
	 * @return int|WP_Error Expiration, or error on failure.
	 */
	public function get_expiration() {
		$value = $this->get_value();
		if ( empty( $value ) || empty( $value['expiration'] ) || ! is_numeric( $value['expiration'] ) ) {
			return new WP_Error(
				'oauth2.tokens.authorization_code.get_user.invalid_data',
				__( 'Authorization code data is not valid.', 'oauth2' )
			);
		}

		return (int) $value['expiration'];
	}

	/**
	 * Validate the code for use.
	 *
	 * @param array $args Other request arguments to validate.
	 * @return bool|WP_Error True if valid, error describing problem otherwise.
	 */
	public function validate( $args = [] ) {
		$expiration = $this->get_expiration();
		$now        = time();
		if ( $expiration <= $now ) {
			return new WP_Error(
				'oauth2.tokens.authorization_code.validate.expired',
				__( 'Authorization code has expired.', 'oauth2' ),
				[
					'status'     => WP_Http::BAD_REQUEST,
					'expiration' => $expiration,
					'time'       => $now,
				]
			);
		}

		return true;
	}

	/**
	 * Delete the authorization code.
	 *
	 * @return bool|WP_Error True if deleted, error otherwise.
	 */
	public function delete() {
		$result = delete_post_meta( $this->client->get_post_id(), wp_slash( $this->get_meta_key() ) );
		if ( ! $result ) {
			return new WP_Error(
				'oauth2.tokens.authorization_code.delete.could_not_delete',
				__( 'Unable to delete authorization code.', 'oauth2' )
			);
		}

		return true;
	}

	/**
	 * Creates a new authorization code instance for the given client and code.
	 *
	 * @param Client $client
	 * @param string $code
	 *
	 * @return Authorization_Code|WP_Error Authorization code instance, or error on failure.
	 */
	public static function get_by_code( Client $client, $code ) {
		$key   = static::KEY_PREFIX . $code;
		$value = get_post_meta( $client->get_post_id(), wp_slash( $key ), false );
		if ( empty( $value ) ) {
			return new WP_Error(
				'oauth2.client.check_authorization_code.invalid_code',
				__( 'Authorization code is not valid for the specified client.', 'oauth2' ),
				[
					'status' => WP_Http::NOT_FOUND,
					'client' => $client->get_id(),
					'code'   => $code,
				]
			);
		}

		return new static( $client, $code );
	}

	/**
	 * Creates a new authorization code instance for the given client and user.
	 *
	 * @param Client  $client
	 * @param WP_User $user
	 *
	 * @return Authorization_Code|WP_Error Authorization code instance, or error on failure.
	 */
	public static function create( Client $client, WP_User $user ) {
		$code     = wp_generate_password( static::KEY_LENGTH, false );
		$meta_key = static::KEY_PREFIX . $code;
		$data     = [
			'user'       => (int) $user->ID,
			'expiration' => time() + static::MAX_AGE,
		];
		$result   = add_post_meta( $client->get_post_id(), wp_slash( $meta_key ), wp_slash( $data ), true );
		if ( ! $result ) {
			return new WP_Error(
				'oauth2.tokens.authorization_code.create.could_not_create',
				__( 'Unable to create authorization code.', 'oauth2' )
			);
		}

		return new static( $client, $code );
	}
}
