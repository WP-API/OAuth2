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
use WP\OAuth2\PKCE;
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
	 * Get the PKCE code challenge stored against this code, if any.
	 *
	 * @return string|null Code challenge, or null if this code was not issued with one.
	 */
	public function get_code_challenge() {
		$value = $this->get_value();
		if ( empty( $value ) || empty( $value['code_challenge'] ) ) {
			return null;
		}

		return $value['code_challenge'];
	}

	/**
	 * Get the PKCE code challenge method stored against this code, if any.
	 *
	 * @return string|null Code challenge method, or null if this code was not issued with a challenge.
	 */
	public function get_code_challenge_method() {
		$value = $this->get_value();
		if ( empty( $value ) || empty( $value['code_challenge_method'] ) ) {
			return null;
		}

		return $value['code_challenge_method'];
	}

	/**
	 * Validate the code for use.
	 *
	 * @param array $args Other request arguments to validate. {
	 *     @var string $code_verifier PKCE code verifier, if the client is using PKCE.
	 * }
	 * @return bool|WP_Error True if valid, error describing problem otherwise.
	 */
	public function validate( $args = [] ) {
		$expiration = $this->get_expiration();
		if ( is_wp_error( $expiration ) ) {
			return $expiration;
		}

		$now = time();
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

		$verifier_check = $this->validate_code_verifier( $args );
		if ( is_wp_error( $verifier_check ) ) {
			return $verifier_check;
		}

		return true;
	}

	/**
	 * Validate a PKCE code verifier against the stored code challenge.
	 *
	 * @param array $args Request arguments, as passed to validate().
	 * @return true|WP_Error True if valid (including when this code has no
	 *                       PKCE challenge and none was supplied), error otherwise.
	 */
	protected function validate_code_verifier( $args ) {
		$challenge = $this->get_code_challenge();
		$verifier  = isset( $args['code_verifier'] ) && is_string( $args['code_verifier'] ) ? $args['code_verifier'] : null;

		if ( null === $challenge ) {
			if ( null === $verifier ) {
				return true;
			}

			/**
			 * Filter whether a code_verifier is accepted for a code that has no stored code_challenge.
			 *
			 * A verifier arriving for a non-PKCE code is unexpected: either the
			 * client is misconfigured, or the code was obtained some other way.
			 * Rejecting it by default is the safer choice.
			 *
			 * @param bool   $reject True to reject the request, the default.
			 * @param string $verifier Code verifier that was supplied.
			 */
			if ( apply_filters( 'oauth2.pkce.reject_unexpected_verifier', true, $verifier ) ) {
				return new WP_Error(
					'oauth2.tokens.authorization_code.validate.unexpected_verifier',
					__( 'This authorization code was not issued with a PKCE challenge.', 'oauth2' ),
					[
						'status' => WP_Http::BAD_REQUEST,
						'error'  => 'invalid_grant',
					]
				);
			}

			return true;
		}

		$method = $this->get_code_challenge_method();
		if ( null === $method ) {
			// A stored challenge with no stored method means corrupted data; fail closed.
			return new WP_Error(
				'oauth2.tokens.authorization_code.validate.missing_challenge_method',
				__( 'Authorization code data is not valid.', 'oauth2' ),
				[ 'status' => WP_Http::BAD_REQUEST ]
			);
		}

		if ( null === $verifier ) {
			return new WP_Error(
				'oauth2.tokens.authorization_code.validate.missing_verifier',
				__( 'This authorization code requires a code_verifier to be exchanged.', 'oauth2' ),
				[
					'status' => WP_Http::BAD_REQUEST,
					'error'  => 'invalid_grant',
				]
			);
		}

		if ( ! PKCE::is_valid_verifier( $verifier ) || ! PKCE::verify( $verifier, $challenge, $method ) ) {
			return new WP_Error(
				'oauth2.tokens.authorization_code.validate.invalid_verifier',
				__( 'The supplied code_verifier does not match the code_challenge for this authorization code.', 'oauth2' ),
				[
					'status' => WP_Http::BAD_REQUEST,
					'error'  => 'invalid_grant',
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
	 * @param array   $data Optional extra data for this code. Only `code_challenge`
	 *                      and `code_challenge_method` are recognised; anything
	 *                      else is ignored, and neither `user` nor `expiration`
	 *                      can be overridden this way.
	 *
	 * @return Authorization_Code|WP_Error Authorization code instance, or error on failure.
	 */
	public static function create( Client $client, WP_User $user, array $data = [] ) {
		$code     = wp_generate_password( static::KEY_LENGTH, false );
		$meta_key = static::KEY_PREFIX . $code;
		$value    = [
			'user'       => (int) $user->ID,
			'expiration' => time() + static::MAX_AGE,
		];

		// Only store the challenge when one was actually supplied, so a
		// non-PKCE code's meta shape is unchanged from before this existed.
		if ( ! empty( $data['code_challenge'] ) ) {
			$value['code_challenge']        = $data['code_challenge'];
			$value['code_challenge_method'] = ! empty( $data['code_challenge_method'] ) ? $data['code_challenge_method'] : PKCE::METHOD_PLAIN;
		}

		$result = add_post_meta( $client->get_post_id(), wp_slash( $meta_key ), wp_slash( $value ), true );
		if ( ! $result ) {
			return new WP_Error(
				'oauth2.tokens.authorization_code.create.could_not_create',
				__( 'Unable to create authorization code.', 'oauth2' )
			);
		}

		return new static( $client, $code );
	}
}
