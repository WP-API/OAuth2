<?php
/**
 *
 * @package    WordPress
 * @subpackage JSON API
 */

namespace WP\OAuth2;

use WP\OAuth2\Tokens\Access_Token;
use WP_Error;
use WP_User;

/**
 * Internal client that owns Personal Access Tokens.
 */
class PersonalClient implements ClientInterface {
	/**
	 * Internal ID for the client.
	 */
	const ID = '__personal_access_token';

	/**
	 * Constructor.
	 *
	 * This should always be accessed via {@see get_instance} instead.
	 */
	protected function __construct() {
		// No-op.
	}

	/**
	 * Get Personal Access Token client instance.
	 *
	 * This is a singleton instance, as it is a fake client backing personal
	 * access tokens.
	 *
	 * @return static
	 */
	public static function get_instance() {
		static $instance;
		if ( empty( $instance ) ) {
			$instance = new static();
		}

		return $instance;
	}

	/**
	 * Get the client's ID.
	 *
	 * @return string Client ID.
	 */
	public function get_id() {
		return static::ID;
	}

	/**
	 * Get the client's name.
	 *
	 * @return string HTML string.
	 */
	public function get_name() {
		return __( 'Personal Access Token', 'oauth2' );
	}

	/**
	 * Get the client's description.
	 *
	 * @param boolean $raw True to get raw database value for editing, false to get rendered value for display.
	 *
	 * @return string
	 */
	public function get_description( $raw = false ) {
		return __( 'Personal access token manually created by the user.', 'oauth2' );
	}

	/**
	 * Get the client's type.
	 *
	 * @return string Type ID if available, or an empty string.
	 */
	public function get_type() {
		return 'private';
	}

	/**
	 * Get the Client Secret Key.
	 *
	 * @return string The Secret Key if available, or an empty string.
	 */
	public function get_secret() {
		return '';
	}

	/**
	 * Get registered URI for the client.
	 *
	 * @return array List of valid redirect URIs.
	 */
	public function get_redirect_uris() {
		return [];
	}

	/**
	 * Check if a redirect URI is valid for the client.
	 *
	 * @param string $uri Supplied redirect URI to check.
	 *
	 * @return boolean Always false: personal tokens do not support redirections.
	 */
	public function check_redirect_uri( $uri ) {
		return false;
	}

	/**
	 * @param WP_User $user
	 *
	 * @return Authorization_Code|WP_Error
	 */
	public function generate_authorization_code( WP_User $user ) {
		return new WP_Error(
			'oauth2.personalclient.no_auth_code',
			__( 'Personal Access Tokens do not support authorization codes.', 'oauth2' )
		);
	}

	/**
	 * Get data stored for an authorization code.
	 *
	 * @param string $code Authorization code to fetch.
	 *
	 * @return Authorization_Code|WP_Error Data if available, error if invalid code.
	 */
	public function get_authorization_code( $code ) {
		return new WP_Error(
			'oauth2.personalclient.no_auth_code',
			__( 'Personal Access Tokens do not support authorization codes.', 'oauth2' )
		);
	}

	/**
	 * @return bool|WP_Error
	 */
	public function regenerate_secret() {
		return new WP_Error(
			'oauth2.personalclient.no_secrets',
			__( 'Personal Access Tokens do not support secrets.', 'oauth2' )
		);
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
		return Access_Token::create( $this, $user, $meta );
	}

	/**
	 * @param array $data
	 *
	 * @return WP_Error|Client Client instance on success, error otherwise.
	 */
	public function update( $data ) {
		return new WP_Error(
			'oauth2.personalclient.no_update',
			__( 'Personal Access Tokens cannot be updated.', 'oauth2' )
		);
	}

	/**
	 * Delete the client.
	 *
	 * @return bool
	 */
	public function delete() {
		return false;
	}

	/**
	 * Approve a client.
	 *
	 * @return bool|WP_Error True if client was updated, error otherwise.
	 */
	public function approve() {
		return new WP_Error(
			'oauth2.personalclient.no_approved',
			__( 'Personal Access Tokens do not have an approval status.', 'oauth2' )
		);
	}
}
