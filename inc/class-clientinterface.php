<?php
/**
 *
 * @package    WordPress
 * @subpackage JSON API
 */

namespace WP\OAuth2;

use WP_User;

interface ClientInterface {
	/**
	 * Get the client's ID.
	 *
	 * @return string Client ID.
	 */
	public function get_id();

	/**
	 * Get the client's name.
	 *
	 * @return string HTML string.
	 */
	public function get_name();

	/**
	 * Get the client's description.
	 *
	 * @param boolean $raw True to get raw database value for editing, false to get rendered value for display.
	 *
	 * @return string
	 */
	public function get_description( $raw = false );

	/**
	 * Get the client's type.
	 *
	 * @return string Type ID if available, or an empty string.
	 */
	public function get_type();

	/**
	 * Get the Client Secret Key.
	 *
	 * @return string The Secret Key if available, or an empty string.
	 */
	public function get_secret();

	/**
	 * Get registered URI for the client.
	 *
	 * @return array List of valid redirect URIs.
	 */
	public function get_redirect_uris();

	/**
	 * Check if a redirect URI is valid for the client.
	 *
	 * @param string $uri Supplied redirect URI to check.
	 *
	 * @return boolean True if the URI is valid, false otherwise.
	 * @todo Implement this properly :)
	 *
	 */
	public function check_redirect_uri( $uri );

	/**
	 * @param WP_User $user
	 *
	 * @return Authorization_Code|WP_Error
	 */
	public function generate_authorization_code( WP_User $user );

	/**
	 * Get data stored for an authorization code.
	 *
	 * @param string $code Authorization code to fetch.
	 *
	 * @return Authorization_Code|WP_Error Data if available, error if invalid code.
	 */
	public function get_authorization_code( $code );

	/**
	 * @return bool|WP_Error
	 */
	public function regenerate_secret();

	/**
	 * Issue token for a user.
	 *
	 * @param \WP_User $user
	 * @param array    $meta
	 *
	 * @return Access_Token
	 */
	public function issue_token( WP_User $user, $meta = [] );

	/**
	 * @param array $data
	 *
	 * @return WP_Error|Client Client instance on success, error otherwise.
	 */
	public function update( $data );

	/**
	 * Delete the client.
	 *
	 * @return bool
	 */
	public function delete();

	/**
	 * Approve a client.
	 *
	 * @return bool|WP_Error True if client was updated, error otherwise.
	 */
	public function approve();
}
