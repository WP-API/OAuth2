<?php
/**
 *
 * @package WordPress
 * @subpackage JSON API
 */

namespace WP\OAuth2\Types;

interface Type {
	public function handle_authorisation();

	/**
	 * Get response_type code for authorisation page.
	 *
	 * This is used to determine which type to route requests to.
	 *
	 * @return string
	 */
	public function get_response_type_code();
}
