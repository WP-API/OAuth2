<?php
/**
 *
 * @package WordPress
 * @subpackage JSON API
 */

namespace WP\OAuth2\Tokens;

/**
 * Get a token by ID.
 *
 * @param string $id Token ID.
 * @return Access_Token|null Token if ID is found, null otherwise.
 */
function get_by_id( $id ) {
	return Access_Token::get_by_id( $id );
}
