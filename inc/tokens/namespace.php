<?php

namespace WP\OAuth2\Tokens;

function get_by_id( $id ) {
	return Access_Token::get_by_id( $id );
}
