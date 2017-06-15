<?php

namespace WP\OAuth2\Types;

class Implicit implements Type {

	function handle_authorisation() {
		return true;
	}

}
