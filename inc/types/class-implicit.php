<?php

namespace WP\OAuth2\Types;

use WP\OAuth2\Client;

class Implicit extends Base {

	protected function handle_authorization_submission( $submit, Client $client, $data ) {
		$redirect_uri = $data['redirect_uri'];

		switch ( $submit ) {
			case 'authorize':
				// Generate authorization code and redirect back.
				$code = 'x';
				$redirect_args = array(
					'code' => $code,
				);
				break;

			case 'cancel':
				$redirect_args = array(
					'error' => 'access_denied',
				);
				break;

			default:
				return new WP_Error(
					'oauth2.types.authorization_code.handle_authorisation.invalid_action',
					__( 'Invalid form action.', 'oauth2' )
				);
		}

		if ( ! empty( $data['state'] ) ) {
			$redirect_args['state'] = $data['state'];
		}

		$fragment = build_query( $redirect_args );
		$generated_redirect = $redirect_uri . '#' . $fragment;
		wp_redirect( $generated_redirect );
		exit;
	}

}
