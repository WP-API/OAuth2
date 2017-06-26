<?php

namespace WP\OAuth2\Types;

use WP_Http;
use WP\OAuth2\Client;

class AuthorizationCode extends Base {
	/**
	 * Get response_type code for authorisation page.
	 *
	 * This is used to determine which type to route requests to.
	 *
	 * @return string
	 */
	public function get_response_type_code() {
		return 'code';
	}

	protected function handle_authorization_submission( $submit, Client $client, $data ) {
		$redirect_uri = $data['redirect_uri'];

		switch ( $submit ) {
			case 'authorize':
				// Generate authorization code and redirect back.
				$code = $client->generate_authorization_code();
				if ( is_wp_error( $code ) ) {
					return $code;
				}

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

		$generated_redirect = add_query_arg( urlencode_deep( $redirect_args ), $redirect_uri );
		wp_redirect( $generated_redirect );
		exit;
	}
}
