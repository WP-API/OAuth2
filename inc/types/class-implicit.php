<?php
/**
 *
 * @package WordPress
 * @subpackage JSON API
 */

namespace WP\OAuth2\Types;

use WP_Error;
use WP\OAuth2\Client;

class Implicit extends Base {
	/**
	 * Get response_type code for authorisation page.
	 *
	 * This is used to determine which type to route requests to.
	 *
	 * @return string
	 */
	public function get_response_type_code() {
		return 'token';
	}

	/**
	 * Handles the authorization.
	 *
	 * @param string $submit
	 * @param Client $client
	 * @param array  $data
	 *
	 * @return WP_Error
	 */
	protected function handle_authorization_submission( $submit, Client $client, $data ) {
		$redirect_uri = $data['redirect_uri'];

		switch ( $submit ) {
			case 'authorize':
				// Generate token and redirect back.
				$user  = wp_get_current_user();
				$token = $client->issue_token( $user );
				if ( is_wp_error( $token ) ) {
					return $token;
				}

				$redirect_args = [
					'access_token' => $token->get_key(),
					'token_type'   => 'bearer',
				];
				break;

			case 'cancel':
				$redirect_args = [
					'error' => 'access_denied',
				];
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

		$redirect_args = $this->filter_redirect_args(
			$redirect_args,
			'authorize' === $submit,
			$client,
			$data
		);

		$fragment           = build_query( $redirect_args );
		$generated_redirect = $redirect_uri . '#' . $fragment;
		wp_safe_redirect( $generated_redirect );
		exit;
	}

}
