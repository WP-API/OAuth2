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
	 * Refuse the implicit grant for clients that require PKCE.
	 *
	 * The implicit grant issues a token directly and mints no authorization
	 * code, so there is nothing for a PKCE challenge to bind to. Silently
	 * accepting a code_challenge here would give a false sense of protection,
	 * so a client marked as requiring PKCE cannot use this grant at all.
	 *
	 * @param Client $client Client being authorised.
	 * @param array  $request Unslashed request parameters, from $_GET.
	 * @return array|WP_Error
	 */
	protected function gather_extra_params( Client $client, array $request ) {
		if ( $client->is_pkce_required() ) {
			return new WP_Error(
				'oauth2.types.implicit.gather_extra_params.pkce_required',
				__( 'This client requires PKCE, which the implicit grant cannot support. Use the authorization_code grant instead.', 'oauth2' ),
				[ 'error' => 'unauthorized_client' ]
			);
		}

		return [];
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

	/**
	 * Build a URL for reporting an authorisation error back to the client.
	 *
	 * Access tokens are returned in the URL fragment for this grant, so
	 * errors are reported the same way, per RFC 6749 section 4.2.2.1.
	 *
	 * @param string      $redirect_uri Validated redirect URI for the client.
	 * @param string      $error Error code, e.g. `unauthorized_client`.
	 * @param string      $description Human-readable error description.
	 * @param string|null $state State parameter from the original request, if any.
	 * @return string URL to redirect the client to.
	 */
	protected function get_error_redirect_url( $redirect_uri, $error, $description, $state = null ) {
		$args = [
			'error'             => $error,
			'error_description' => $description,
		];
		if ( ! empty( $state ) ) {
			$args['state'] = $state;
		}

		return $redirect_uri . '#' . build_query( $args );
	}
}
