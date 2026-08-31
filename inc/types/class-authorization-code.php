<?php
/**
 *
 * @package WordPress
 * @subpackage JSON API
 */

namespace WP\OAuth2\Types;

use WP_Error;
use WP\OAuth2\Client;
use WP\OAuth2\PKCE;

class Authorization_Code extends Base {
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

	/**
	 * Gather and validate PKCE parameters from the authorisation request.
	 *
	 * @param Client $client Client being authorised.
	 * @param array  $request Unslashed request parameters, from $_GET.
	 * @return array|WP_Error `code_challenge`/`code_challenge_method` to carry
	 *                        through to the minted code, or an error.
	 */
	protected function gather_extra_params( Client $client, array $request ) {
		$code_challenge        = isset( $request['code_challenge'] ) && is_string( $request['code_challenge'] ) ? $request['code_challenge'] : null;
		$code_challenge_method = isset( $request['code_challenge_method'] ) && is_string( $request['code_challenge_method'] ) ? $request['code_challenge_method'] : null;

		if ( null === $code_challenge ) {
			if ( $client->is_pkce_required() ) {
				return new WP_Error(
					'oauth2.types.authorization_code.gather_extra_params.pkce_required',
					__( 'This client requires a code_challenge for the authorization_code grant.', 'oauth2' ),
					[ 'error' => 'invalid_request' ]
				);
			}

			return [];
		}

		// The method defaults to 'plain' when omitted, per RFC 7636 section 4.3.
		if ( null === $code_challenge_method ) {
			$code_challenge_method = PKCE::METHOD_PLAIN;
		}

		if ( ! in_array( $code_challenge_method, PKCE::supported_methods(), true ) ) {
			return new WP_Error(
				'oauth2.types.authorization_code.gather_extra_params.unsupported_method',
				__( 'Unsupported code_challenge_method. Note that this value is case-sensitive; use S256.', 'oauth2' ),
				[ 'error' => 'invalid_request' ]
			);
		}

		if ( ! PKCE::is_valid_challenge( $code_challenge, $code_challenge_method ) ) {
			return new WP_Error(
				'oauth2.types.authorization_code.gather_extra_params.invalid_challenge',
				__( 'Invalid code_challenge.', 'oauth2' ),
				[ 'error' => 'invalid_request' ]
			);
		}

		if ( $client->is_pkce_required() ) {
			/**
			 * Filter the code_challenge_method values that satisfy a client's PKCE requirement.
			 *
			 * Defaults to S256 only. `plain` offers no protection against a
			 * malicious app on the same device reading the authorization
			 * request, which is exactly the threat PKCE exists to mitigate
			 * for public clients (RFC 9700 section 2.1.1), so it does not
			 * satisfy a requirement even though it remains an accepted method.
			 *
			 * @param string[] $methods Methods that satisfy "PKCE required".
			 */
			$required_methods = apply_filters( 'oauth2.pkce.required_methods', [ PKCE::METHOD_S256 ] );
			if ( ! in_array( $code_challenge_method, $required_methods, true ) ) {
				return new WP_Error(
					'oauth2.types.authorization_code.gather_extra_params.weak_method',
					__( 'This client requires PKCE with the S256 code_challenge_method.', 'oauth2' ),
					[ 'error' => 'invalid_request' ]
				);
			}
		}

		return [
			'code_challenge'        => $code_challenge,
			'code_challenge_method' => $code_challenge_method,
		];
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
				// Generate authorization code and redirect back.
				$user = wp_get_current_user();
				$code = $client->generate_authorization_code( $user, $data );
				if ( is_wp_error( $code ) ) {
					return $code;
				}

				// Defends against a third-party Client subclass overriding
				// generate_authorization_code() with the pre-PKCE arity,
				// which would silently mint a code with no challenge.
				if ( ! empty( $data['code_challenge'] ) && $code->get_code_challenge() !== $data['code_challenge'] ) {
					$code->delete();
					wp_safe_redirect(
						$this->get_error_redirect_url(
							$redirect_uri,
							'server_error',
							__( 'Could not persist the PKCE challenge for this authorization code.', 'oauth2' ),
							! empty( $data['state'] ) ? $data['state'] : null
						)
					);
					exit;
				}

				$redirect_args = [
					'code' => $code->get_code(),
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

		$generated_redirect = add_query_arg( urlencode_deep( $redirect_args ), $redirect_uri );
		// phpcs:ignore WordPress.Security.SafeRedirect -- Intentionally external redirect, secured via client registration.
		wp_redirect( $generated_redirect );
		exit;
	}
}
