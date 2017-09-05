<?php

namespace WP\OAuth2\Utilities;

class Oauth2_Wp_Cli extends \WP_CLI_Command {
	/**
	* Generate a code challenge.
	*
	* ## OPTIONS
	*
	* [<random_string>]
	* : The string to be hashed.
	*
	*
	* [--length=<length>]
	* : The length of the random seed string.
	* ---
	* default: 64
	* ---
	*
	* ## EXAMPLES
	*
	*     wp oauth2 generate-code-challenge --length=64
	*
	* @alias generate-code-challenge
	*/
	function generate_code_challenge( $args, $assoc_args ) {
		if ( ! empty( $args[0] ) && ! empty( $assoc_args['length'] ) ) {
			\WP_CLI::warning( 'Length parameter will be ignored since the input string was provided.' );
		}

		$length = empty( $assoc_args['length'] ) ? 64 : intval( $assoc_args['length'] );

		if ( $length < 43 || $length > 128 ) {
			\WP_CLI::error( 'Length should be >= 43 and <= 128.' );
		}

		if ( ! empty( $args[0] ) ) {
			$random_seed = $args[0];

			if ( strlen( $random_seed ) < 43 || strlen( $random_seed ) > 128 ) {
				\WP_CLI::error( 'Length of the provided random seed should be >= 43 and <= 128.' );
			}

			\WP_CLI::warning( "Using provided string {$random_seed} as a random seed. It is recommended to use this command without parameters, 64 characters long random key will be generated automatically." );
		} else {
			$is_strong_crypto = true;
			$random_seed = \bin2hex( \openssl_random_pseudo_bytes( $length / 2 + $length % 2, $is_strong_crypto ) );
			$random_seed = \substr( $random_seed, 0, $length );

			if ( ! $is_strong_crypto ) {
				\WP_CLI::error( 'openssl_random_pseudo_bytes failed to generate a cryptographically strong random string.' );
			}
		}

		$code_challenge = \base64_encode( hash( 'sha256', $random_seed ) );

		$items = [
			[
				'code_verifier' => $random_seed,
				'code_challenge = base64( sha256( code_verifier ) )' => $code_challenge,
			],
		];

		\WP_CLI\Utils\format_items( 'table', $items, [ 'code_verifier', 'code_challenge = base64( sha256( code_verifier ) )' ] );
	}
}
