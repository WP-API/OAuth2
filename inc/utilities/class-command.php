<?php
/**
 *
 * @package WordPress
 * @subpackage JSON API
 */

namespace WP\OAuth2\Utilities;

use WP\OAuth2\PKCE;
use WP_CLI;
use WP_CLI\Utils;
use WP_CLI_Command;

/**
 * Manage OAuth 2 for WordPress from the command line.
 */
class Command extends WP_CLI_Command {
	/**
	 * Generate a PKCE code verifier and its matching code challenge.
	 *
	 * ## OPTIONS
	 *
	 * [<verifier>]
	 * : Use this code verifier instead of generating a random one.
	 *
	 * [--length=<length>]
	 * : Length of the randomly generated code verifier. Ignored if a verifier is given.
	 * ---
	 * default: 64
	 * ---
	 *
	 * [--method=<method>]
	 * : Code challenge method to derive the challenge with.
	 * ---
	 * default: S256
	 * options:
	 *   - S256
	 *   - plain
	 * ---
	 *
	 * [--format=<format>]
	 * : Render output in a particular format.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 *   - csv
	 *   - yaml
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp oauth2 generate-code-challenge
	 *     wp oauth2 generate-code-challenge --method=plain
	 *
	 * @alias generate-code-challenge
	 *
	 * @param array $args Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 */
	public function generate_code_challenge( $args, $assoc_args ) {
		$method = $assoc_args['method'];

		if ( ! empty( $args[0] ) ) {
			$verifier = $args[0];

			if ( ! PKCE::is_valid_verifier( $verifier ) ) {
				WP_CLI::error( 'The supplied verifier must be 43-128 characters from [A-Za-z0-9-._~].' );
			}
		} else {
			$length = (int) $assoc_args['length'];
			if ( $length < PKCE::VERIFIER_MIN_LENGTH || $length > PKCE::VERIFIER_MAX_LENGTH ) {
				WP_CLI::error( sprintf( 'Length must be between %d and %d.', PKCE::VERIFIER_MIN_LENGTH, PKCE::VERIFIER_MAX_LENGTH ) );
			}

			$verifier = PKCE::generate_verifier( $length );
		}

		$challenge = PKCE::derive_challenge( $verifier, $method );

		$items = [
			[
				'code_verifier'         => $verifier,
				'code_challenge'        => $challenge,
				'code_challenge_method' => $method,
			],
		];

		Utils\format_items( $assoc_args['format'], $items, [ 'code_verifier', 'code_challenge', 'code_challenge_method' ] );
	}
}
