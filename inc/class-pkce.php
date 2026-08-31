<?php
/**
 *
 * @package WordPress
 * @subpackage JSON API
 */

namespace WP\OAuth2;

/**
 * Proof Key for Code Exchange (PKCE) helpers, per RFC 7636.
 *
 * Kept as a single set of static methods so the transform is written once,
 * rather than duplicated between the authorisation endpoint, the token
 * endpoint, and the WP-CLI helper command.
 */
class PKCE {
	const METHOD_S256  = 'S256';
	const METHOD_PLAIN = 'plain';

	const VERIFIER_MIN_LENGTH = 43;
	const VERIFIER_MAX_LENGTH = 128;

	/**
	 * Get the challenge methods this site supports.
	 *
	 * @return string[] Supported `code_challenge_method` values.
	 */
	public static function supported_methods() {
		/**
		 * Filter the PKCE code challenge methods this site accepts.
		 *
		 * Comparisons against these values are case-sensitive, per RFC 7636
		 * section 4.3.
		 *
		 * @param string[] $methods Supported `code_challenge_method` values.
		 */
		return apply_filters( 'oauth2.pkce.supported_methods', [ static::METHOD_S256, static::METHOD_PLAIN ] );
	}

	/**
	 * Derive a code challenge from a verifier, for a given transform method.
	 *
	 * @param string $verifier Code verifier.
	 * @param string $method Challenge method, `S256` or `plain`. Case-sensitive.
	 *
	 * @return string|null Derived challenge, or null if the method is not recognised.
	 */
	public static function derive_challenge( $verifier, $method ) {
		if ( ! is_string( $verifier ) ) {
			return null;
		}

		switch ( $method ) {
			case static::METHOD_S256:
				return rtrim( strtr( base64_encode( hash( 'sha256', $verifier, true ) ), '+/', '-_' ), '=' ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode

			case static::METHOD_PLAIN:
				return $verifier;

			default:
				return null;
		}
	}

	/**
	 * Verify a code verifier against a stored code challenge.
	 *
	 * Fails closed: an unsupported method, or a non-string input, returns
	 * false rather than raising a warning or a TypeError from hash_equals().
	 *
	 * @param string $verifier Code verifier supplied at the token endpoint.
	 * @param string $challenge Code challenge stored at authorization time.
	 * @param string $method Challenge method the challenge was derived with.
	 *
	 * @return bool Whether the verifier produces the given challenge.
	 */
	public static function verify( $verifier, $challenge, $method ) {
		if ( ! is_string( $verifier ) || ! is_string( $challenge ) ) {
			return false;
		}

		$derived = static::derive_challenge( $verifier, $method );
		if ( null === $derived ) {
			return false;
		}

		return hash_equals( $challenge, $derived );
	}

	/**
	 * Check whether a string is a valid PKCE code verifier.
	 *
	 * Per RFC 7636 section 4.1: 43-128 characters from the unreserved URI
	 * character set [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~".
	 *
	 * @param mixed $verifier Value to check.
	 *
	 * @return bool
	 */
	public static function is_valid_verifier( $verifier ) {
		if ( ! is_string( $verifier ) ) {
			return false;
		}

		return (bool) preg_match( '/^[A-Za-z0-9\-._~]{' . static::VERIFIER_MIN_LENGTH . ',' . static::VERIFIER_MAX_LENGTH . '}\z/', $verifier );
	}

	/**
	 * Check whether a string is a valid code challenge for the given method.
	 *
	 * `S256` challenges are base64url (unpadded) of a 32-byte SHA-256 digest,
	 * which is always exactly 43 characters from a narrower alphabet than the
	 * verifier's. `plain` challenges are just verifiers, so the verifier's
	 * character set and length range apply directly.
	 *
	 * @param mixed  $challenge Value to check.
	 * @param string $method Challenge method, `S256` or `plain`. Case-sensitive.
	 *
	 * @return bool
	 */
	public static function is_valid_challenge( $challenge, $method ) {
		if ( ! is_string( $challenge ) ) {
			return false;
		}

		if ( static::METHOD_S256 === $method ) {
			return (bool) preg_match( '/^[A-Za-z0-9\-_]{43}\z/', $challenge );
		}

		if ( static::METHOD_PLAIN === $method ) {
			return static::is_valid_verifier( $challenge );
		}

		return false;
	}

	/**
	 * Generate a random code verifier.
	 *
	 * @param int $length Desired length, 43-128. Default 64.
	 *
	 * @return string Randomly generated code verifier.
	 */
	public static function generate_verifier( $length = 64 ) {
		$length = max( static::VERIFIER_MIN_LENGTH, min( static::VERIFIER_MAX_LENGTH, (int) $length ) );

		// Base64url-encode more bytes than needed, then trim to length, so the
		// result is uniformly distributed over the unreserved character set.
		$bytes    = random_bytes( $length );
		$verifier = rtrim( strtr( base64_encode( $bytes ), '+/', '-_' ), '=' ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode

		return substr( $verifier, 0, $length );
	}
}
