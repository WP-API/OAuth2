<?php
/**
 * Stand-ins for the wp-login.php functions that the consent template calls.
 *
 * @package WP\OAuth2\Tests
 */

namespace {
	if ( ! function_exists( 'login_header' ) ) {
		function login_header( $title = 'Log In', $message = '', $wp_error = null ) {} // phpcs:ignore Universal.NamingConventions.NoReservedKeywordParameterNames,Generic.CodeAnalysis.UnusedFunctionParameter
	}

	if ( ! function_exists( 'login_footer' ) ) {
		function login_footer( $input_id = '' ) {} // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter
	}
}
