<?php
/**
 * Plugin Name: OAuth 2 for WordPress
 * Description: Connect apps to your site using OAuth 2.
 * Version: 0.1.0
 * Author: WordPress Core Contributors (REST API Focus)
 * Author URI: https://make.wordpress.org/core/
 * Text Domain: oauth2
 */

namespace WP\OAuth2;

require __DIR__ . '/inc/namespace.php';
require __DIR__ . '/inc/class-client.php';
require __DIR__ . '/inc/class-scopes.php';
require __DIR__ . '/inc/authentication/namespace.php';
require __DIR__ . '/inc/endpoints/namespace.php';
require __DIR__ . '/inc/endpoints/class-authorization.php';
require __DIR__ . '/inc/endpoints/class-token.php';
require __DIR__ . '/inc/tokens/namespace.php';
require __DIR__ . '/inc/tokens/class-token.php';
require __DIR__ . '/inc/tokens/class-access-token.php';
require __DIR__ . '/inc/tokens/class-authorization-code.php';
require __DIR__ . '/inc/types/class-type.php';
require __DIR__ . '/inc/types/class-base.php';
require __DIR__ . '/inc/types/class-authorization-code.php';
require __DIR__ . '/inc/types/class-implicit.php';
require __DIR__ . '/inc/admin/namespace.php';
require __DIR__ . '/inc/admin/profile/namespace.php';

if ( defined( 'WP_CLI' ) && WP_CLI ) {
	require __DIR__ . '/inc/utilities/class-command.php';
}

bootstrap();
