<?php
/**
 * OAuth 2 for WordPress
 *
 * @package     WordPress
 * @subpackage  JSON API
 * @author      Squiz Pty Ltd <products@squiz.net>
 * @copyright   2019 Squiz Pty Ltd (ABN 77 084 670 600)
 * @license     GPL-2.0-or-later
 *
 * @oauth2
 * Plugin Name: OAuth 2 for WordPress
 * Plugin URI:  https://github.com/WP-API/OAuth2
 * Description: Connect apps to your site using OAuth 2.
 * Version:     0.2.0
 * Author:      WordPress Core Contributors (REST API Focus)
 * Author URI:  https://make.wordpress.org/core/
 * License:     GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: oauth2
 * Domain Path: /languages
 * Requires at least:  4.8
 * Requires PHP: 5.6
 */

namespace WP\OAuth2;

// Avoid loading twice if loaded via App Connect.
if ( class_exists( 'WP\\OAuth2\\Client' ) ) {
	return;
}

require __DIR__ . '/inc/namespace.php';
require __DIR__ . '/inc/class-clientinterface.php';
require __DIR__ . '/inc/class-client.php';
require __DIR__ . '/inc/class-personalclient.php';
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
require __DIR__ . '/inc/admin/profile/personaltokens/namespace.php';

bootstrap();
