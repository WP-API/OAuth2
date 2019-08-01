<?php
/**
 *
 * @package WordPress
 * @subpackage JSON API
 */

namespace WP\OAuth2\Admin\Profile\PersonalTokens;

use WP\OAuth2\PersonalClient;
use WP\OAuth2\Tokens\Access_Token;
use WP_Error;
use WP_User;

const ACCESS_TOKENS_PAGE_SLUG = 'oauth2_personal_tokens';

/**
 *
 */
function bootstrap() {
	// Personal Access Tokens page.
	add_action( 'admin_action_' . ACCESS_TOKENS_PAGE_SLUG, __NAMESPACE__ . '\\render_page' );
}

/**
 * Get the token page URL.
 *
 * @return string
 */
function get_page_url( $args = [] ) {
	$url            = admin_url( 'profile.php' );
	$args['action'] = ACCESS_TOKENS_PAGE_SLUG;
	$url            = add_query_arg( urlencode_deep( $args ), $url );
	return $url;
}

/**
 * Bootstrap the profile page.
 *
 * This sets up the globals for the user page.
 */
function bootstrap_profile_page() {
	global $user_id, $submenu_file, $parent_file;
	$user_id = null;
	if ( ! empty( $_REQUEST['user_id'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$user_id = absint( $_REQUEST['user_id'] ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
	}

	$current_user = wp_get_current_user();
	if ( ! defined( 'IS_PROFILE_PAGE' ) ) {
		define( 'IS_PROFILE_PAGE', $user_id === $current_user->ID );
	}

	if ( ! $user_id && IS_PROFILE_PAGE ) {
		$user_id = $current_user->ID;
	}

	$user = get_user_by( 'id', $user_id );
	if ( empty( $user ) ) {
		wp_die( esc_html__( 'Invalid user ID.' ) );
	}
	if ( ! current_user_can( 'edit_user', $user_id ) ) {
		wp_die( esc_html__( 'Sorry, you are not allowed to edit this user.' ) );
	}

	if ( current_user_can( 'edit_users' ) && ! IS_PROFILE_PAGE ) {
		$submenu_file = 'users.php'; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
	} else {
		$submenu_file = 'profile.php'; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
	}

	if ( current_user_can( 'edit_users' ) ) {
		$parent_file = 'users.php'; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
	} else {
		$parent_file = 'profile.php'; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
	}
}

/**
 * Render the access token creation page.
 */
function render_page() {
	bootstrap_profile_page();

	$user = get_user_by( 'id', $GLOBALS['user_id'] );

	if ( isset( $_POST['oauth2_action'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
		$error = handle_page_action( $user );

		if ( is_wp_error( $error ) ) {
			add_action(
				'all_admin_notices',
				function () use ( $error ) {
					echo '<div class="error"><p>' . esc_html( $error->get_error_message() ) . '</p></div>';
				}
			);
		}
	}

	$GLOBALS['title'] = __( 'Personal Access Tokens', 'oauth2' ); // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
	require ABSPATH . 'wp-admin/admin-header.php';

	$tokens = Access_Token::get_for_user( $user );
	$tokens = array_filter(
		$tokens,
		function ( Access_Token $token ) {
			$client = $token->get_client();
			return ! empty( $client ) && $client instanceof PersonalClient;
		}
	);
	?>
	<div class="wrap" id="profile-page">
		<h1><?php esc_html_e( 'Create a Personal Access Token', 'oauth2' ); ?></h1>

		<p><?php esc_html_e( "The WordPress API allows access to your site by external applications. Personal access tokens allow easy access for personal scripts, command line utilities, or during development. Generally, you shouldn't provide these to applications you don't trust, and you should treat them just like passwords.", 'oauth2' ); ?></p>

		<form action="" method="POST">
			<table class="form-table">
				<tr>
					<th scope="row">
						<label for="token-name">Token name</label>
					</th>
					<td>
						<input
							class="regular-text"
							id="token-name"
							name="name"
							required="required"
							type="text"
						/>

						<p class="description"><?php esc_html_e( 'Give this token a name so you can easily identify it later.', 'oauth2' ); ?></p>
					</td>
				</tr>
			</table>

			<input type="hidden" name="oauth2_action" value="create" />

			<?php wp_nonce_field( 'oauth2_personal_tokens.create' ); ?>

			<p class="buttons">
				<button class="button-primary"><?php esc_html_e( 'Generate Token', 'oauth2' ); ?></button>
			</p>
		</form>
	</div>
	<?php
	require ABSPATH . 'wp-admin/admin-footer.php';
	exit;
}

/**
 * Handle action from a form.
 */
function handle_page_action( WP_User $user ) {
	if ( ! isset( $_POST['oauth2_action'] ) ) {
		return new WP_Error(
			'rest_oauth2_invalid_action',
			__( 'Invalid action.', 'oauth2' )
		);
	}

	$action = sanitize_text_field( wp_unslash( $_POST['oauth2_action'] ) );

	switch ( $action ) {
		case 'create':
			check_admin_referer( 'oauth2_personal_tokens.create' );
			if ( empty( $_POST['name'] ) ) {
				return new WP_Error(
					'rest_oauth2_missing_name',
					__( 'Missing name for personal access token.', 'oauth2' )
				);
			}

			$name = sanitize_text_field( wp_unslash( $_POST['name'] ) );
			return handle_create( $user, $name );

		default:
			return new WP_Error(
				'rest_oauth2_invalid_action',
				__( 'Invalid action.', 'oauth2' )
			);
	}
}

/**
 * Handle token creation
 */
function handle_create( WP_User $user, $name ) {
	$client = PersonalClient::get_instance();
	$meta   = [
		'name' => $name,
	];
	$token  = $client->issue_token( $user, $meta );

	render_create_success( $user, $token );
}

/**
 * @param WP_User $user
 * @param         $token
 */
function render_create_success( WP_User $user, $token ) {
	$GLOBALS['title'] = __( 'Personal Access Tokens', 'oauth2' ); // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
	require ABSPATH . 'wp-admin/admin-header.php';
	?>

	<div class="wrap" id="profile-page">
		<h1><?php esc_html_e( 'Token created!', 'oauth2' ); ?></h1>
		<p><?php esc_html_e( "Your token has been created. Make sure to copy it now, as it won't be displayed again!", 'oauth2' ); ?></p>

		<pre style="font-size: 2em"><?php echo esc_html( $token->get_key() ); ?></pre>

		<p><a href="<?php echo esc_url( get_edit_user_link( $user->ID ) ); ?>"><?php esc_html_e( 'Back to profile', 'oauth2' ); ?></a></p>
	</div>

	<?php
	require ABSPATH . 'wp-admin/admin-footer.php';
	exit;
}
