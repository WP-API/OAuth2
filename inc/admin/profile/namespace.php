<?php
/**
 * Administration UI and utilities
 */

namespace WP\OAuth2\Admin\Profile;

use WP\OAuth2\Tokens\Access_Token;
use WP_User;

/**
 * Bootstrap actions for the profile screen.
 */
function bootstrap() {
	add_action( 'personal_options', __NAMESPACE__ . '\\render_profile_section', 50 );
	add_action( 'all_admin_notices', __NAMESPACE__ . '\\output_profile_messages' );
	add_action( 'personal_options_update',  __NAMESPACE__ . '\\handle_revocation', 10, 1 );
	add_action( 'edit_user_profile_update', __NAMESPACE__ . '\\handle_revocation', 10, 1 );
}

/**
 * Render current tokens for a user.
 *
 * @param WP_User $user User whose profile is being rendered.
 */
function render_profile_section( WP_User $user ) {
	$tokens = Access_Token::get_for_user( $user );
	?>
		<table class="form-table">
			<tbody>
			<tr>
				<th scope="row"><?php _e( 'Authorized Applications', 'oauth2' ) ?></th>
				<td>
					<?php if ( ! empty( $tokens ) ): ?>
						<table class="widefat">
							<thead>
							<tr>
								<th style="padding-left:10px;"><?php esc_html_e( 'Application Name', 'oauth2' ); ?></th>
								<th></th>
							</tr>
							</thead>
							<tbody>
							<?php
							foreach ( $tokens as $token ) {
								render_token_row( $token );
							}
							?>
							</tbody>
						</table>
					<?php else: ?>
						<p class="description"><?php esc_html_e( 'No applications authorized.', 'oauth2' ) ?></p>
					<?php endif ?>
				</td>
			</tr>
			</tbody>
		</table>
	<?php
}

/**
 * Render a single row.
 */
function render_token_row( Access_Token $token ) {
	$client = $token->get_client();

	$details = [
		sprintf(
			/* translators: %s: formatted date */
			esc_html__( 'Authorized %s', 'oauth2' ),
			date( get_option( 'date_format' ), $token->get_creation_time() )
		),
	];
	$button_title = sprintf(
		/* translators: %s: app name */
		__( 'Revoke access for "%s"', 'oauth2' ),
		$client->get_name()
	);
	?>
	<tr>
		<td>
			<p><strong><?php echo $client->get_name() ?></strong></p>
			<p><?php echo implode( ' | ', $details ) ?></p>
		</td>
		<td style="vertical-align: middle">
			<button
				class="button"
				name="oauth2_revoke"
				value="<?php echo esc_attr( $token->get_key() ) ?>"
				title="<?php echo esc_attr( $button_title ) ?>"
			>
				<?php esc_html_e( 'Revoke', 'oauth2' ) ?>
			</button>
		</td>
	</tr>
	<?php
}

/**
 * Output messages based on previous actions.
 */
function output_profile_messages() {
	global $pagenow;
	if ( $pagenow !== 'profile.php' && $pagenow !== 'user-edit.php' ) {
		return;
	}

	if ( ! empty( $_GET['oauth2_revoked'] ) ) {
		echo '<div id="message" class="updated"><p>' . __( 'Token revoked.', 'oauth2' ) . '</p></div>';
	}
	if ( ! empty( $_GET['oauth2_revocation_failed'] ) ) {
		echo '<div id="message" class="updated"><p>' . __( 'Unable to revoke token.', 'oauth2' ) . '</p></div>';
	}
}

/**
 * Handle a revocation.
 *
 * @param int $user_id
 */
function handle_revocation( $user_id ) {
	if ( empty( $_POST['oauth2_revoke'] ) ) {
		return;
	}

	$key = wp_unslash( $_POST['oauth2_revoke'] );
	$token = Access_Token::get_by_id( $key );
	if ( empty( $token ) ) {
		var_dump( $key, $token );
		wp_safe_redirect( add_query_arg( 'oauth2_revocation_failed', true, get_edit_user_link( $user_id ) ) );
		exit;
	}

	// Check it's for the right user.
	if ( $token->get_user_id() !== $user_id ) {
		wp_die();
	}

	$result = $token->revoke();
	if ( is_wp_error( $result ) ) {
		wp_safe_redirect( add_query_arg( 'oauth2_revocation_failed', true, get_edit_user_link( $user_id ) ) );
		exit;
	}

	// Success, redirect and tell the user.
	wp_safe_redirect( add_query_arg( 'oauth2_revoked', $key, get_edit_user_link( $user_id ) ) );
	exit;
}
