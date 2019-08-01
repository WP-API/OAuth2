<?php
/**
 * Administration UI and utilities
 *
 * @package    WordPress
 * @subpackage JSON API
 */

namespace WP\OAuth2\Admin\Profile;

use WP\OAuth2\PersonalClient;
use WP\OAuth2\Tokens\Access_Token;
use WP_User;

/**
 * Bootstrap actions for the profile screen.
 */
function bootstrap() {
	add_action( 'show_user_profile', __NAMESPACE__ . '\\render_profile_section' );
	add_action( 'edit_user_profile', __NAMESPACE__ . '\\render_profile_section' );
	add_action( 'all_admin_notices', __NAMESPACE__ . '\\output_profile_messages' );
	add_action( 'personal_options_update', __NAMESPACE__ . '\\handle_revocation', 10, 1 );
	add_action( 'edit_user_profile_update', __NAMESPACE__ . '\\handle_revocation', 10, 1 );

	PersonalTokens\bootstrap();
}

/**
 * Render current tokens for a user.
 *
 * @param WP_User $user User whose profile is being rendered.
 */
function render_profile_section( WP_User $user ) {
	$tokens = Access_Token::get_for_user( $user );
	$tokens = array_filter(
		$tokens,
		function ( Access_Token $token ) {
			return (bool) $token->get_client();
		}
	);

	if ( ! IS_PROFILE_PAGE ) {
		$personal_url = PersonalTokens\get_page_url( [ 'user_id' => $user->ID ] );
	} else {
		$personal_url = PersonalTokens\get_page_url();
	}

	?>
	<h2><?php esc_html_e( 'Authorized Applications', 'oauth2' ); ?></h2>
	<?php if ( ! empty( $tokens ) ) : ?>
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
				render_token_row( $user, $token );
			}
			?>
			</tbody>
			<tfoot>
			<tr>
				<td colspan="2">
					<a href="<?php echo esc_url( $personal_url ); ?>">
						<?php esc_html_e( 'Create personal access token', 'oauth2' ); ?>
					</a>
				</td>
			</tr>
			</tfoot>
		</table>
	<?php else : ?>
		<p class="description"><?php esc_html_e( 'No applications authorized.', 'oauth2' ); ?></p>
		<p>
			<a href="<?php echo esc_url( $personal_url ); ?>"><?php esc_html_e( 'Create personal access token', 'oauth2' ); ?></a>
		</p>
	<?php endif ?>
	<?php
}

/**
 *  Render a single row.
 *
 * @param WP_User      $user
 * @param Access_Token $token
 */
function render_token_row( WP_User $user, Access_Token $token ) {
	$client      = $token->get_client();
	$is_personal = $client instanceof PersonalClient;

	if ( $is_personal ) {
		$token_name = $token->get_meta( 'name', __( 'Unknown Token', 'oauth2' ) );
	}

	$creation_time = $token->get_creation_time();
	$details       = [
		sprintf(
			/* translators: %1$s: formatted date, %2$s: formatted time */
			esc_html__( 'Authorized %1$s at %2$s', 'oauth2' ),
			date( get_option( 'date_format' ), $creation_time ),
			date( get_option( 'time_format' ), $creation_time )
		),
	];

	/**
	 * Filter details shown for an access token on the profile screen.
	 *
	 * @param string[]     $details List of HTML snippets to render in table.
	 * @param Access_Token $token   Token being displayed.
	 * @param WP_User      $user    User whose profile is being rendered.
	 */
	$details = apply_filters( 'oauth2.admin.profile.render_token_row.details', $details, $token, $user );

	// Build actions.
	if ( $is_personal ) {
		$button_title = sprintf(
			/* translators: %s: personal token name */
			__( 'Revoke personal token "%s"', 'oauth2' ),
			esc_html( $token_name )
		);
	} else {
		$button_title = sprintf(
			/* translators: %s: app name */
			__( 'Revoke access for "%s"', 'oauth2' ),
			$client->get_name()
		);
	}

	$actions = [
		sprintf(
			'<button class="button" name="oauth2_revoke" title="%s" value="%s">%s</button>',
			esc_attr( $button_title ),
			wp_create_nonce( 'oauth2_revoke:' . $token->get_key() ) . ':' . esc_attr( $token->get_key() ),
			esc_html__( 'Revoke', 'oauth2' )
		),
	];

	/**
	 * Filter actions shown for an access token on the profile screen.
	 *
	 * @param string[]     $actions List of HTML snippets to render in table.
	 * @param Access_Token $token   Token being displayed.
	 * @param WP_User      $user    User whose profile is being rendered.
	 */
	$actions = apply_filters( 'oauth2.admin.profile.render_token_row.actions', $actions, $token, $user );

	$name = sprintf( '<strong>%s</strong>', $client->get_name() );
	if ( $is_personal ) {
		$name = sprintf(
			'<strong>%s</strong> <em>(%s)</em>',
			esc_html( $token_name ),
			$client->get_name()
		);
	}
	?>
	<tr>
		<td>
			<p><?php echo $name; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?></p>
			<p><?php echo implode( ' | ', $details ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?></p>
		</td>
		<td style="vertical-align: middle">
			<?php echo implode( '', $actions ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
		</td>
	</tr>
	<?php
}

/**
 * Output messages based on previous actions.
 */
function output_profile_messages() {
	global $pagenow;
	if ( 'profile.php' !== $pagenow && 'user-edit.php' !== $pagenow ) {
		return;
	}

	if ( ! empty( $_GET['oauth2_revoked'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		echo '<div id="message" class="updated"><p>' . esc_html__( 'Token revoked.', 'oauth2' ) . '</p></div>';
	}
	if ( ! empty( $_GET['oauth2_revocation_failed'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		echo '<div id="message" class="updated"><p>' . esc_html__( 'Unable to revoke token.', 'oauth2' ) . '</p></div>';
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

	$data = sanitize_text_field( wp_unslash( $_POST['oauth2_revoke'] ) );
	if ( strpos( $data, ':' ) === null ) {
		return;
	}

	// Split out nonce and check it.
	list( $nonce, $key ) = explode( ':', $data, 2 );
	if ( ! wp_verify_nonce( $nonce, 'oauth2_revoke:' . $key ) ) {
		wp_nonce_ays( 'oauth2_revoke' );
		die();
	}

	$token = Access_Token::get_by_id( $key );
	if ( empty( $token ) ) {
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
