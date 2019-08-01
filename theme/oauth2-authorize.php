<?php
/**
 *
 * @package WordPress
 * @subpackage JSON API
 */

/** @var \WP\OAuth2\Client $client */

login_header(
	__( 'Authorize', 'oauth2' ),
	'',
	$errors
);

$_current_user = wp_get_current_user();

$url = $_SERVER['REQUEST_URI']; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput

?>

<style>

	.login-title {
		margin-bottom: 15px;
	}

	.login-info .avatar {
		margin-right: 15px;
		margin-bottom: 15px;
		float: left;
	}

	#login form .login-info p {
		margin-bottom: 15px;
	}

	/** Note - login scope has not yet been implemented. **/
	.login-scope {
		clear: both;
		margin-bottom: 15px;
	}

	.login-scope h4 {
		margin-bottom: 10px;
	}

	.login-scope ul {
		margin-left: 1.5em;
	}

	.submit {
		clear: both;
	}

	.submit .button {
		margin-right: 10px;
		float: left;
	}

</style>

<form name="oauth2_authorize_form" id="oauth2_authorize_form" action="<?php echo esc_url( $url ); ?>" method="post">

	<?php
	printf(
		'<h2 class="login-title">%s</h2>',
		esc_html(
			sprintf(
				/* translators: %1$s: client name */
				__( 'Connect %1$s', 'oauth2' ),
				$client->get_name()
			)
		)
	);
	?>

	<div class="login-info">

		<?php echo get_avatar( $_current_user->ID, '78' ); ?>

		<?php
		printf(
			/* translators: %1$s: user login, %2$s: client name, %3$s: site name */
			'<p>' . __( 'Howdy <strong>%1$s</strong>,<br/> "%2$s" would like to connect to %3$s.', 'oauth2' ) . '</p>', // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			esc_html( $_current_user->user_login ),
			esc_html( $client->get_name() ),
			esc_html( get_bloginfo( 'name' ) )
		);
		?>

	</div>

	<?php
	/**
	 * Fires inside the lostpassword <form> tags.
	 */
	do_action( 'oauth2_authorize_form', $client );
	wp_nonce_field( sprintf( 'oauth2_authorize:%s', $client->get_id() ) );
	?>

	<p class="submit">
		<button type="submit" name="wp-submit" value="authorize" class="button button-primary button-large"><?php esc_html_e( 'Authorize', 'oauth2' ); ?></button>
		<button type="submit" name="wp-submit" value="cancel" class="button button-large"><?php esc_html_e( 'Cancel', 'oauth2' ); ?></button>
	</p>

</form>

<p id="nav">
<a href="<?php echo esc_url( wp_login_url( $url, true ) ); ?>"><?php esc_html_e( 'Switch user', 'oauth2' ); ?></a>
<?php
if ( get_option( 'users_can_register' ) ) :
	$registration_url = sprintf( '<a href="%s">%s</a>', esc_url( wp_registration_url() ), __( 'Register', 'oauth2' ) );
	/**
	 * Filter the registration URL below the login form.
	 *
	 * @since 1.5.0
	 *
	 * @param string $registration_url Registration URL.
	 */
	echo ' | ' . apply_filters( 'register', $registration_url ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
endif;
?>
</p>

<?php
login_footer();
