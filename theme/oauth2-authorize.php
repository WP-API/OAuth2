<?php
login_header(
	__( 'Authorize', 'oauth2' ),
	'',
	$errors
);

$current_user = wp_get_current_user();

$url = $_SERVER['REQUEST_URI'];

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

<form name="oauth1_authorize_form" id="oauth1_authorize_form" action="<?php echo esc_url( $url ); ?>" method="post">

	<h2 class="login-title"><?php echo esc_html( sprintf( __('Connect %1$s'), $client->get_name() ) ) ?></h2>

	<div class="login-info">

		<?php echo get_avatar( $current_user->ID, '78' ); ?>

		<p><?php
			printf(
				__( 'Howdy <strong>%1$s</strong>,<br/> "%2$s" would like to connect to %3$s.', 'oauth2' ),
				$current_user->user_login,
		    $client->get_name(),
				get_bloginfo( 'name' )
			)
		?></p>

	</div>

	<?php
	/**
	 * Fires inside the lostpassword <form> tags.
	 */
	do_action( 'oauth2_authorize_form', $client );
	wp_nonce_field( 'json_oauth2_authorize' );
	?>

	<p class="submit">
		<button type="submit" name="wp-submit" value="authorize" class="button button-primary button-large"><?php _e( 'Authorize', 'oauth2' ); ?></button>
		<button type="submit" name="wp-submit" value="cancel" class="button button-large"><?php _e( 'Cancel', 'oauth2' ); ?></button>
	</p>

</form>

<p id="nav">
<a href="<?php echo esc_url( wp_login_url( $url, true ) ); ?>"><?php _e( 'Switch user' ) ?></a>
<?php
if ( get_option( 'users_can_register' ) ) :
	$registration_url = sprintf( '<a href="%s">%s</a>', esc_url( wp_registration_url() ), __( 'Register' ) );
	/**
	 * Filter the registration URL below the login form.
	 *
	 * @since 1.5.0
	 *
	 * @param string $registration_url Registration URL.
	 */
	echo ' | ' . apply_filters( 'register', $registration_url );
endif;
?>
</p>

<?php
login_footer();
