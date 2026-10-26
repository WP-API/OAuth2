<?php
/**
 * Tests for the admin namespace functions.
 *
 * @package WP\OAuth2\Tests
 */

namespace WP\OAuth2\Tests;

require_once __DIR__ . '/class-test-case.php';

use WP\OAuth2\Admin\ListTable;
use function WP\OAuth2\Admin\render_approval_status;
use function WP\OAuth2\Admin\validate_parameters;

/**
 * Test cases for the client admin screens.
 */
class Test_Admin extends Test_Case {

	/**
	 * Build a valid set of submitted client parameters.
	 *
	 * @param array $overrides Values to override or add.
	 *
	 * @return array Parameters as they arrive from the edit form.
	 */
	protected function get_params( array $overrides = [] ) {
		return array_merge(
			[
				'name'        => 'Test Client',
				'description' => 'Test client description.',
				'type'        => 'web',
				'callback'    => 'https://example.com/callback',
			],
			$overrides
		);
	}

	public function test_validate_parameters_accepts_valid_client() {
		$valid = validate_parameters( $this->get_params() );

		$this->assertIsArray( $valid );
		$this->assertEquals( 'Test Client', $valid['name'] );
	}

	// -------------------------------------------------------------------------
	// Token TTL
	// -------------------------------------------------------------------------

	public function test_validate_parameters_ttl_empty_when_not_submitted() {
		$valid = validate_parameters( $this->get_params() );

		$this->assertSame( '', $valid['token_ttl'] );
	}

	public function test_validate_parameters_ttl_empty_for_empty_string() {
		$valid = validate_parameters( $this->get_params( [ 'token_ttl' => '' ] ) );

		$this->assertSame( '', $valid['token_ttl'] );
	}

	public function test_validate_parameters_casts_ttl_to_int() {
		// Form values always arrive as strings.
		$valid = validate_parameters( $this->get_params( [ 'token_ttl' => '3600' ] ) );

		$this->assertSame( 3600, $valid['token_ttl'] );
	}

	public function test_validate_parameters_accepts_zero_ttl() {
		$valid = validate_parameters( $this->get_params( [ 'token_ttl' => '0' ] ) );

		$this->assertSame( 0, $valid['token_ttl'] );
	}

	public function test_validate_parameters_rejects_negative_ttl() {
		$result = validate_parameters( $this->get_params( [ 'token_ttl' => '-1' ] ) );

		$this->assertWPError( $result );
		$this->assertEquals( 'rest_oauth2_invalid_ttl', $result->get_error_code() );
	}

	/**
	 * Get a list table instance.
	 *
	 * @return ListTable
	 */
	protected function get_list_table() {
		set_current_screen( 'users_page_rest-oauth2-apps' );
		require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';
		require_once dirname( __DIR__ ) . '/inc/admin/class-listtable.php';

		return new ListTable( [ 'screen' => 'users_page_rest-oauth2-apps' ] );
	}

	/**
	 * Capture the output of the approved column for a client.
	 *
	 * @param \WP\OAuth2\Client $client Client to print the column for.
	 *
	 * @return string Column output.
	 */
	protected function get_approved_column( $client ) {
		ob_start();
		$this->get_list_table()->column_approved( get_post( $client->get_post_id() ) );

		return ob_get_clean();
	}

	/**
	 * Capture the output of the approval status for a client.
	 *
	 * @param \WP\OAuth2\Client $client Client to print the status for.
	 *
	 * @return string Notice markup.
	 */
	protected function get_approval_status( $client ) {
		ob_start();
		render_approval_status( get_post( $client->get_post_id() ) );

		return ob_get_clean();
	}

	public function test_list_table_has_approved_column() {
		$this->assertArrayHasKey( 'approved', $this->get_list_table()->get_columns() );
	}

	public function test_approved_column_prints_yes_for_published_client() {
		$this->assertSame( 'Yes', $this->get_approved_column( $this->create_client() ) );
	}

	public function test_approved_column_prints_no_for_unapproved_client() {
		$this->assertSame( 'No', $this->get_approved_column( $this->create_unapproved_client() ) );
	}

	public function test_approval_status_shows_warning_and_button_for_admin() {
		wp_set_current_user( self::factory()->user->create( [ 'role' => 'administrator' ] ) );

		$output = $this->get_approval_status( $this->create_unapproved_client() );

		$this->assertStringContainsString( 'notice-warning', $output );
		$this->assertStringContainsString( 'This application is not approved yet.', $output );
		$this->assertStringContainsString( 'button button-primary', $output );
		$this->assertStringContainsString( 'action=approve', $output );
		$this->assertStringContainsString( 'return=edit', $output );
		$this->assertStringNotContainsString( 'Ask an administrator', $output );
	}

	public function test_approval_status_asks_for_administrator_without_capability() {
		wp_set_current_user( self::factory()->user->create( [ 'role' => 'subscriber' ] ) );

		$output = $this->get_approval_status( $this->create_unapproved_client() );

		$this->assertStringContainsString( 'notice-warning', $output );
		$this->assertStringContainsString( 'Ask an administrator to approve it.', $output );
		$this->assertStringNotContainsString( 'button-primary', $output );
	}

	public function test_approval_status_shows_success_for_published_client() {
		wp_set_current_user( self::factory()->user->create( [ 'role' => 'administrator' ] ) );

		$output = $this->get_approval_status( $this->create_client() );

		$this->assertStringContainsString( 'notice-success', $output );
		$this->assertStringContainsString( 'This application is approved.', $output );
		$this->assertStringNotContainsString( 'button-primary', $output );
	}
}
