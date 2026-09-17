<?php
/**
 * Tests for the WP\OAuth2\Well_Known namespace functions.
 *
 * @package WP\OAuth2\Tests
 */

namespace WP\OAuth2\Tests;

require_once __DIR__ . '/class-test-case.php';

use function WP\OAuth2\Well_Known\get_authorization_server_metadata;
use function WP\OAuth2\Well_Known\get_grant_types_supported;
use function WP\OAuth2\Well_Known\get_metadata_for_site;
use function WP\OAuth2\Well_Known\get_response_types_supported;
use function WP\OAuth2\Well_Known\get_site_id_by_path;
use function WP\OAuth2\Well_Known\match_well_known_path;

/**
 * Test cases for the well-known discovery document functions.
 */
class Test_Well_Known extends Test_Case {

	/**
	 * Skip a test that can only run on a network.
	 */
	protected function require_multisite() {
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Requires a multisite install.' );
		}
	}

	// -------------------------------------------------------------------------
	// match_well_known_path
	// -------------------------------------------------------------------------

	public function test_match_well_known_path_matches_root_site() {
		$this->assertEquals( '/', match_well_known_path( '/.well-known/oauth-authorization-server' ) );
	}

	public function test_match_well_known_path_tolerates_trailing_slash() {
		$this->assertEquals( '/', match_well_known_path( '/.well-known/oauth-authorization-server/' ) );
	}

	public function test_match_well_known_path_ignores_query_string() {
		$this->assertEquals( '/', match_well_known_path( '/.well-known/oauth-authorization-server?foo=bar' ) );
	}

	public function test_match_well_known_path_returns_null_for_unrelated_path() {
		$this->assertNull( match_well_known_path( '/some-other-path' ) );
	}

	/**
	 * RFC 8414 puts the well-known path in front of the site's own path.
	 */
	public function test_match_well_known_path_reads_site_path_suffix() {
		$this->assertEquals( '/blog/', match_well_known_path( '/.well-known/oauth-authorization-server/blog' ) );
	}

	public function test_match_well_known_path_reads_nested_site_path_suffix() {
		$this->assertEquals( '/blog/sub/', match_well_known_path( '/.well-known/oauth-authorization-server/blog/sub' ) );
	}

	public function test_match_well_known_path_matches_a_subsites_own_path() {
		$this->require_multisite();

		$site_id = $this->factory->blog->create( [ 'path' => '/blog/' ] );

		switch_to_blog( $site_id );
		$matched = match_well_known_path( '/blog/.well-known/oauth-authorization-server' );
		restore_current_blog();

		$this->assertEquals( '/blog/', $matched );
	}

	// -------------------------------------------------------------------------
	// get_site_id_by_path
	// -------------------------------------------------------------------------

	public function test_get_site_id_by_path_finds_the_current_site() {
		$this->assertEquals( get_current_blog_id(), get_site_id_by_path( '/' ) );
	}

	public function test_get_site_id_by_path_returns_null_for_unknown_path() {
		$this->assertNull( get_site_id_by_path( '/no-such-site/' ) );
	}

	public function test_get_site_id_by_path_finds_a_subsite() {
		$this->require_multisite();

		$site_id = $this->factory->blog->create( [ 'path' => '/blog/' ] );

		$this->assertEquals( $site_id, get_site_id_by_path( '/blog/' ) );
	}

	// -------------------------------------------------------------------------
	// get_authorization_server_metadata
	// -------------------------------------------------------------------------

	public function test_metadata_issuer_is_the_site_url() {
		$metadata = get_authorization_server_metadata();
		$this->assertEquals( home_url(), $metadata['issuer'] );
	}

	public function test_metadata_advertises_the_token_endpoint() {
		$metadata = get_authorization_server_metadata();
		$this->assertStringContainsString( 'oauth2/access_token', $metadata['token_endpoint'] );
	}

	public function test_metadata_advertises_the_pkce_challenge_methods() {
		$metadata = get_authorization_server_metadata();
		$this->assertContains( 'S256', $metadata['code_challenge_methods_supported'] );
	}

	public function test_metadata_is_filterable() {
		add_filter( 'oauth2.well_known_authorization_server_metadata', function ( $metadata ) {
			$metadata['service_documentation'] = 'https://example.org/docs';
			return $metadata;
		} );

		$metadata = get_authorization_server_metadata();

		$this->assertEquals( 'https://example.org/docs', $metadata['service_documentation'] );
	}

	// -------------------------------------------------------------------------
	// get_metadata_for_site
	// -------------------------------------------------------------------------

	public function test_get_metadata_for_site_describes_the_requested_subsite() {
		$this->require_multisite();

		$site_id = $this->factory->blog->create( [ 'path' => '/blog/' ] );

		$metadata = get_metadata_for_site( $site_id );

		$this->assertEquals( get_home_url( $site_id ), $metadata['issuer'] );
		$this->assertNotEquals( home_url(), $metadata['issuer'] );
		$this->assertStringContainsString( '/blog/', $metadata['token_endpoint'] );
	}

	public function test_get_metadata_for_site_restores_the_current_site() {
		$this->require_multisite();

		$site_id  = $this->factory->blog->create( [ 'path' => '/blog/' ] );
		$original = get_current_blog_id();

		get_metadata_for_site( $site_id );

		$this->assertEquals( $original, get_current_blog_id() );
	}

	// -------------------------------------------------------------------------
	// get_grant_types_supported / get_response_types_supported
	// -------------------------------------------------------------------------

	public function test_get_grant_types_supported_includes_authorization_code() {
		$this->assertContains( 'authorization_code', get_grant_types_supported() );
	}

	public function test_get_grant_types_supported_includes_client_credentials() {
		$this->assertContains( 'client_credentials', get_grant_types_supported() );
	}

	public function test_get_response_types_supported_includes_code_and_token() {
		$response_types = get_response_types_supported();
		$this->assertContains( 'code', $response_types );
		$this->assertContains( 'token', $response_types );
	}
}
