<?php
/**
 * Tests for the RFC 9728 protected resource metadata functions.
 *
 * @package WP\OAuth2\Tests
 */

namespace WP\OAuth2\Tests;

require_once __DIR__ . '/class-test-case.php';

use const WP\OAuth2\Well_Known\PROTECTED_RESOURCE_PATH;

use function WP\OAuth2\Well_Known\get_ancestor_paths;
use function WP\OAuth2\Well_Known\get_authorization_server_metadata;
use function WP\OAuth2\Well_Known\get_protected_resource_metadata;
use function WP\OAuth2\Well_Known\get_protected_resource_metadata_for_site;
use function WP\OAuth2\Well_Known\get_protected_resource_metadata_url;
use function WP\OAuth2\Well_Known\get_rest_base_sub_path;
use function WP\OAuth2\Well_Known\match_well_known_path;
use function WP\OAuth2\Well_Known\split_resource_path;

/**
 * Test cases for the protected resource metadata document.
 */
class Test_Protected_Resource extends Test_Case {

	public function set_up() {
		parent::set_up();

		// Without pretty permalinks the REST API lives in a query argument,
		// so there is no resource path to describe. That case has its own
		// tests below.
		$this->set_permalink_structure( '/%postname%/' );
	}

	/**
	 * Skip a test that can only run on a network.
	 */
	protected function require_multisite() {
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Requires a multisite install.' );
		}
	}

	/**
	 * Give a site the pretty permalinks the REST API path form needs.
	 *
	 * @param int $site_id Site to update.
	 */
	protected function set_pretty_permalinks( $site_id ) {
		switch_to_blog( $site_id );
		update_option( 'permalink_structure', '/%postname%/' );
		restore_current_blog();
	}

	// -------------------------------------------------------------------------
	// match_well_known_path
	// -------------------------------------------------------------------------

	public function test_match_well_known_path_matches_the_protected_resource_document() {
		$this->assertEquals(
			'/wp-json/',
			match_well_known_path( '/.well-known/oauth-protected-resource/wp-json', PROTECTED_RESOURCE_PATH )
		);
	}

	public function test_match_well_known_path_matches_the_bare_protected_resource_path() {
		$this->assertEquals(
			'/',
			match_well_known_path( '/.well-known/oauth-protected-resource', PROTECTED_RESOURCE_PATH )
		);
	}

	public function test_match_well_known_path_ignores_a_different_document() {
		$this->assertNull(
			match_well_known_path( '/.well-known/oauth-authorization-server', PROTECTED_RESOURCE_PATH )
		);
	}

	public function test_match_well_known_path_defaults_to_the_authorization_server_document() {
		$this->assertNull( match_well_known_path( '/.well-known/oauth-protected-resource' ) );
	}

	// -------------------------------------------------------------------------
	// get_ancestor_paths
	// -------------------------------------------------------------------------

	public function test_get_ancestor_paths_lists_parents_longest_first() {
		$this->assertEquals(
			[ '/blog/wp-json/mcp/', '/blog/wp-json/', '/blog/', '/' ],
			get_ancestor_paths( '/blog/wp-json/mcp' )
		);
	}

	public function test_get_ancestor_paths_of_the_root_is_just_the_root() {
		$this->assertEquals( [ '/' ], get_ancestor_paths( '/' ) );
	}

	// -------------------------------------------------------------------------
	// get_rest_base_sub_path
	// -------------------------------------------------------------------------

	public function test_get_rest_base_sub_path_is_the_rest_prefix() {
		$this->assertEquals( '/wp-json', get_rest_base_sub_path( get_current_blog_id() ) );
	}

	public function test_get_rest_base_sub_path_honours_a_filtered_prefix() {
		add_filter(
			'rest_url_prefix',
			function () {
				return 'api';
			}
		);

		$this->assertEquals( '/api', get_rest_base_sub_path( get_current_blog_id() ) );
	}

	public function test_get_rest_base_sub_path_is_empty_without_pretty_permalinks() {
		$this->set_permalink_structure( '' );

		$this->assertEquals( '', get_rest_base_sub_path( get_current_blog_id() ) );
	}

	// -------------------------------------------------------------------------
	// split_resource_path
	// -------------------------------------------------------------------------

	public function test_split_resource_path_matches_the_rest_root() {
		$resource = split_resource_path( '/wp-json/' );

		$this->assertEquals( get_current_blog_id(), $resource['site_id'] );
		$this->assertEquals( '/wp-json', $resource['sub_path'] );
	}

	public function test_split_resource_path_matches_a_route_beneath_the_rest_root() {
		$resource = split_resource_path( '/wp-json/wp/v2/posts/' );

		$this->assertEquals( '/wp-json/wp/v2/posts', $resource['sub_path'] );
	}

	public function test_split_resource_path_matches_the_site_root() {
		$resource = split_resource_path( '/' );

		$this->assertEquals( get_current_blog_id(), $resource['site_id'] );
		$this->assertEquals( '', $resource['sub_path'] );
	}

	public function test_split_resource_path_rejects_a_path_outside_the_rest_api() {
		$this->assertNull( split_resource_path( '/not-wp-json/' ) );
	}

	public function test_split_resource_path_honours_a_filtered_rest_prefix() {
		add_filter(
			'rest_url_prefix',
			function () {
				return 'api';
			}
		);

		$resource = split_resource_path( '/api/mcp/' );

		$this->assertEquals( '/api/mcp', $resource['sub_path'] );
	}

	public function test_split_resource_path_without_pretty_permalinks_serves_only_the_site_root() {
		$this->set_permalink_structure( '' );

		$this->assertNull( split_resource_path( '/wp-json/' ) );
		$this->assertEquals( '', split_resource_path( '/' )['sub_path'] );
	}

	public function test_split_resource_path_prefers_the_longest_site_path() {
		$this->require_multisite();

		$site_id = $this->factory->blog->create( [ 'path' => '/blog/' ] );
		$this->set_pretty_permalinks( $site_id );

		$resource = split_resource_path( '/blog/wp-json/mcp/' );

		$this->assertEquals( $site_id, $resource['site_id'] );
		$this->assertEquals( '/blog/', $resource['site_path'] );
		$this->assertEquals( '/wp-json/mcp', $resource['sub_path'] );
	}

	public function test_split_resource_path_falls_back_to_the_root_site() {
		$this->require_multisite();

		$this->factory->blog->create( [ 'path' => '/blog/' ] );

		$resource = split_resource_path( '/wp-json/' );

		$this->assertEquals( get_current_blog_id(), $resource['site_id'] );
		$this->assertEquals( '/wp-json', $resource['sub_path'] );
	}

	public function test_split_resource_path_rejects_an_unknown_site() {
		$this->require_multisite();

		$this->assertNull( split_resource_path( '/no-such-site/wp-json/' ) );
	}

	// -------------------------------------------------------------------------
	// get_protected_resource_metadata
	// -------------------------------------------------------------------------

	public function test_metadata_resource_is_the_requested_identifier() {
		$metadata = get_protected_resource_metadata( '/wp-json/mcp' );

		$this->assertEquals( home_url( '/wp-json/mcp' ), $metadata['resource'] );
	}

	public function test_metadata_resource_has_no_trailing_slash() {
		$metadata = get_protected_resource_metadata( '/wp-json/' );

		$this->assertEquals( home_url( '/wp-json' ), $metadata['resource'] );
	}

	public function test_metadata_resource_for_the_site_root_is_the_home_url() {
		$metadata = get_protected_resource_metadata( '' );

		$this->assertEquals( untrailingslashit( home_url() ), $metadata['resource'] );
	}

	/**
	 * The RFC 8414 document's issuer is where a client goes next, so the two
	 * have to name the same authorization server.
	 */
	public function test_metadata_authorization_server_matches_the_8414_issuer() {
		$metadata = get_protected_resource_metadata( '/wp-json' );

		$this->assertEquals(
			[ get_authorization_server_metadata()['issuer'] ],
			$metadata['authorization_servers']
		);
	}

	public function test_metadata_advertises_header_and_query_bearer_methods() {
		$methods = get_protected_resource_metadata( '/wp-json' )['bearer_methods_supported'];

		$this->assertContains( 'header', $methods );
		$this->assertContains( 'query', $methods );
	}

	/**
	 * Tokens are never read from a form body, so advertising it would be wrong.
	 */
	public function test_metadata_does_not_advertise_the_body_bearer_method() {
		$this->assertNotContains(
			'body',
			get_protected_resource_metadata( '/wp-json' )['bearer_methods_supported']
		);
	}

	public function test_metadata_omits_scopes_supported() {
		$this->assertArrayNotHasKey( 'scopes_supported', get_protected_resource_metadata( '/wp-json' ) );
	}

	public function test_metadata_includes_the_site_name() {
		$this->assertEquals(
			get_bloginfo( 'name', 'display' ),
			get_protected_resource_metadata( '/wp-json' )['resource_name']
		);
	}

	public function test_metadata_is_filterable() {
		add_filter(
			'oauth2.well_known_protected_resource_metadata',
			function ( $metadata ) {
				$metadata['scopes_supported'] = [ 'read' ];
				return $metadata;
			}
		);

		$this->assertEquals( [ 'read' ], get_protected_resource_metadata( '/wp-json' )['scopes_supported'] );
	}

	public function test_metadata_filter_receives_the_resource_path() {
		$seen = null;

		add_filter(
			'oauth2.well_known_protected_resource_metadata',
			function ( $metadata, $sub_path ) use ( &$seen ) {
				$seen = $sub_path;
				return $metadata;
			},
			10,
			2
		);

		get_protected_resource_metadata( '/wp-json/mcp' );

		$this->assertEquals( '/wp-json/mcp', $seen );
	}

	// -------------------------------------------------------------------------
	// get_protected_resource_metadata_for_site
	// -------------------------------------------------------------------------

	public function test_get_protected_resource_metadata_for_site_describes_the_requested_subsite() {
		$this->require_multisite();

		$site_id = $this->factory->blog->create( [ 'path' => '/blog/' ] );
		$this->set_pretty_permalinks( $site_id );

		$metadata = get_protected_resource_metadata_for_site( $site_id, '/wp-json' );

		$this->assertEquals( get_home_url( $site_id, '/wp-json' ), $metadata['resource'] );
		$this->assertNotEquals( home_url( '/wp-json' ), $metadata['resource'] );
		$this->assertEquals( [ get_home_url( $site_id ) ], $metadata['authorization_servers'] );
	}

	public function test_get_protected_resource_metadata_for_site_restores_the_current_site() {
		$this->require_multisite();

		$site_id  = $this->factory->blog->create( [ 'path' => '/blog/' ] );
		$original = get_current_blog_id();

		get_protected_resource_metadata_for_site( $site_id, '/wp-json' );

		$this->assertEquals( $original, get_current_blog_id() );
	}

	// -------------------------------------------------------------------------
	// get_protected_resource_metadata_url
	// -------------------------------------------------------------------------

	public function test_metadata_url_puts_the_well_known_path_before_the_resource_path() {
		$this->assertEquals(
			home_url( '/.well-known/oauth-protected-resource/wp-json' ),
			get_protected_resource_metadata_url( '/wp-json' )
		);
	}

	public function test_metadata_url_defaults_to_the_rest_root() {
		$this->assertEquals(
			home_url( '/.well-known/oauth-protected-resource/wp-json' ),
			get_protected_resource_metadata_url()
		);
	}

	public function test_metadata_url_for_the_site_root_has_no_resource_path() {
		$this->assertEquals(
			home_url( '/.well-known/oauth-protected-resource' ),
			get_protected_resource_metadata_url( '' )
		);
	}

	/**
	 * A site in a subdirectory doesn't own the domain root, so the URL it
	 * advertises has to sit under the site itself to be reachable.
	 */
	public function test_metadata_url_sits_under_the_subsite() {
		$this->require_multisite();

		$site_id = $this->factory->blog->create( [ 'path' => '/blog/' ] );
		$this->set_pretty_permalinks( $site_id );

		switch_to_blog( $site_id );
		$url     = get_protected_resource_metadata_url();
		$matched = match_well_known_path( wp_parse_url( $url, PHP_URL_PATH ), PROTECTED_RESOURCE_PATH );
		restore_current_blog();

		$this->assertStringStartsWith( get_home_url( $site_id, '/.well-known/' ), $url );
		$this->assertEquals( '/blog/wp-json/', $matched );
	}

	/**
	 * The URL a client is told to fetch has to be one the matcher accepts.
	 */
	public function test_metadata_url_is_servable() {
		$url  = get_protected_resource_metadata_url();
		$path = wp_parse_url( $url, PHP_URL_PATH );

		$matched  = match_well_known_path( $path, PROTECTED_RESOURCE_PATH );
		$resource = split_resource_path( $matched );

		$this->assertEquals( '/wp-json', $resource['sub_path'] );
		$this->assertEquals(
			home_url( '/wp-json' ),
			get_protected_resource_metadata_for_site( $resource['site_id'], $resource['sub_path'] )['resource']
		);
	}
}
