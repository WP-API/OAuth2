<?php
/**
 *
 * @package WordPress
 * @subpackage JSON API
 */

namespace WP\OAuth2\Admin;

use WP\OAuth2\Client;
use WP_List_Table;
use WP_Query;

class ListTable extends WP_List_Table {

	/**
	 * @todo check if the meta_query is actually required.
	 */
	public function prepare_items() {
		$paged = $this->get_pagenum();

		$args = [
			'post_type'   => Client::POST_TYPE,
			'post_status' => 'any',
			'paged'       => $paged,
		];

		$query       = new WP_Query( $args );
		$this->items = $query->posts;

		$pagination_args = [
			'total_items' => $query->found_posts,
			'total_pages' => $query->max_num_pages,
			'per_page'    => $query->get( 'posts_per_page' ),
		];
		$this->set_pagination_args( $pagination_args );
	}

	/**
	 * Get a list of columns for the list table.
	 *
	 * @since  3.1.0
	 * @access public
	 *
	 * @return array Array in which the key is the ID of the column,
	 *               and the value is the description.
	 */
	public function get_columns() {
		$c = [
			'cb'          => '<input type="checkbox" />',
			'name'        => __( 'Name', 'oauth2' ),
			'description' => __( 'Description', 'oauth2' ),
		];

		return $c;
	}

	/**
	 * @param \WP_Post $item Post object.
	 */
	public function column_cb( $item ) {
		?>
		<label class="screen-reader-text"
			for="cb-select-<?php echo esc_attr( $item->ID ); ?>"><?php esc_html_e( 'Select consumer', 'oauth2' ); ?></label>

		<input id="cb-select-<?php echo esc_attr( $item->ID ); ?>" type="checkbox"
			name="consumers[]" value="<?php echo esc_attr( $item->ID ); ?>"/>

		<?php
	}

	/**
	 * @param \WP_Post $item Post object.
	 * @return string Name of the column.
	 */
	protected function column_name( $item ) {
		$title = get_the_title( $item->ID );
		if ( empty( $title ) ) {
			$title = '<em>' . esc_html__( 'Untitled', 'oauth2' ) . '</em>';
		}

		$edit_link   = add_query_arg(
			[
				'page'   => 'rest-oauth2-apps',
				'action' => 'edit',
				'id'     => $item->ID,
			],
			admin_url( 'users.php' )
		);
		$delete_link = add_query_arg(
			[
				'page'   => 'rest-oauth2-apps',
				'action' => 'delete',
				'id'     => $item->ID,
			],
			admin_url( 'users.php' )
		);
		$delete_link = wp_nonce_url( $delete_link, 'rest-oauth2-delete:' . $item->ID );

		$actions = [
			'edit'   => sprintf( '<a href="%s">%s</a>', esc_url( $edit_link ), esc_html__( 'Edit', 'oauth2' ) ),
			'delete' => sprintf( '<a href="%s">%s</a>', esc_url( $delete_link ), esc_html__( 'Delete', 'oauth2' ) ),
		];

		$post_type_object = get_post_type_object( $item->post_type );
		if ( current_user_can( $post_type_object->cap->publish_posts ) && 'publish' !== $item->post_status ) {
			$publish_link = add_query_arg(
				[
					'page'   => 'rest-oauth2-apps',
					'action' => 'approve',
					'id'     => $item->ID,
				],
				admin_url( 'users.php' )
			);

			$publish_link           = wp_nonce_url( $publish_link, 'rest-oauth2-approve:' . $item->ID );
			$actions['app-approve'] = sprintf(
				'<a href="%s">%s</a>',
				esc_url( $publish_link ),
				esc_html__( 'Approve', 'oauth2' )
			);
		}

		$action_html = $this->row_actions( $actions );

		// Get suffixes for draft, etc
		ob_start();
		_post_states( $item );
		$title = sprintf(
			'<strong><a href="%s">%s</a>%s</strong>',
			$edit_link,
			$title,
			ob_get_clean()
		);

		return $title . ' ' . $action_html;
	}

	/**
	 * @param \WP_Post $item Post object.
	 * @return string Content of the column.
	 */
	protected function column_description( $item ) {
		return $item->post_content;
	}
}
