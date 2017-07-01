<?php

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
//			'meta_query'  => [
//				[
//					'key'   => 'type',
//					'value' => 'oauth2',
//				],
//			],
			'paged'       => $paged,
		];

		$query       = new WP_Query( $args );
		$this->items = $query->posts;

		$pagination_args = [
			'total_items' => $query->found_posts,
			'total_pages' => $query->max_num_pages,
			'per_page'    => $query->get( 'posts_per_page' )
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
			'name'        => __( 'Name', 'rest_oauth2' ),
			'description' => __( 'Description', 'rest_oauth2' ),
		];

		return $c;
	}

	/**
	 * @param \WP_Post $item Post object.
	 */
	public function column_cb( $item ) {
		?>
		<label class="screen-reader-text"
		       for="cb-select-<?php echo esc_attr( $item->ID ) ?>"><?php esc_html_e( 'Select consumer', 'rest_oauth2' ); ?></label>

		<input id="cb-select-<?php echo esc_attr( $item->ID ) ?>" type="checkbox"
		       name="consumers[]" value="<?php echo esc_attr( $item->ID ) ?>"/>

		<?php
	}

	/**
	 * @param \WP_Post $item Post object.
	 * @return string Name of the column.
	 */
	protected function column_name( $item ) {
		$title = get_the_title( $item->ID );
		if ( empty( $title ) ) {
			$title = '<em>' . esc_html__( 'Untitled', 'rest_oauth2' ) . '</em>';
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

		$actions     = [
			'edit'   => sprintf( '<a href="%s">%s</a>', esc_url( $edit_link ), esc_html__( 'Edit', 'rest_oauth2' ) ),
			'delete' => sprintf( '<a href="%s">%s</a>', esc_url( $delete_link ), esc_html__( 'Delete', 'rest_oauth2' ) ),
		];
		$action_html = $this->row_actions( $actions );

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
