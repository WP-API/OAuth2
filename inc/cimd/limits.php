<?php
/**
 * Locks and rate limits for fetching client metadata documents.
 *
 * @package WordPress
 * @subpackage JSON API
 */

namespace WP\OAuth2\CIMD;

const LOCK_GROUP = 'oauth2_cimd';

/**
 * Take the fetch lock for a client ID URL.
 *
 * The lock is a row in the main site's options table, which every site of a
 * network shares. The handle holds a random token and the time the lock was
 * taken. An expired lock is taken over only if no other request changed it
 * first.
 *
 * @param string $url Client ID URL.
 * @return string|false Handle to pass to release_lock(), or false if another request holds the lock.
 */
function acquire_lock( $url ) {
	$key    = 'oauth2_cimd_lock_' . md5( $url );
	$handle = wp_generate_password( 32, false ) . '|' . time();

	global $wpdb;
	$table = $wpdb->base_prefix . 'options';

	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- The unique option_name makes the insert atomic. The table name is the trusted base prefix, not user input.
	$added = $wpdb->query( $wpdb->prepare( "INSERT IGNORE INTO {$wpdb->base_prefix}options (option_name, option_value, autoload) VALUES (%s, %s, 'no')", $key, $handle ) );
	if ( 1 === $added ) {
		return $handle;
	}

	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Reads the lock without the options cache. The table name is the trusted base prefix, not user input.
	$held = $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM {$wpdb->base_prefix}options WHERE option_name = %s", $key ) );
	if ( null === $held || time() - (int) ( explode( '|', $held, 2 )[1] ?? 0 ) < LOCK_TIMEOUT ) {
		return false;
	}

	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Matching the old value makes the takeover atomic.
	$taken = $wpdb->update(
		$table,
		[ 'option_value' => $handle ],
		[
			'option_name'  => $key,
			'option_value' => $held,
		]
	);

	return 1 === $taken ? $handle : false;
}

/**
 * Release the fetch lock for a client ID URL, if it is still ours.
 *
 * @param string $url    Client ID URL.
 * @param string $handle Handle returned by acquire_lock().
 */
function release_lock( $url, $handle ) {
	$key = 'oauth2_cimd_lock_' . md5( $url );

	global $wpdb;
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Only deletes the row if it still holds our handle.
	$wpdb->delete(
		$wpdb->base_prefix . 'options',
		[
			'option_name'  => $key,
			'option_value' => $handle,
		]
	);
}

/**
 * Get the rate limit for a scope.
 *
 * @param int    $user_id User ID.
 * @param string $scope   Either `user` or `global`.
 * @return array Array with int `limit` and int `window` keys.
 */
function get_rate_limit( $user_id, $scope ) {
	$defaults = [
		'limit'  => 'global' === $scope ? 60 : 10,
		'window' => 600,
	];

	/**
	 * Filters the limit on client metadata document fetches.
	 *
	 * The `user` scope counts the fetches of one user, and the `global` scope
	 * counts all fetches across the network.
	 *
	 * @param array  $limit   Array with `limit` fetches allowed per `window` seconds.
	 * @param int    $user_id User ID.
	 * @param string $scope   Either `user` or `global`.
	 */
	$limit = apply_filters( 'oauth2.cimd.rate_limit', $defaults, $user_id, $scope );
	$limit = is_array( $limit ) ? $limit : [];

	return [
		'limit'  => max( 0, (int) ( $limit['limit'] ?? $defaults['limit'] ) ),
		'window' => max( 1, (int) ( $limit['window'] ?? $defaults['window'] ) ),
	];
}

/**
 * Count one fetch against a rate limit counter.
 *
 * With an external object cache the count is atomic. Without one it is a
 * network-wide transient that is read and then written, so concurrent requests
 * can briefly exceed the limit.
 *
 * @param string $key   Counter name.
 * @param array  $limit Array with `limit` and `window`.
 * @return bool True if the fetch fits within the limit.
 */
function take_rate_limit_slot( $key, array $limit ) {
	if ( wp_using_ext_object_cache() ) {
		wp_cache_add_global_groups( LOCK_GROUP );
		wp_cache_add( $key, 0, LOCK_GROUP, $limit['window'] );
		$count = wp_cache_incr( $key, 1, LOCK_GROUP );
		if ( false === $count ) {
			return false;
		}

		if ( $count > $limit['limit'] ) {
			wp_cache_decr( $key, 1, LOCK_GROUP );

			return false;
		}

		return true;
	}

	$state = get_site_transient( $key );
	if ( ! is_array( $state ) || ! isset( $state['count'], $state['reset'] ) || $state['reset'] <= time() ) {
		$state = [
			'count' => 0,
			'reset' => time() + $limit['window'],
		];
	}

	if ( $state['count'] >= $limit['limit'] ) {
		return false;
	}

	++$state['count'];
	set_site_transient( $key, $state, max( 1, $state['reset'] - time() ) );

	return true;
}

/**
 * Give back a slot taken with take_rate_limit_slot().
 *
 * @param string $key Counter name.
 */
function return_rate_limit_slot( $key ) {
	if ( wp_using_ext_object_cache() ) {
		wp_cache_decr( $key, 1, LOCK_GROUP );

		return;
	}

	$state = get_site_transient( $key );
	if ( is_array( $state ) && isset( $state['count'], $state['reset'] ) && $state['count'] > 0 ) {
		--$state['count'];
		set_site_transient( $key, $state, max( 1, $state['reset'] - time() ) );
	}
}

/**
 * Reserve a slot for a real fetch, in both the per-user and the network-wide limit.
 *
 * @param int $user_id User ID.
 * @return bool True if the fetch may go ahead.
 */
function reserve_fetch( $user_id ) {
	$user_key = 'oauth2_cimd_rl_' . $user_id;
	if ( ! take_rate_limit_slot( $user_key, get_rate_limit( $user_id, 'user' ) ) ) {
		return false;
	}

	if ( ! take_rate_limit_slot( 'oauth2_cimd_rl_global', get_rate_limit( $user_id, 'global' ) ) ) {
		return_rate_limit_slot( $user_key );

		return false;
	}

	return true;
}
