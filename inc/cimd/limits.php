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
	 * counts all fetches. A network counts them per site.
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
 * Read a rate limit counter that is kept outside the object cache.
 *
 * The per-user counter is a user option, which a network keeps per site. The
 * site-wide counter is a transient of the current site.
 *
 * @param string $key     Counter name.
 * @param int    $user_id User ID for a per-user counter, 0 for the site-wide one.
 * @return array|null Array with `count` and `reset`, or null if there is no live counter.
 */
function get_rate_limit_state( $key, $user_id ) {
	$state = $user_id ? get_user_option( $key, $user_id ) : get_transient( $key );
	if ( ! is_array( $state ) || ! isset( $state['count'], $state['reset'] ) || $state['reset'] <= time() ) {
		return null;
	}

	return $state;
}

/**
 * Store a rate limit counter that is kept outside the object cache.
 *
 * @param string $key     Counter name.
 * @param int    $user_id User ID for a per-user counter, 0 for the site-wide one.
 * @param array  $state   Array with `count` and `reset`.
 */
function set_rate_limit_state( $key, $user_id, array $state ) {
	if ( $user_id ) {
		update_user_option( $user_id, $key, $state );

		return;
	}

	set_transient( $key, $state, max( 1, $state['reset'] - time() ) );
}

/**
 * Get the object cache key of a rate limit counter of the current site.
 *
 * @param string $key Counter name.
 * @return string Cache key with the blog ID.
 */
function get_rate_limit_cache_key( $key ) {
	return get_current_blog_id() . '_' . $key;
}

/**
 * Count one fetch against a rate limit counter of the current site.
 *
 * With an external object cache the count is atomic, and a network keeps it
 * per site through the cache group. Without one it is a user option or a
 * transient of the current site that is read and then written, so concurrent
 * requests can briefly exceed the limit.
 *
 * @param string $key     Counter name.
 * @param array  $limit   Array with `limit` and `window`.
 * @param int    $user_id User ID for a per-user counter, 0 for the site-wide one.
 * @return bool True if the fetch fits within the limit.
 */
function take_rate_limit_slot( $key, array $limit, $user_id = 0 ) {
	if ( wp_using_ext_object_cache() ) {
		$cache_key = get_rate_limit_cache_key( $key );
		wp_cache_add( $cache_key, 0, LOCK_GROUP, $limit['window'] );
		$count = wp_cache_incr( $cache_key, 1, LOCK_GROUP );
		if ( false === $count ) {
			return false;
		}

		if ( $count > $limit['limit'] ) {
			wp_cache_decr( $cache_key, 1, LOCK_GROUP );

			return false;
		}

		return true;
	}

	$state = get_rate_limit_state( $key, $user_id ) ?? [
		'count' => 0,
		'reset' => time() + $limit['window'],
	];

	if ( $state['count'] >= $limit['limit'] ) {
		return false;
	}

	++$state['count'];
	set_rate_limit_state( $key, $user_id, $state );

	return true;
}

/**
 * Give back a slot taken with take_rate_limit_slot().
 *
 * @param string $key     Counter name.
 * @param int    $user_id User ID for a per-user counter, 0 for the site-wide one.
 */
function return_rate_limit_slot( $key, $user_id = 0 ) {
	if ( wp_using_ext_object_cache() ) {
		wp_cache_decr( get_rate_limit_cache_key( $key ), 1, LOCK_GROUP );

		return;
	}

	$state = get_rate_limit_state( $key, $user_id );
	if ( $state && $state['count'] > 0 ) {
		--$state['count'];
		set_rate_limit_state( $key, $user_id, $state );
	}
}

/**
 * Reserve a slot for a real fetch, in both the per-user and the site-wide limit of the current site.
 *
 * @param int $user_id User ID.
 * @return bool True if the fetch may go ahead.
 */
function reserve_fetch( $user_id ) {
	$user_key = 'oauth2_cimd_rl_' . $user_id;
	if ( ! take_rate_limit_slot( $user_key, get_rate_limit( $user_id, 'user' ), $user_id ) ) {
		return false;
	}

	if ( ! take_rate_limit_slot( 'oauth2_cimd_rl_global', get_rate_limit( $user_id, 'global' ) ) ) {
		return_rate_limit_slot( $user_key, $user_id );

		return false;
	}

	return true;
}
