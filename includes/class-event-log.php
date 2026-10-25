<?php
/**
 * Event log storage.
 *
 * @package AndersonSiteShield
 */

namespace AndersonSiteShield;

defined( 'ABSPATH' ) || exit;

/**
 * Stores security events in their own table.
 *
 * Every event goes through Event_Log::log(), which fires the
 * `anshield_event_logged` action. A future SOC/SIEM sender hooks there.
 */
class Event_Log {

	const DB_VERSION = '1';

	const SEVERITIES = array( 'info', 'notice', 'warning', 'critical' );

	/**
	 * Table name with prefix.
	 *
	 * @return string
	 */
	public static function table() {
		global $wpdb;
		return $wpdb->prefix . 'anshield_events';
	}

	/**
	 * Create or upgrade the table.
	 */
	public static function install() {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$table   = self::table();
		$charset = $wpdb->get_charset_collate();
		$sql     = "CREATE TABLE {$table} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			created_at datetime NOT NULL,
			event_type varchar(64) NOT NULL,
			severity varchar(16) NOT NULL DEFAULT 'info',
			user_id bigint(20) unsigned NOT NULL DEFAULT 0,
			username varchar(191) NOT NULL DEFAULT '',
			ip varchar(45) NOT NULL DEFAULT '',
			user_agent varchar(255) NOT NULL DEFAULT '',
			object_type varchar(32) NOT NULL DEFAULT '',
			object_id varchar(191) NOT NULL DEFAULT '',
			message text NOT NULL,
			context longtext NULL,
			PRIMARY KEY  (id),
			KEY created_at (created_at),
			KEY event_type (event_type),
			KEY severity (severity),
			KEY ip (ip)
		) {$charset};";
		dbDelta( $sql );
		update_option( 'anshield_db_version', self::DB_VERSION, false );
	}

	/**
	 * Record an event.
	 *
	 * @param string $type     Machine type, e.g. "auth.login_failed".
	 * @param string $severity info|notice|warning|critical.
	 * @param string $message  Human-readable sentence.
	 * @param array  $args     Optional: user_id, username, object_type, object_id, context (array).
	 * @return int|false Insert ID.
	 */
	public static function log( $type, $severity, $message, array $args = array() ) {
		global $wpdb;

		if ( ! Settings::get( 'log_enabled' ) ) {
			return false;
		}
		if ( ! in_array( $severity, self::SEVERITIES, true ) ) {
			$severity = 'info';
		}

		// Cap low-severity rows so a flood of probes can't fill the database.
		if ( 'info' === $severity ) {
			$bucket = 'anshield_info_' . gmdate( 'YmdH' );
			$count  = (int) get_transient( $bucket );
			set_transient( $bucket, $count + 1, HOUR_IN_SECONDS );
			if ( $count >= 1000 ) {
				return false;
			}
		}

		$user_id  = isset( $args['user_id'] ) ? (int) $args['user_id'] : get_current_user_id();
		$username = isset( $args['username'] ) ? (string) $args['username'] : '';
		if ( '' === $username && $user_id ) {
			$user     = get_userdata( $user_id );
			$username = $user ? $user->user_login : '';
		}

		$event = array(
			'created_at'  => gmdate( 'Y-m-d H:i:s' ),
			'event_type'  => substr( preg_replace( '/[^a-z0-9._-]/', '', strtolower( $type ) ), 0, 64 ),
			'severity'    => $severity,
			'user_id'     => $user_id,
			'username'    => substr( sanitize_user( $username, false ), 0, 191 ),
			'ip'          => defined( 'WP_CLI' ) && WP_CLI ? 'cli' : Request::ip(),
			'user_agent'  => Request::user_agent(),
			'object_type' => isset( $args['object_type'] ) ? substr( sanitize_key( $args['object_type'] ), 0, 32 ) : '',
			'object_id'   => isset( $args['object_id'] ) ? substr( (string) $args['object_id'], 0, 191 ) : '',
			'message'     => wp_strip_all_tags( $message ),
			'context'     => ! empty( $args['context'] ) ? wp_json_encode( $args['context'] ) : null,
		);
		$ok = $wpdb->insert( self::table(), $event ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
		if ( ! $ok ) {
			return false;
		}
		$event['id'] = (int) $wpdb->insert_id;

		/**
		 * Fires after a security event is stored. The SOC sender will hook here.
		 *
		 * @param array $event Stored row.
		 */
		do_action( 'anshield_event_logged', $event );

		return $event['id'];
	}

	/**
	 * Log a noisy event at most once per IP per period, counting the rest.
	 * Use for probes (XML-RPC, username scans) so an attack can't fill the table.
	 *
	 * @param string $type     Event type.
	 * @param string $severity Severity.
	 * @param string $message  Message.
	 * @param int    $period   Seconds.
	 * @return int|false
	 */
	public static function log_throttled( $type, $severity, $message, $period = HOUR_IN_SECONDS ) {
		$key   = 'anshield_t_' . md5( $type . '|' . Request::ip() );
		$count = get_transient( $key );
		if ( false !== $count ) {
			set_transient( $key, (int) $count + 1, $period );
			return false;
		}
		set_transient( $key, 1, $period );
		return self::log(
			$type,
			$severity,
			$message,
			array(
				'user_id' => 0,
				'context' => array( 'note' => 'Repeats from this IP are not logged for an hour.' ),
			)
		);
	}

	/**
	 * Query events.
	 *
	 * @param array $args severity (min), type (prefix), search, per_page, page, since (Y-m-d H:i:s UTC).
	 * @return array { rows: array, total: int }
	 */
	public static function query( array $args = array() ) {
		global $wpdb;
		$table    = self::table();
		$where    = array( '1=1' );
		$params   = array();
		$per_page = isset( $args['per_page'] ) ? max( 1, min( 500, (int) $args['per_page'] ) ) : 50;
		$page     = isset( $args['page'] ) ? max( 1, (int) $args['page'] ) : 1;

		if ( ! empty( $args['severity'] ) && in_array( $args['severity'], self::SEVERITIES, true ) ) {
			$levels       = array_slice( self::SEVERITIES, array_search( $args['severity'], self::SEVERITIES, true ) );
			$where[]      = 'severity IN (' . implode( ',', array_fill( 0, count( $levels ), '%s' ) ) . ')';
			$params       = array_merge( $params, $levels );
		}
		if ( ! empty( $args['type'] ) ) {
			$where[]  = 'event_type LIKE %s';
			$params[] = $wpdb->esc_like( $args['type'] ) . '%';
		}
		if ( ! empty( $args['search'] ) ) {
			$like     = '%' . $wpdb->esc_like( $args['search'] ) . '%';
			$where[]  = '(message LIKE %s OR username LIKE %s OR ip LIKE %s)';
			$params[] = $like;
			$params[] = $like;
			$params[] = $like;
		}
		if ( ! empty( $args['since'] ) ) {
			$where[]  = 'created_at >= %s';
			$params[] = $args['since'];
		}

		$where_sql = implode( ' AND ', $where );
		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery
		$count_sql = "SELECT COUNT(*) FROM {$table} WHERE {$where_sql}";
		$total     = (int) ( $params ? $wpdb->get_var( $wpdb->prepare( $count_sql, $params ) ) : $wpdb->get_var( $count_sql ) );
		$rows_sql  = "SELECT * FROM {$table} WHERE {$where_sql} ORDER BY id DESC LIMIT %d OFFSET %d";
		$rows      = $wpdb->get_results( $wpdb->prepare( $rows_sql, array_merge( $params, array( $per_page, ( $page - 1 ) * $per_page ) ) ), ARRAY_A );
		// phpcs:enable

		return array(
			'rows'  => $rows ? $rows : array(),
			'total' => $total,
		);
	}

	/**
	 * Count events by severity since a time.
	 *
	 * @param string $since UTC datetime.
	 * @return array severity => count.
	 */
	public static function counts_since( $since ) {
		global $wpdb;
		$table = self::table();
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT severity, COUNT(*) AS n FROM {$table} WHERE created_at >= %s GROUP BY severity", $since ), ARRAY_A );
		$out  = array_fill_keys( self::SEVERITIES, 0 );
		foreach ( (array) $rows as $row ) {
			if ( isset( $out[ $row['severity'] ] ) ) {
				$out[ $row['severity'] ] = (int) $row['n'];
			}
		}
		return $out;
	}

	/**
	 * Delete events older than the retention period.
	 *
	 * @return int Rows deleted.
	 */
	public static function prune() {
		global $wpdb;
		$days   = (int) Settings::get( 'log_retention_days' );
		$cutoff = gmdate( 'Y-m-d H:i:s', time() - $days * DAY_IN_SECONDS );
		$table  = self::table();
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery
		return (int) $wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE created_at < %s", $cutoff ) );
	}

	/**
	 * Drop the table (uninstall).
	 */
	public static function uninstall() {
		global $wpdb;
		$table = self::table();
		$wpdb->query( "DROP TABLE IF EXISTS {$table}" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery, WordPress.DB.DirectDatabaseQuery.SchemaChange
	}
}
