<?php
/**
 * WP-CLI commands.
 *
 * @package JATSiteShield
 */

namespace JATSiteShield;

use JATSiteShield\Modules\File_Integrity;
use JATSiteShield\Modules\Login_Protection;
use JATSiteShield\Modules\Login_Url;
use JATSiteShield\Modules\Two_Factor;

defined( 'ABSPATH' ) || exit;

/**
 * Manage JAT Site Shield from the command line.
 */
class CLI {

	/**
	 * Show which protections are on.
	 *
	 * ## EXAMPLES
	 *
	 *     wp jat-shield status
	 *
	 * @param array $args       Positional.
	 * @param array $assoc_args Named.
	 */
	public function status( $args, $assoc_args ) {
		$rows = array();
		foreach ( Admin\Admin::checks() as $check ) {
			$rows[] = array(
				'protection' => $check['label'],
				'status'     => $check['ok'] ? 'on' : ( empty( $check['optional'] ) ? 'OFF' : 'optional' ),
				'note'       => $check['note'],
			);
		}
		\WP_CLI\Utils\format_items( isset( $assoc_args['format'] ) ? $assoc_args['format'] : 'table', $rows, array( 'protection', 'status', 'note' ) );
		if ( JATSS_SAFE_MODE ) {
			\WP_CLI::warning( 'JATSS_SAFE_MODE is on: custom login URL, two-factor and lockouts are paused.' );
		}
	}

	/**
	 * Print the custom login URL.
	 *
	 * @subcommand login-url
	 */
	public function login_url() {
		if ( ! Settings::get( 'custom_login_enabled' ) ) {
			\WP_CLI::log( 'Custom login URL is off. Login page: ' . site_url( 'wp-login.php' ) );
			return;
		}
		\WP_CLI::log( Login_Url::url() );
	}

	/**
	 * Lift login lockouts.
	 *
	 * ## OPTIONS
	 *
	 * <ip>
	 * : IP address, or "all".
	 *
	 * ## EXAMPLES
	 *
	 *     wp jat-shield unlock 203.0.113.9
	 *     wp jat-shield unlock all
	 *
	 * @param array $args Positional.
	 */
	public function unlock( $args ) {
		$ip = $args[0];
		if ( 'all' !== $ip && ! Request::is_valid_ip_or_cidr( $ip ) ) {
			\WP_CLI::error( 'Not a valid IP address.' );
		}
		$n = Login_Protection::unlock( $ip );
		\WP_CLI::success( sprintf( 'Cleared %d lockout(s).', $n ) );
	}

	/**
	 * List current lockouts.
	 */
	public function lockouts() {
		$rows = array();
		foreach ( Login_Protection::lockouts() as $ip => $until ) {
			$rows[] = array(
				'ip'    => $ip,
				'until' => gmdate( 'Y-m-d H:i:s', $until ) . ' UTC',
			);
		}
		\WP_CLI\Utils\format_items( 'table', $rows, array( 'ip', 'until' ) );
	}

	/**
	 * Turn off two-factor for a user (they can set it up again).
	 *
	 * ## OPTIONS
	 *
	 * <user>
	 * : User ID, login or email.
	 *
	 * ## EXAMPLES
	 *
	 *     wp jat-shield reset-2fa jeremy
	 *
	 * @subcommand reset-2fa
	 * @param array $args Positional.
	 */
	public function reset_2fa( $args ) {
		$key  = $args[0];
		$user = is_numeric( $key ) ? get_user_by( 'id', (int) $key ) : ( is_email( $key ) ? get_user_by( 'email', $key ) : get_user_by( 'login', $key ) );
		if ( ! $user ) {
			\WP_CLI::error( 'User not found.' );
		}
		Two_Factor::reset( $user->ID, 'reset with WP-CLI' );
		\WP_CLI::success( sprintf( 'Two-factor reset for %s.', $user->user_login ) );
	}

	/**
	 * Run a file integrity scan now and print the findings.
	 *
	 * ## OPTIONS
	 *
	 * [--all]
	 * : Include informational findings.
	 *
	 * [--format=<format>]
	 * : table, json or csv.
	 * ---
	 * default: table
	 * ---
	 *
	 * @param array $args       Positional.
	 * @param array $assoc_args Named.
	 */
	public function scan( $args, $assoc_args ) {
		$fim = Plugin::instance()->module( 'fim' );
		$fim->start_scan( 'cli' );
		wp_clear_scheduled_hook( File_Integrity::CRON_TICK );
		$state = File_Integrity::state();
		while ( 'running' === $state['status'] ) {
			delete_transient( 'jatss_fim_lock' );
			$fim->tick( 3600 );
			$state = File_Integrity::state();
		}
		$last = File_Integrity::last();
		$rows = array();
		foreach ( $last['findings'] as $f ) {
			if ( 'info' === $f['severity'] && empty( $assoc_args['all'] ) ) {
				continue;
			}
			$rows[] = array(
				'severity' => $f['severity'],
				'kind'     => $f['kind'],
				'path'     => $f['path'],
				'accepted' => File_Integrity::is_acknowledged( $f ) ? 'yes' : '',
			);
		}
		foreach ( (array) $last['notes'] as $target => $note ) {
			\WP_CLI::debug( $target . ': ' . $note, 'jat-shield' );
		}
		if ( ! $rows ) {
			\WP_CLI::success( 'No issues found.' );
			return;
		}
		\WP_CLI\Utils\format_items( $assoc_args['format'], $rows, array( 'severity', 'kind', 'path', 'accepted' ) );
	}

	/**
	 * Show recent events.
	 *
	 * ## OPTIONS
	 *
	 * [--severity=<severity>]
	 * : Minimum severity: info, notice, warning, critical.
	 *
	 * [--count=<count>]
	 * : How many.
	 * ---
	 * default: 20
	 * ---
	 *
	 * [--format=<format>]
	 * : table, json or csv.
	 * ---
	 * default: table
	 * ---
	 *
	 * @param array $args       Positional.
	 * @param array $assoc_args Named.
	 */
	public function log( $args, $assoc_args ) {
		$result = Event_Log::query(
			array(
				'severity' => isset( $assoc_args['severity'] ) ? $assoc_args['severity'] : '',
				'per_page' => (int) $assoc_args['count'],
			)
		);
		\WP_CLI\Utils\format_items( $assoc_args['format'], $result['rows'], array( 'created_at', 'severity', 'event_type', 'username', 'ip', 'message' ) );
	}
}
