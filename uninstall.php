<?php
/**
 * Uninstall: remove all plugin data.
 *
 * @package JATSiteShield
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

/**
 * Remove this plugin's data from the current site.
 */
function jatss_uninstall_site() {
	global $wpdb;

	$uploads = wp_get_upload_dir();
	$file    = trailingslashit( $uploads['basedir'] ) . '.htaccess';
	if ( file_exists( $file ) ) {
		require_once ABSPATH . 'wp-admin/includes/misc.php';
		insert_with_markers( $file, 'JAT Site Shield', array() );
	}

	$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}jatss_events" ); // phpcs:ignore WordPress.DB

	foreach ( array( 'jatss_settings', 'jatss_db_version', 'jatss_lockouts', 'jatss_fim_state', 'jatss_fim_last', 'jatss_fim_ack', 'jatss_fim_baseline', 'jatss_fim_rebase', 'jatss_uploads_test' ) as $option ) {
		delete_option( $option );
	}
	$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE 'jatss\\_2fa\\_lock\\_%' OR option_name LIKE '\\_transient\\_jatss\\_%' OR option_name LIKE '\\_transient\\_timeout\\_jatss\\_%' OR option_name LIKE '\\_site\\_transient\\_jatss\\_%' OR option_name LIKE '\\_site\\_transient\\_timeout\\_jatss\\_%'" ); // phpcs:ignore WordPress.DB

	wp_clear_scheduled_hook( 'jatss_daily' );
	wp_clear_scheduled_hook( 'jatss_fim_tick' );
}

if ( is_multisite() ) {
	foreach ( get_sites( array( 'fields' => 'ids', 'number' => 0 ) ) as $jatss_site_id ) {
		switch_to_blog( $jatss_site_id );
		jatss_uninstall_site();
		restore_current_blog();
	}
} else {
	jatss_uninstall_site();
}

// Two-factor secrets and other per-user data (users are shared across a network).
global $wpdb;
$wpdb->query( "DELETE FROM {$wpdb->usermeta} WHERE meta_key LIKE 'jatss\\_%'" ); // phpcs:ignore WordPress.DB

// The two-factor key is useless once the secrets are gone.
if ( file_exists( WP_CONTENT_DIR . '/jatss-key.php' ) ) {
	wp_delete_file( WP_CONTENT_DIR . '/jatss-key.php' );
}
