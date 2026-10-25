<?php
/**
 * Uninstall: remove all plugin data.
 *
 * @package AndersonSiteShield
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

/**
 * Remove this plugin's data from the current site.
 */
function anshield_uninstall_site() {
	global $wpdb;

	$uploads = wp_get_upload_dir();
	$file    = trailingslashit( $uploads['basedir'] ) . '.htaccess';
	if ( file_exists( $file ) ) {
		require_once ABSPATH . 'wp-admin/includes/misc.php';
		insert_with_markers( $file, 'Anderson Site Shield', array() );
	}

	$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}anshield_events" ); // phpcs:ignore WordPress.DB

	foreach ( array( 'anshield_settings', 'anshield_db_version', 'anshield_lockouts', 'anshield_fim_state', 'anshield_fim_last', 'anshield_fim_ack', 'anshield_fim_baseline', 'anshield_fim_rebase', 'anshield_uploads_test' ) as $option ) {
		delete_option( $option );
	}
	$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE 'anshield\\_2fa\\_lock\\_%' OR option_name LIKE '\\_transient\\_anshield\\_%' OR option_name LIKE '\\_transient\\_timeout\\_anshield\\_%' OR option_name LIKE '\\_site\\_transient\\_anshield\\_%' OR option_name LIKE '\\_site\\_transient\\_timeout\\_anshield\\_%'" ); // phpcs:ignore WordPress.DB

	wp_clear_scheduled_hook( 'anshield_daily' );
	wp_clear_scheduled_hook( 'anshield_fim_tick' );
}

if ( is_multisite() ) {
	foreach ( get_sites( array( 'fields' => 'ids', 'number' => 0 ) ) as $anshield_site_id ) {
		switch_to_blog( $anshield_site_id );
		anshield_uninstall_site();
		restore_current_blog();
	}
} else {
	anshield_uninstall_site();
}

// Two-factor secrets and other per-user data (users are shared across a network).
global $wpdb;
$wpdb->query( "DELETE FROM {$wpdb->usermeta} WHERE meta_key LIKE 'anshield\\_%'" ); // phpcs:ignore WordPress.DB

// The two-factor key is useless once the secrets are gone.
if ( file_exists( WP_CONTENT_DIR . '/anshield-key.php' ) ) {
	wp_delete_file( WP_CONTENT_DIR . '/anshield-key.php' );
}
