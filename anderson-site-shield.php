<?php
/**
 * Plugin Name:       Anderson Site Shield
 * Plugin URI:        https://github.com/CptNope/Anderson-Site-Shield
 * Description:       Locks WordPress down: login protection, two-factor authentication, core hardening, an activity log and file integrity monitoring.
 * Version:           1.0.0
 * Requires at least: 6.4
 * Requires PHP:      7.4
 * Author:            Jeremy Anderson
 * Author URI:        https://jeremyanderson.tech
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       anderson-site-shield
 * Update URI:        https://github.com/CptNope/Anderson-Site-Shield
 *
 * @package AndersonSiteShield
 */

defined( 'ABSPATH' ) || exit;

define( 'ANSHIELD_VERSION', '1.0.0' );
define( 'ANSHIELD_FILE', __FILE__ );
define( 'ANSHIELD_DIR', plugin_dir_path( __FILE__ ) );
define( 'ANSHIELD_URL', plugin_dir_url( __FILE__ ) );
define( 'ANSHIELD_BASENAME', plugin_basename( __FILE__ ) );
define( 'ANSHIELD_GITHUB_REPO', 'CptNope/Anderson-Site-Shield' );

/*
 * Recovery switch. Add define( 'ANSHIELD_SAFE_MODE', true ); to wp-config.php
 * to turn off the custom login URL, two-factor prompts and login lockouts
 * while keeping logging and hardening on. Use it if you are locked out.
 */
if ( ! defined( 'ANSHIELD_SAFE_MODE' ) ) {
	define( 'ANSHIELD_SAFE_MODE', false );
}

spl_autoload_register(
	static function ( $class ) {
		$prefix = 'AndersonSiteShield\\';
		if ( 0 !== strpos( $class, $prefix ) ) {
			return;
		}
		$relative = substr( $class, strlen( $prefix ) );
		$parts    = explode( '\\', $relative );
		$name     = array_pop( $parts );
		$file     = 'class-' . strtolower( str_replace( '_', '-', $name ) ) . '.php';
		$subdir   = $parts ? strtolower( implode( '/', $parts ) ) . '/' : '';
		$path     = ANSHIELD_DIR . 'includes/' . $subdir . $file;
		if ( is_readable( $path ) ) {
			require_once $path;
		}
	}
);

register_activation_hook( __FILE__, array( 'AndersonSiteShield\\Plugin', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'AndersonSiteShield\\Plugin', 'deactivate' ) );

AndersonSiteShield\Plugin::instance()->boot();
