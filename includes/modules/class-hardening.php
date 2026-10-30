<?php
/**
 * Core hardening.
 *
 * @package JATSiteShield
 */

namespace JATSiteShield\Modules;

use JATSiteShield\Event_Log;
use JATSiteShield\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Turns off risky WordPress features and adds security headers.
 */
class Hardening {

	const HTACCESS_MARKER = 'JAT Site Shield';

	/**
	 * Hook in.
	 */
	public function register() {
		if ( Settings::get( 'harden_file_edit' ) && ! defined( 'DISALLOW_FILE_EDIT' ) ) {
			define( 'DISALLOW_FILE_EDIT', true );
		}

		if ( Settings::get( 'harden_xmlrpc' ) && ! self::xmlrpc_needed() ) {
			add_filter( 'xmlrpc_enabled', '__return_false' );
			add_filter( 'xmlrpc_methods', '__return_empty_array', 999 );
			add_filter( 'wp_headers', array( $this, 'remove_pingback_header' ) );
			add_filter( 'pings_open', '__return_false', 999 );
			remove_action( 'wp_head', 'rsd_link' );
			add_action( 'plugins_loaded', array( $this, 'block_xmlrpc_request' ), 0 );
		}

		if ( Settings::get( 'harden_user_enum' ) ) {
			add_action( 'parse_request', array( $this, 'block_author_scan' ), 1 );
			add_filter( 'rest_pre_dispatch', array( $this, 'block_rest_users' ), 10, 3 );
			add_filter( 'oembed_response_data', array( $this, 'strip_oembed_author' ) );
			add_filter( 'wp_sitemaps_add_provider', array( $this, 'drop_user_sitemap' ), 10, 2 );
		}

		if ( Settings::get( 'harden_headers' ) ) {
			add_action( 'send_headers', array( $this, 'send_security_headers' ) );
			add_action( 'admin_init', array( $this, 'send_security_headers' ) );
			add_action( 'login_init', array( $this, 'send_security_headers' ) );
		}

		if ( Settings::get( 'harden_hide_version' ) ) {
			add_filter( 'the_generator', '__return_empty_string' );
			add_filter( 'style_loader_src', array( $this, 'strip_core_version' ), 999 );
			add_filter( 'script_loader_src', array( $this, 'strip_core_version' ), 999 );
		}

		if ( Settings::get( 'harden_app_passwords' ) ) {
			add_filter( 'wp_is_application_passwords_available', '__return_false' );
		}
	}

	/**
	 * Whether a plugin that needs XML-RPC (Jetpack) is active.
	 *
	 * @return bool
	 */
	public static function xmlrpc_needed() {
		return (bool) apply_filters( 'jatss_xmlrpc_needed', defined( 'JETPACK__VERSION' ) || class_exists( 'Jetpack' ) );
	}

	/**
	 * Refuse XML-RPC requests outright (pingbacks and multicall included).
	 */
	public function block_xmlrpc_request() {
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			Event_Log::log_throttled( 'harden.xmlrpc_blocked', 'info', 'Blocked an XML-RPC request.' ); // Runs before init, so not translated.
			status_header( 403 );
			header( 'Content-Type: text/plain; charset=utf-8' );
			echo 'XML-RPC is disabled on this site.';
			exit;
		}
	}

	/**
	 * Drop the X-Pingback header.
	 *
	 * @param array $headers Headers.
	 * @return array
	 */
	public function remove_pingback_header( $headers ) {
		unset( $headers['X-Pingback'] );
		return $headers;
	}

	/**
	 * Stop /?author=N from revealing usernames to logged-out visitors.
	 *
	 * @param \WP $wp Request.
	 */
	public function block_author_scan( $wp ) {
		if ( is_user_logged_in() || is_admin() ) {
			return;
		}
		$author = isset( $wp->query_vars['author'] ) ? $wp->query_vars['author'] : '';
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$raw = isset( $_GET['author'] ) && is_string( $_GET['author'] ) ? sanitize_text_field( wp_unslash( $_GET['author'] ) ) : '';
		if ( ( '' !== $author && is_numeric( $author ) ) || ( '' !== $raw && ! is_array( $raw ) && preg_match( '/^\s*-?\d/', (string) $raw ) ) ) {
			Event_Log::log_throttled( 'harden.user_enum_blocked', 'info', __( 'Blocked a username scan (?author=).', 'jat-site-shield' ) );
			wp_safe_redirect( home_url( '/' ), 301 );
			exit;
		}
	}

	/**
	 * Hide the REST users endpoint from people who can't list users.
	 *
	 * @param mixed            $result  Response so far.
	 * @param \WP_REST_Server  $server  Server.
	 * @param \WP_REST_Request $request Request.
	 * @return mixed
	 */
	public function block_rest_users( $result, $server, $request ) {
		$route = untrailingslashit( strtolower( $request->get_route() ) );
		if ( preg_match( '#^/wp/v2/users(/|$)#', $route . '/' ) && ! current_user_can( 'list_users' ) ) {
			// Logged-in users may still read their own record (the editor needs /users/me).
			if ( is_user_logged_in() && preg_match( '#^/wp/v2/users/(me|' . get_current_user_id() . ')$#', $route ) ) {
				return $result;
			}
			return new \WP_Error( 'rest_user_cannot_view', __( 'Sorry, you are not allowed to list users.', 'jat-site-shield' ), array( 'status' => rest_authorization_required_code() ) );
		}
		return $result;
	}

	/**
	 * Remove author name and link from oEmbed responses.
	 *
	 * @param array $data oEmbed data.
	 * @return array
	 */
	public function strip_oembed_author( $data ) {
		unset( $data['author_name'], $data['author_url'] );
		return $data;
	}

	/**
	 * Remove the users sitemap.
	 *
	 * @param \WP_Sitemaps_Provider $provider Provider.
	 * @param string                $name     Name.
	 * @return \WP_Sitemaps_Provider|false
	 */
	public function drop_user_sitemap( $provider, $name ) {
		return 'users' === $name ? false : $provider;
	}

	/**
	 * Security headers. These are safe defaults that don't break themes;
	 * a Content-Security-Policy is left to the site because it's site-specific.
	 */
	public function send_security_headers() {
		if ( headers_sent() ) {
			return;
		}
		header( 'X-Content-Type-Options: nosniff' );
		header( 'X-Frame-Options: SAMEORIGIN' );
		header( 'Referrer-Policy: strict-origin-when-cross-origin' );
		header( 'Permissions-Policy: camera=(), microphone=(), geolocation=(), interest-cohort=()' );
		header( 'Cross-Origin-Opener-Policy: same-origin-allow-popups' );
		if ( Settings::get( 'harden_hsts' ) && is_ssl() ) {
			header( 'Strict-Transport-Security: max-age=31536000' );
		}
	}

	/**
	 * Replace ?ver= with a hash when it equals the WordPress version (the number reveals it).
	 *
	 * @param string $src Asset URL.
	 * @return string
	 */
	public function strip_core_version( $src ) {
		global $wp_version;
		if ( ! is_string( $src ) || false === strpos( $src, 'ver=' . $wp_version ) ) {
			return $src;
		}
		// Swap the version for a hash of it instead of removing it, so browsers and
		// Cloudflare still fetch fresh files after a WordPress update.
		$hash = substr( wp_hash( 'jatss-ver|' . $wp_version ), 0, 8 );
		return add_query_arg( 'ver', $hash, remove_query_arg( 'ver', $src ) );
	}

	/**
	 * Path to the uploads .htaccess.
	 *
	 * @return string
	 */
	public static function uploads_htaccess() {
		$uploads = wp_get_upload_dir();
		return trailingslashit( $uploads['basedir'] ) . '.htaccess';
	}

	/**
	 * Add or remove the "no PHP in uploads" rules (Apache / LiteSpeed).
	 *
	 * @param bool $enable Add (true) or remove (false).
	 * @return bool Written.
	 */
	public static function write_uploads_rules( $enable ) {
		require_once ABSPATH . 'wp-admin/includes/misc.php';
		$file  = self::uploads_htaccess();
		$rules = $enable ? array(
			'<FilesMatch "\.(?i:php[0-9]?|phtml|phar|pht|phps)$">',
			'  <IfModule mod_authz_core.c>',
			'    Require all denied',
			'  </IfModule>',
			'  <IfModule !mod_authz_core.c>',
			'    Order allow,deny',
			'    Deny from all',
			'  </IfModule>',
			'</FilesMatch>',
		) : array();

		if ( ! $enable && ! file_exists( $file ) ) {
			return true;
		}
		if ( ! wp_is_writable( dirname( $file ) ) ) {
			return false;
		}
		return (bool) insert_with_markers( $file, self::HTACCESS_MARKER, $rules );
	}

	/**
	 * Check from outside whether PHP in uploads is really blocked: writes a
	 * harmless test file, requests it over HTTP, then deletes it.
	 *
	 * @return string 'blocked' | 'executes' | 'unknown'
	 */
	public static function test_uploads_php() {
		$uploads = wp_get_upload_dir();
		$name    = 'jatss-test-' . wp_generate_password( 12, false ) . '.php';
		$path    = trailingslashit( $uploads['basedir'] ) . $name;
		$marker  = 'jatss-' . wp_generate_password( 16, false );

		// The file only prints a marker; it reads no input. The marker is split in the
		// source, so seeing it whole proves the PHP ran (not just that the source was served).
		$half = (int) floor( strlen( $marker ) / 2 );
		if ( false === file_put_contents( $path, '<?php echo "' . substr( $marker, 0, $half ) . '" . "' . substr( $marker, $half ) . '";' ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions
			return 'unknown';
		}
		$response = wp_remote_get(
			trailingslashit( $uploads['baseurl'] ) . $name,
			array(
				'timeout'   => 8,
				/** This filter is documented in wp-includes/class-wp-http-streams.php (same as core's loopback checks). */
				'sslverify' => apply_filters( 'https_local_ssl_verify', false ), // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
			)
		);
		wp_delete_file( $path );
		if ( file_exists( $path ) ) {
			Event_Log::log( 'harden.test_file_left', 'warning', sprintf( /* translators: %s: file */ __( 'Could not delete the uploads test file %s. Delete it by hand.', 'jat-site-shield' ), $name ) );
		}

		if ( is_wp_error( $response ) ) {
			return 'unknown';
		}
		$code = (int) wp_remote_retrieve_response_code( $response );
		$body = (string) wp_remote_retrieve_body( $response );
		if ( false !== strpos( $body, $marker ) ) {
			return 'executes';
		}
		return in_array( $code, array( 401, 403, 404, 500 ), true ) || 200 === $code ? 'blocked' : 'unknown';
	}
}
