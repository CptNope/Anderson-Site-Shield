<?php
/**
 * Custom login URL: serves the login page at a private address and returns
 * "Not Found" for wp-login.php and for /wp-admin when logged out.
 *
 * @package JATSiteShield
 */

namespace JATSiteShield\Modules;

use JATSiteShield\Event_Log;
use JATSiteShield\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Moves wp-login.php to /{slug}.
 *
 * Recovery if you forget the address: add define( 'JATSS_SAFE_MODE', true );
 * to wp-config.php, or run `wp jat-shield login-url` to print it.
 */
class Login_Url {

	/**
	 * Whether this request is for the custom login address.
	 *
	 * @var bool
	 */
	private $is_custom = false;

	/**
	 * Whether this request went straight to wp-login.php.
	 *
	 * @var bool
	 */
	private $is_direct = false;

	/**
	 * Slugs that would clash with WordPress paths.
	 *
	 * @var string[]
	 */
	const RESERVED = array( 'wp-admin', 'wp-login', 'wp-login-php', 'wp-content', 'wp-includes', 'wp-json', 'login', 'admin', 'dashboard', 'feed', 'xmlrpc', 'wp-signup', 'wp-activate', 'wp-cron', 'index', 'robots', 'sitemap', 'wp-sitemap', 'embed', 'trackback', 'comments', 'search', 'page', 'author', 'category', 'tag' );

	/**
	 * Whether the feature is on for this site.
	 *
	 * @return bool
	 */
	public static function enabled() {
		return Settings::get( 'custom_login_enabled' )
			&& '' !== (string) Settings::get( 'custom_login_slug' )
			&& ! JATSS_SAFE_MODE
			&& ! is_multisite()
			&& ! ( defined( 'WP_CLI' ) && WP_CLI );
	}

	/**
	 * The full custom login URL.
	 *
	 * @param string $query Query string without "?".
	 * @return string
	 */
	public static function url( $query = '' ) {
		$slug = (string) Settings::get( 'custom_login_slug' );
		if ( ! get_option( 'permalink_structure' ) ) {
			// Plain permalinks: the server may not route unknown paths to WordPress, so use ?slug.
			return home_url( '/' ) . '?' . $slug . ( '' !== $query ? '&' . $query : '' );
		}
		$url = home_url( '/' . $slug );
		if ( '/' === substr( (string) get_option( 'permalink_structure' ), -1 ) ) {
			$url = trailingslashit( $url );
		}
		return '' !== $query ? $url . '?' . $query : $url;
	}

	/**
	 * Check a proposed slug.
	 *
	 * @param string $slug Sanitized slug.
	 * @return true|\WP_Error
	 */
	public static function validate_slug( $slug ) {
		if ( strlen( $slug ) < 4 ) {
			return new \WP_Error( 'jatss_slug', __( 'The login address must be at least 4 characters.', 'jat-site-shield' ) );
		}
		if ( in_array( $slug, self::RESERVED, true ) || 0 === strpos( $slug, 'wp-' ) ) {
			return new \WP_Error( 'jatss_slug', __( 'That login address is reserved by WordPress or too easy to guess. Pick another.', 'jat-site-shield' ) );
		}
		$types = get_post_types( array( 'public' => true ) );
		if ( get_page_by_path( $slug, OBJECT, array_values( $types ) ) ) {
			return new \WP_Error( 'jatss_slug', __( 'A page or post already uses that address. Pick another.', 'jat-site-shield' ) );
		}
		return true;
	}

	/**
	 * Hook in.
	 */
	public function register() {
		if ( ! self::enabled() ) {
			return;
		}

		$this->classify_request();

		add_action( 'wp_loaded', array( $this, 'route' ), 1 );
		add_filter( 'site_url', array( $this, 'filter_url' ), 100, 1 );
		add_filter( 'network_site_url', array( $this, 'filter_url' ), 100, 1 );
		add_filter( 'wp_redirect', array( $this, 'filter_url' ), 100, 1 );
		add_filter( 'login_url', array( $this, 'filter_url' ), 100, 1 );
		add_filter( 'logout_url', array( $this, 'filter_url' ), 100, 1 );
		add_filter( 'lostpassword_url', array( $this, 'filter_url' ), 100, 1 );
		add_filter( 'register_url', array( $this, 'filter_url' ), 100, 1 );
		remove_action( 'template_redirect', 'wp_redirect_admin_locations', 1000 );
	}

	/**
	 * Work out what this request is for, from its path and the script PHP is running.
	 */
	private function classify_request() {
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$path = (string) strtok( $uri, '?#' );
		// "//wp-login.php" parses as a host name, and servers treat "//" as "/", so normalize by hand.
		$path = rawurldecode( $path );
		$path = (string) preg_replace( '#/+#', '/', '/' . $path );
		$path = strtolower( untrailingslashit( $path ) );

		$home_path = strtolower( untrailingslashit( (string) wp_parse_url( home_url(), PHP_URL_PATH ) ) );
		$slug      = (string) Settings::get( 'custom_login_slug' );

		$this->is_custom = $path === $home_path . '/' . strtolower( $slug )
			|| ( ! get_option( 'permalink_structure' ) && $home_path === $path && isset( $_GET[ $slug ] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		$script = isset( $_SERVER['SCRIPT_FILENAME'] ) ? strtolower( basename( (string) wp_unslash( $_SERVER['SCRIPT_FILENAME'] ) ) ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$blocked = array( 'wp-login.php', 'wp-register.php', 'wp-signup.php', 'wp-activate.php' );
		$by_path = (bool) preg_match( '#/(wp-login|wp-register|wp-signup|wp-activate)\.php(/|$)#', $path . '/' );

		$this->is_direct = ! $this->is_custom && ( $by_path || in_array( $script, $blocked, true ) );

		// Password-protected posts post to wp-login.php?action=postpass. Allow it: it only sets the post password cookie.
		$action = isset( $_GET['action'] ) && is_string( $_GET['action'] ) ? $_GET['action'] : ''; // phpcs:ignore WordPress.Security
		if ( $this->is_direct && 'postpass' === $action && 'wp-login.php' === ( $script ? $script : basename( $path ) ) ) {
			$this->is_direct = false;
		}
	}

	/**
	 * Serve, block or pass the request.
	 */
	public function route() {
		global $pagenow;

		if ( $this->is_custom ) {
			// Serve the real login page. wp-login.php expects these as globals.
			global $error, $interim_login, $action, $user_login; // phpcs:ignore
			$pagenow = 'wp-login.php'; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
			require_once ABSPATH . 'wp-login.php';
			exit;
		}

		if ( $this->is_direct ) {
			Event_Log::log_throttled( 'auth.login_page_probe', 'info', __( 'Blocked a request to wp-login.php (custom login URL is on).', 'jat-site-shield' ) );
			$this->not_found();
		}

		if ( is_admin() && ! is_user_logged_in() && ! wp_doing_ajax() && ! wp_doing_cron() && 'admin-post.php' !== $pagenow ) {
			$this->not_found();
		}
	}

	/**
	 * Whether this request may be shown the custom address: only someone
	 * already on the login page, or a logged-in user. Logged-out visitors
	 * anywhere else see plain wp-login.php links, which return "Not Found".
	 *
	 * @return bool
	 */
	private function may_reveal() {
		if ( $this->is_custom ) {
			return true;
		}
		return did_action( 'plugins_loaded' ) && function_exists( 'is_user_logged_in' ) && is_user_logged_in();
	}

	/**
	 * Rewrite any wp-login.php URL to the custom address.
	 *
	 * @param string $url URL (absolute or relative).
	 * @return string
	 */
	public function filter_url( $url ) {
		if ( ! is_string( $url ) || false === stripos( $url, 'wp-login.php' ) || ! $this->may_reveal() ) {
			return $url;
		}
		$hash = '';
		$pos  = strpos( $url, '#' );
		if ( false !== $pos ) {
			$hash = substr( $url, $pos );
			$url  = substr( $url, 0, $pos );
		}
		$parts = explode( '?', $url, 2 );
		if ( ! preg_match( '#(^|/)wp-login\.php$#i', $parts[0] ) ) {
			return $url . $hash;
		}
		$query = isset( $parts[1] ) ? $parts[1] : '';
		if ( preg_match( '/(^|&)action=postpass(&|$)/', $query ) ) {
			return $url . $hash;
		}
		return self::url( $query ) . $hash;
	}

	/**
	 * Send a bare 404 and stop.
	 */
	private function not_found() {
		status_header( 404 );
		nocache_headers();
		header( 'Content-Type: text/html; charset=utf-8' );
		echo '<!doctype html><html><head><meta name="robots" content="noindex"><title>Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>';
		exit;
	}
}
