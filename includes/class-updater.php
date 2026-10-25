<?php
/**
 * Self-updates from GitHub releases.
 *
 * @package AndersonSiteShield
 */

namespace AndersonSiteShield;

defined( 'ABSPATH' ) || exit;

/**
 * Shows new GitHub releases on the Plugins screen and installs them through
 * the normal WordPress updater. Only release assets named
 * anderson-site-shield.zip from the configured repository are accepted.
 */
class Updater {

	const CACHE_KEY = 'anshield_update_release';
	const ASSET     = 'anderson-site-shield.zip';

	/**
	 * Hook in.
	 */
	public function register() {
		add_filter( 'pre_set_site_transient_update_plugins', array( $this, 'inject_update' ) );
		add_filter( 'plugins_api', array( $this, 'plugin_info' ), 20, 3 );
		add_filter( 'upgrader_source_selection', array( $this, 'fix_folder_name' ), 10, 4 );
		add_filter( 'upgrader_pre_download', array( $this, 'check_package_url' ), 10, 4 );
		add_action( 'upgrader_process_complete', array( $this, 'clear_cache' ), 10, 0 );
	}

	/**
	 * Latest release from GitHub (cached 6 hours).
	 *
	 * @param bool $force Skip cache.
	 * @return array|null version, zip, url, notes, published.
	 */
	public static function latest_release( $force = false ) {
		$cached = get_site_transient( self::CACHE_KEY );
		if ( ! $force && is_array( $cached ) ) {
			return isset( $cached['version'] ) ? $cached : null;
		}

		$response = wp_remote_get(
			'https://api.github.com/repos/' . ANSHIELD_GITHUB_REPO . '/releases/latest',
			array(
				'timeout' => 10,
				'headers' => array(
					'Accept'     => 'application/vnd.github+json',
					'User-Agent' => 'Anderson-Site-Shield/' . ANSHIELD_VERSION,
				),
			)
		);

		$release = null;
		if ( ! is_wp_error( $response ) && 200 === (int) wp_remote_retrieve_response_code( $response ) ) {
			$data = json_decode( (string) wp_remote_retrieve_body( $response ), true );
			if ( is_array( $data ) && ! empty( $data['tag_name'] ) && empty( $data['draft'] ) && empty( $data['prerelease'] ) ) {
				$zip = '';
				foreach ( isset( $data['assets'] ) ? (array) $data['assets'] : array() as $asset ) {
					if ( isset( $asset['name'], $asset['browser_download_url'] ) && self::ASSET === $asset['name'] ) {
						$zip = $asset['browser_download_url'];
					}
				}
				if ( $zip && self::is_trusted_url( $zip ) ) {
					$release = array(
						'version'   => ltrim( (string) $data['tag_name'], 'vV' ),
						'zip'       => $zip,
						'url'       => isset( $data['html_url'] ) ? $data['html_url'] : '',
						'notes'     => isset( $data['body'] ) ? (string) $data['body'] : '',
						'published' => isset( $data['published_at'] ) ? $data['published_at'] : '',
					);
				}
			}
		}

		// Cache failures briefly so a GitHub outage doesn't slow every admin page.
		set_site_transient( self::CACHE_KEY, $release ? $release : array( 'none' => true ), $release ? 6 * HOUR_IN_SECONDS : HOUR_IN_SECONDS );
		return $release;
	}

	/**
	 * Only release downloads from this repository are allowed.
	 *
	 * @param string $url URL.
	 * @return bool
	 */
	private static function is_trusted_url( $url ) {
		$prefix = 'https://github.com/' . ANSHIELD_GITHUB_REPO . '/releases/download/';
		return 0 === strpos( $url, $prefix ) && '/' . self::ASSET === substr( $url, -strlen( '/' . self::ASSET ) );
	}

	/**
	 * Add our update to WordPress's update list.
	 *
	 * @param object $transient Update data.
	 * @return object
	 */
	public function inject_update( $transient ) {
		if ( ! is_object( $transient ) ) {
			return $transient;
		}
		$release = self::latest_release();
		$item    = (object) array(
			'id'           => ANSHIELD_GITHUB_REPO,
			'slug'         => 'anderson-site-shield',
			'plugin'       => ANSHIELD_BASENAME,
			'new_version'  => $release ? $release['version'] : ANSHIELD_VERSION,
			'url'          => 'https://github.com/' . ANSHIELD_GITHUB_REPO,
			'package'      => $release ? $release['zip'] : '',
			'requires'     => '6.4',
			'requires_php' => '7.4',
		);
		if ( $release && version_compare( $release['version'], ANSHIELD_VERSION, '>' ) ) {
			$transient->response[ ANSHIELD_BASENAME ] = $item;
		} else {
			$transient->no_update[ ANSHIELD_BASENAME ] = $item;
		}
		return $transient;
	}

	/**
	 * "View details" popup.
	 *
	 * @param mixed  $result Result.
	 * @param string $action Action.
	 * @param object $args   Args.
	 * @return mixed
	 */
	public function plugin_info( $result, $action, $args ) {
		if ( 'plugin_information' !== $action || ! isset( $args->slug ) || 'anderson-site-shield' !== $args->slug ) {
			return $result;
		}
		$release = self::latest_release();
		return (object) array(
			'name'          => 'Anderson Site Shield',
			'slug'          => 'anderson-site-shield',
			'version'       => $release ? $release['version'] : ANSHIELD_VERSION,
			'author'        => '<a href="https://jeremyanderson.tech">Jeremy Anderson</a>',
			'homepage'      => 'https://github.com/' . ANSHIELD_GITHUB_REPO,
			'requires'      => '6.4',
			'requires_php'  => '7.4',
			'last_updated'  => $release ? $release['published'] : '',
			'download_link' => $release ? $release['zip'] : '',
			'sections'      => array(
				'description' => esc_html__( 'Locks WordPress down: login protection, two-factor authentication, core hardening, an activity log and file integrity monitoring.', 'anderson-site-shield' ),
				'changelog'   => $release ? wpautop( esc_html( $release['notes'] ) ) : '',
			),
		);
	}

	/**
	 * Refuse to download our update from anywhere else.
	 *
	 * @param mixed        $reply    Short-circuit.
	 * @param string       $package  URL.
	 * @param \WP_Upgrader $upgrader Upgrader.
	 * @return mixed
	 */
	public function check_package_url( $reply, $package, $upgrader, $hook_extra = array() ) {
		$plugin = isset( $hook_extra['plugin'] ) ? $hook_extra['plugin'] : '';
		if ( ! $plugin ) {
			$plugin = isset( $upgrader->skin->plugin ) ? $upgrader->skin->plugin : ( isset( $upgrader->skin->options['plugin'] ) ? $upgrader->skin->options['plugin'] : '' );
		}
		if ( ANSHIELD_BASENAME === $plugin && is_string( $package ) && ! self::is_trusted_url( $package ) ) {
			return new \WP_Error( 'anshield_untrusted_package', __( 'Refused an update for Anderson Site Shield that did not come from its GitHub releases.', 'anderson-site-shield' ) );
		}
		return $reply;
	}

	/**
	 * Make sure the unzipped folder is named anderson-site-shield.
	 *
	 * @param string       $source        Unzipped path.
	 * @param string       $remote_source Parent.
	 * @param \WP_Upgrader $upgrader      Upgrader.
	 * @param array        $extra         Extra.
	 * @return string|\WP_Error
	 */
	public function fix_folder_name( $source, $remote_source, $upgrader, $extra = array() ) {
		if ( empty( $extra['plugin'] ) || ANSHIELD_BASENAME !== $extra['plugin'] ) {
			return $source;
		}
		$wanted = trailingslashit( $remote_source ) . 'anderson-site-shield/';
		if ( trailingslashit( $source ) === $wanted ) {
			return $source;
		}
		global $wp_filesystem;
		if ( $wp_filesystem && $wp_filesystem->move( $source, $wanted, true ) ) {
			return $wanted;
		}
		return new \WP_Error( 'anshield_rename', __( 'Could not rename the update folder.', 'anderson-site-shield' ) );
	}

	/**
	 * Forget the cached release after an update.
	 */
	public function clear_cache() {
		delete_site_transient( self::CACHE_KEY );
	}
}
