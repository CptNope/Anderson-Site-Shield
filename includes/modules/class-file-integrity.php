<?php
/**
 * File integrity monitoring.
 *
 * @package JATSiteShield
 */

namespace JATSiteShield\Modules;

use JATSiteShield\Event_Log;
use JATSiteShield\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Compares WordPress core and WordPress.org plugins against the official
 * checksums, flags unknown PHP files in core folders and PHP files in uploads.
 *
 * Scans run in steps on WP-Cron so a large site never hits a timeout.
 */
class File_Integrity {

	const STATE_OPTION = 'jatss_fim_state';
	const LAST_OPTION  = 'jatss_fim_last';
	const ACK_OPTION   = 'jatss_fim_ack';
	const CRON_TICK    = 'jatss_fim_tick';
	const TIME_BUDGET  = 20;
	const MAX_PER_KIND = 300;
	const BASE_OPTION  = 'jatss_fim_baseline';
	const REBASE_OPT   = 'jatss_fim_rebase';

	const PHP_EXT = '/\.(php[0-9]?|phtml|phar|pht|phps|inc)$/i';

	/**
	 * Files people often delete on purpose; missing ones are only informational.
	 *
	 * @var string[]
	 */
	const OPTIONAL_CORE = array( 'readme.html', 'license.txt', 'wp-config-sample.php', 'xmlrpc.php' );

	/**
	 * Hook in.
	 */
	public function register() {
		add_action( self::CRON_TICK, array( $this, 'tick' ) );
		add_action( 'upgrader_process_complete', array( $this, 'rebase_after_update' ), 10, 2 );
	}

	/**
	 * After a theme or plugin update, take a fresh baseline for it on the
	 * next scan instead of reporting every changed file.
	 *
	 * @param \WP_Upgrader $upgrader Upgrader.
	 * @param array        $extra    Details.
	 */
	public function rebase_after_update( $upgrader, $extra ) {
		$targets = (array) get_option( self::REBASE_OPT, array() );
		$type    = isset( $extra['type'] ) ? $extra['type'] : '';
		if ( 'plugin' === $type ) {
			$items = isset( $extra['plugins'] ) ? (array) $extra['plugins'] : ( isset( $extra['plugin'] ) ? array( $extra['plugin'] ) : array() );
			if ( ! $items && method_exists( $upgrader, 'plugin_info' ) && $upgrader->plugin_info() ) {
				$items = array( $upgrader->plugin_info() );
			}
			foreach ( $items as $item ) {
				$targets[] = 'plugins/' . dirname( $item );
			}
		} elseif ( 'theme' === $type ) {
			$items = isset( $extra['themes'] ) ? (array) $extra['themes'] : ( isset( $extra['theme'] ) ? array( $extra['theme'] ) : array() );
			if ( ! $items && method_exists( $upgrader, 'theme_info' ) && $upgrader->theme_info() ) {
				$items = array( $upgrader->theme_info()->get_stylesheet() );
			}
			foreach ( $items as $item ) {
				$targets[] = 'themes/' . $item;
			}
		}
		update_option( self::REBASE_OPT, array_values( array_unique( $targets ) ), false );
	}

	/* ------------------------------------------------------------------ */
	/* Scan control                                                        */
	/* ------------------------------------------------------------------ */

	/**
	 * Current scan state.
	 *
	 * @return array
	 */
	public static function state() {
		$state = get_option( self::STATE_OPTION, array() );
		return wp_parse_args(
			is_array( $state ) ? $state : array(),
			array(
				'status'   => 'idle',
				'queue'    => array(),
				'done'     => 0,
				'total'    => 0,
				'started'  => 0,
				'trigger'  => '',
				'findings' => array(),
				'notes'    => array(),
			)
		);
	}

	/**
	 * Last finished scan.
	 *
	 * @return array|null
	 */
	public static function last() {
		$last = get_option( self::LAST_OPTION, null );
		return is_array( $last ) ? $last : null;
	}

	/**
	 * Begin a scan (no-op if one is running and recent).
	 *
	 * @param string $trigger Who started it.
	 * @return bool Started.
	 */
	public function start_scan( $trigger = 'manual' ) {
		$state = self::state();
		if ( 'running' === $state['status'] && time() - (int) $state['started'] < HOUR_IN_SECONDS ) {
			return false;
		}

		$queue = array( 'core' );
		if ( Settings::get( 'fim_plugins' ) ) {
			foreach ( array_keys( self::plugins() ) as $slug ) {
				$queue[] = 'plugin:' . $slug;
			}
		}
		$queue[] = 'content';
		$queue[] = 'baseline:mu-plugins';
		foreach ( (array) glob( get_theme_root() . '/*', GLOB_ONLYDIR ) as $theme ) {
			$queue[] = 'baseline:themes/' . basename( $theme );
		}
		foreach ( self::upload_parts() as $part ) {
			$queue[] = 'uploads:' . $part;
		}

		update_option(
			self::STATE_OPTION,
			array(
				'status'   => 'running',
				'queue'    => $queue,
				'done'     => 0,
				'total'    => count( $queue ),
				'started'  => time(),
				'trigger'  => $trigger,
				'findings' => array(),
				'kinds'    => array(),
				'notes'    => array(),
			),
			false
		);
		wp_clear_scheduled_hook( self::CRON_TICK );
		wp_schedule_single_event( time() + 5, self::CRON_TICK );
		return true;
	}

	/**
	 * Work through the queue until the time budget runs out.
	 *
	 * @param int $budget Seconds.
	 */
	public function tick( $budget = self::TIME_BUDGET ) {
		$state = self::state();
		if ( 'running' !== $state['status'] ) {
			return;
		}
		$lock = 'jatss_fim_lock';
		if ( get_transient( $lock ) ) {
			return;
		}
		set_transient( $lock, 1, 2 * self::TIME_BUDGET + 10 );

		$deadline = microtime( true ) + (int) $budget;

		while ( $state['queue'] && microtime( true ) < $deadline ) {
			$target = array_shift( $state['queue'] );
			$result = $this->scan_target( $target );
			foreach ( $result['findings'] as $finding ) {
				$kind = $finding['kind'];
				$have = isset( $state['kinds'][ $kind ] ) ? $state['kinds'][ $kind ] : 0;
				if ( $have < self::MAX_PER_KIND ) {
					$state['findings'][]     = $finding;
					$state['kinds'][ $kind ] = $have + 1;
				} else {
					$state['notes'][ 'cap:' . $kind ] = sprintf(
						/* translators: 1: number, 2: kind */
						__( 'Only the first %1$d %2$s are listed.', 'jat-site-shield' ),
						self::MAX_PER_KIND,
						self::kind_label( $kind )
					);
				}
			}
			if ( '' !== $result['note'] ) {
				$state['notes'][ $target ] = $result['note'];
			}
			++$state['done'];
			update_option( self::STATE_OPTION, $state, false );
		}

		delete_transient( $lock );

		if ( $state['queue'] ) {
			wp_schedule_single_event( time() + 30, self::CRON_TICK );
			return;
		}
		$this->finish( $state );
	}

	/**
	 * Save results and report anything new.
	 *
	 * @param array $state Finished state.
	 */
	private function finish( array $state ) {
		$previous = self::last();
		$prev_ids = array();
		if ( $previous ) {
			foreach ( $previous['findings'] as $f ) {
				$prev_ids[ $f['path'] . '|' . $f['hash'] ] = true;
			}
		}
		$acks = (array) get_option( self::ACK_OPTION, array() );

		$new = array();
		foreach ( $state['findings'] as $f ) {
			if ( isset( $acks[ $f['path'] ] ) && $acks[ $f['path'] ] === $f['hash'] ) {
				continue;
			}
			if ( ! isset( $prev_ids[ $f['path'] . '|' . $f['hash'] ] ) && 'info' !== $f['severity'] ) {
				$new[] = $f;
			}
		}

		update_option(
			self::LAST_OPTION,
			array(
				'finished' => time(),
				'started'  => (int) $state['started'],
				'trigger'  => $state['trigger'],
				'targets'  => (int) $state['total'],
				'findings' => $state['findings'],
				'notes'    => $state['notes'],
			),
			false
		);
		update_option(
			self::STATE_OPTION,
			array(
				'status' => 'idle',
				'queue'  => array(),
			),
			false
		);

		if ( $new ) {
			$order    = array_flip( Event_Log::SEVERITIES );
			$worst    = 'notice';
			$by_kind  = array();
			foreach ( $new as $f ) {
				if ( $order[ $f['severity'] ] > $order[ $worst ] ) {
					$worst = $f['severity'];
				}
				$by_kind[ $f['kind'] ] = isset( $by_kind[ $f['kind'] ] ) ? $by_kind[ $f['kind'] ] + 1 : 1;
			}
			$parts = array();
			foreach ( $by_kind as $kind => $n ) {
				$parts[] = $n . ' ' . self::kind_label( $kind );
			}
			Event_Log::log(
				'fim.changes',
				$worst,
				sprintf(
					/* translators: %s: summary */
					__( 'File integrity scan found new issues: %s.', 'jat-site-shield' ),
					implode( ', ', $parts )
				),
				array(
					'user_id' => 0,
					'context' => array( 'files' => array_slice( wp_list_pluck( $new, 'path' ), 0, 50 ) ),
				)
			);
		} elseif ( 'manual' === $state['trigger'] ) {
			Event_Log::log( 'fim.clean', 'info', __( 'File integrity scan finished with no new issues.', 'jat-site-shield' ) );
		}
	}

	/**
	 * Human label for a finding kind.
	 *
	 * @param string $kind   Kind.
	 * @param bool   $single One file (table rows) rather than a count.
	 * @return string
	 */
	public static function kind_label( $kind, $single = false ) {
		if ( $single ) {
			$one = array(
				'core_modified'   => __( 'Modified core file', 'jat-site-shield' ),
				'core_missing'    => __( 'Missing core file', 'jat-site-shield' ),
				'core_unknown'    => __( 'Not part of WordPress', 'jat-site-shield' ),
				'core_leftover'   => __( 'Left over from an old update', 'jat-site-shield' ),
				'plugin_modified' => __( 'Modified plugin file', 'jat-site-shield' ),
				'plugin_unknown'  => __( 'Not part of the plugin', 'jat-site-shield' ),
				'uploads_php'     => __( 'PHP file in uploads', 'jat-site-shield' ),
				'content_unknown' => __( 'Unexpected PHP in wp-content', 'jat-site-shield' ),
				'new_php'         => __( 'New PHP file since last scan', 'jat-site-shield' ),
				'changed_php'     => __( 'PHP file changed since last scan', 'jat-site-shield' ),
			);
			return isset( $one[ $kind ] ) ? $one[ $kind ] : $kind;
		}
		$labels = array(
			'core_modified'   => __( 'modified core files', 'jat-site-shield' ),
			'core_missing'    => __( 'missing core files', 'jat-site-shield' ),
			'core_unknown'    => __( 'unknown files in core folders', 'jat-site-shield' ),
			'core_leftover'   => __( 'files left over from older WordPress versions', 'jat-site-shield' ),
			'plugin_modified' => __( 'modified plugin files', 'jat-site-shield' ),
			'plugin_unknown'  => __( 'unknown PHP files in plugins', 'jat-site-shield' ),
			'uploads_php'     => __( 'PHP files in uploads', 'jat-site-shield' ),
			'content_unknown' => __( 'unexpected PHP files in wp-content', 'jat-site-shield' ),
			'new_php'         => __( 'new PHP files in themes, mu-plugins or custom plugins', 'jat-site-shield' ),
			'changed_php'     => __( 'changed PHP files in themes, mu-plugins or custom plugins', 'jat-site-shield' ),
		);
		return isset( $labels[ $kind ] ) ? $labels[ $kind ] : $kind;
	}

	/**
	 * Accept a finding so it stops being reported (until the file changes).
	 *
	 * @param string $path Relative path.
	 * @return bool
	 */
	public static function acknowledge( $path ) {
		$last = self::last();
		if ( ! $last ) {
			return false;
		}
		foreach ( $last['findings'] as $f ) {
			if ( $f['path'] === $path ) {
				$acks          = (array) get_option( self::ACK_OPTION, array() );
				$acks[ $path ] = $f['hash'];
				update_option( self::ACK_OPTION, $acks, false );
				if ( in_array( $f['kind'], array( 'new_php', 'changed_php' ), true ) ) {
					self::accept_into_baseline( $path );
				}
				Event_Log::log( 'fim.acknowledged', 'notice', sprintf( /* translators: %s: path */ __( 'File integrity finding accepted: %s.', 'jat-site-shield' ), $path ) );
				return true;
			}
		}
		return false;
	}

	/**
	 * Accept every open finding from the last scan.
	 *
	 * @return int Accepted.
	 */
	public static function acknowledge_all() {
		$last = self::last();
		if ( ! $last ) {
			return 0;
		}
		$acks = (array) get_option( self::ACK_OPTION, array() );
		$n    = 0;
		foreach ( $last['findings'] as $f ) {
			if ( 'info' === $f['severity'] || self::is_acknowledged( $f ) ) {
				continue;
			}
			$acks[ $f['path'] ] = $f['hash'];
			if ( in_array( $f['kind'], array( 'new_php', 'changed_php' ), true ) ) {
				self::accept_into_baseline( $f['path'] );
			}
			++$n;
		}
		update_option( self::ACK_OPTION, $acks, false );
		if ( $n ) {
			Event_Log::log( 'fim.acknowledged_all', 'warning', sprintf( /* translators: %d: count */ __( 'All %d open file integrity findings were accepted at once.', 'jat-site-shield' ), $n ) );
		}
		return $n;
	}

	/**
	 * Whether a finding is accepted.
	 *
	 * @param array $finding Finding.
	 * @return bool
	 */
	public static function is_acknowledged( array $finding ) {
		$acks = (array) get_option( self::ACK_OPTION, array() );
		return isset( $acks[ $finding['path'] ] ) && $acks[ $finding['path'] ] === $finding['hash'];
	}

	/* ------------------------------------------------------------------ */
	/* Targets                                                             */
	/* ------------------------------------------------------------------ */

	/**
	 * Scan one queue entry.
	 *
	 * @param string $target Target.
	 * @return array findings, note.
	 */
	private function scan_target( $target ) {
		if ( 'core' === $target ) {
			return $this->scan_core();
		}
		if ( 0 === strpos( $target, 'plugin:' ) ) {
			return $this->scan_plugin( substr( $target, 7 ) );
		}
		if ( 0 === strpos( $target, 'uploads:' ) ) {
			return $this->scan_uploads( substr( $target, 8 ) );
		}
		if ( 'content' === $target ) {
			return $this->scan_content_root();
		}
		if ( 0 === strpos( $target, 'baseline:' ) ) {
			return $this->scan_baseline( substr( $target, 9 ), '' );
		}
		return array(
			'findings' => array(),
			'note'     => '',
		);
	}

	/**
	 * Make a finding.
	 *
	 * @param string $abs      Absolute path.
	 * @param string $kind     Kind.
	 * @param string $severity Severity.
	 * @param string $detail   Detail.
	 * @return array
	 */
	private static function finding( $abs, $kind, $severity, $detail = '' ) {
		$exists = is_file( $abs );
		return array(
			'path'     => self::relative( $abs ),
			'kind'     => $kind,
			'severity' => $severity,
			'hash'     => $exists ? (string) hash_file( 'sha256', $abs ) : '',
			'size'     => $exists ? (int) filesize( $abs ) : 0,
			'mtime'    => $exists ? (int) filemtime( $abs ) : 0,
			'detail'   => $detail,
		);
	}

	/**
	 * Path relative to the WordPress root.
	 *
	 * @param string $abs Absolute path.
	 * @return string
	 */
	private static function relative( $abs ) {
		$root = wp_normalize_path( ABSPATH );
		$abs  = wp_normalize_path( $abs );
		return 0 === strpos( $abs, $root ) ? substr( $abs, strlen( $root ) ) : $abs;
	}

	/**
	 * Official core checksums for this version (cached).
	 *
	 * @return array|false path => md5
	 */
	private static function core_checksums() {
		global $wp_version;
		$locale = get_locale();
		$key    = 'jatss_core_sums_' . md5( $wp_version . $locale );
		$sums   = get_site_transient( $key );
		if ( is_array( $sums ) && $sums ) {
			return $sums;
		}
		require_once ABSPATH . 'wp-admin/includes/update.php';
		$sums = get_core_checksums( $wp_version, $locale );
		if ( ! is_array( $sums ) && 'en_US' !== $locale ) {
			$sums = get_core_checksums( $wp_version, 'en_US' );
		}
		if ( ! is_array( $sums ) || ! $sums ) {
			return false;
		}
		set_site_transient( $key, $sums, WEEK_IN_SECONDS );
		return $sums;
	}

	/**
	 * Core: modified, missing and unknown files.
	 *
	 * @return array
	 */
	private function scan_core() {
		$sums     = self::core_checksums();
		$findings = array();
		if ( ! $sums ) {
			return array(
				'findings' => array(),
				'note'     => __( 'Could not download the official WordPress checksums, so core files were not checked this time.', 'jat-site-shield' ),
			);
		}

		foreach ( $sums as $file => $md5 ) {
			if ( 0 === strpos( $file, 'wp-content/' ) ) {
				continue;
			}
			$abs = ABSPATH . $file;
			if ( ! file_exists( $abs ) ) {
				$optional   = in_array( $file, self::OPTIONAL_CORE, true );
				$findings[] = self::finding( $abs, 'core_missing', $optional ? 'info' : 'warning' );
				continue;
			}
			$actual = md5_file( $abs );
			if ( ! in_array( $actual, (array) $md5, true ) ) {
				$findings[] = self::finding( $abs, 'core_modified', '.php' === substr( $file, -4 ) ? 'critical' : 'warning' );
			}
		}

		$leftovers = self::old_core_files();
		foreach ( array( 'wp-admin', 'wp-includes' ) as $dir ) {
			$it = new \RecursiveIteratorIterator(
				new \RecursiveDirectoryIterator( ABSPATH . $dir, \FilesystemIterator::SKIP_DOTS ),
				\RecursiveIteratorIterator::LEAVES_ONLY
			);
			foreach ( $it as $file ) {
				if ( ! $file->isFile() ) {
					continue;
				}
				$rel = self::relative( $file->getPathname() );
				if ( isset( $sums[ $rel ] ) ) {
					continue;
				}
				if ( isset( $leftovers[ $rel ] ) ) {
					$findings[] = self::finding( $file->getPathname(), 'core_leftover', 'info', __( 'Listed by WordPress as removed in an older update; safe to delete.', 'jat-site-shield' ) );
				} elseif ( preg_match( self::PHP_EXT, $rel ) ) {
					$findings[] = self::finding( $file->getPathname(), 'core_unknown', 'critical' );
				} elseif ( 'error_log' !== basename( $rel ) ) {
					$findings[] = self::finding( $file->getPathname(), 'core_unknown', 'notice' );
				}
			}
		}

		// PHP files in the WordPress root that aren't core.
		$known_root = array( 'wp-config.php' => true );
		foreach ( (array) glob( ABSPATH . '*.php' ) as $abs ) {
			$rel = self::relative( $abs );
			if ( ! isset( $sums[ $rel ] ) && ! isset( $known_root[ $rel ] ) && ! isset( $leftovers[ $rel ] ) ) {
				$findings[] = self::finding( $abs, 'core_unknown', 'warning', __( 'PHP file in the site root that is not part of WordPress. Check what installed it.', 'jat-site-shield' ) );
			}
		}

		return array(
			'findings' => $findings,
			'note'     => '',
		);
	}

	/**
	 * Files WordPress lists as removed in past releases.
	 *
	 * @return array path => true
	 */
	private static function old_core_files() {
		global $_old_files, $_old_requests_files;
		if ( ! isset( $_old_files ) ) {
			require_once ABSPATH . 'wp-admin/includes/update-core.php';
		}
		$out = array();
		foreach ( (array) $_old_files as $file ) {
			$out[ rtrim( $file, '/' ) ] = true;
		}
		foreach ( (array) $_old_requests_files as $file ) {
			$out[ ltrim( (string) $file, '/' ) ] = true;
		}
		// Directories in the list cover everything under them.
		$dirs = array();
		foreach ( array_keys( $out ) as $path ) {
			if ( false === strpos( basename( $path ), '.' ) ) {
				$dirs[] = $path . '/';
			}
		}
		if ( $dirs ) {
			$out['__dirs'] = $dirs;
		}
		return new class( $out ) implements \ArrayAccess {
			/**
			 * Paths.
			 *
			 * @var array
			 */
			private $paths;

			/**
			 * Constructor.
			 *
			 * @param array $paths Paths.
			 */
			public function __construct( $paths ) {
				$this->paths = $paths;
			}

			/**
			 * Lookup that also matches files inside removed directories.
			 *
			 * @param mixed $offset Path.
			 * @return bool
			 */
			#[\ReturnTypeWillChange]
			public function offsetExists( $offset ) {
				if ( isset( $this->paths[ $offset ] ) ) {
					return true;
				}
				foreach ( isset( $this->paths['__dirs'] ) ? $this->paths['__dirs'] : array() as $dir ) {
					if ( 0 === strpos( $offset, $dir ) ) {
						return true;
					}
				}
				return false;
			}

			/**
			 * Value.
			 *
			 * @param mixed $offset Path.
			 * @return bool
			 */
			#[\ReturnTypeWillChange]
			public function offsetGet( $offset ) {
				return $this->offsetExists( $offset );
			}

			/**
			 * Read-only.
			 *
			 * @param mixed $offset Offset.
			 * @param mixed $value  Value.
			 */
			#[\ReturnTypeWillChange]
			public function offsetSet( $offset, $value ) {}

			/**
			 * Read-only.
			 *
			 * @param mixed $offset Offset.
			 */
			#[\ReturnTypeWillChange]
			public function offsetUnset( $offset ) {}
		};
	}

	/**
	 * Installed plugins keyed by folder slug: [ version, main file ].
	 *
	 * @return array
	 */
	private static function plugins() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$out = array();
		foreach ( get_plugins() as $file => $data ) {
			if ( false === strpos( $file, '/' ) ) {
				continue; // Single-file plugins have no checksum list.
			}
			$slug         = dirname( $file );
			$out[ $slug ] = array(
				'version' => isset( $data['Version'] ) ? $data['Version'] : '',
				'name'    => isset( $data['Name'] ) ? $data['Name'] : $slug,
			);
		}
		return $out;
	}

	/**
	 * Official checksums for a WordPress.org plugin version (cached).
	 *
	 * @param string $slug    Folder.
	 * @param string $version Version.
	 * @return array|null|false path => md5 list; null = not on WordPress.org; false = network error.
	 */
	private static function plugin_checksums( $slug, $version ) {
		$key    = 'jatss_pl_sums_' . md5( $slug . '|' . $version );
		$cached = get_site_transient( $key );
		if ( is_array( $cached ) ) {
			return isset( $cached['none'] ) ? null : $cached;
		}
		$url      = sprintf( 'https://downloads.wordpress.org/plugin-checksums/%s/%s.json', rawurlencode( $slug ), rawurlencode( $version ) );
		$response = wp_remote_get( $url, array( 'timeout' => 15 ) );
		if ( is_wp_error( $response ) ) {
			return false;
		}
		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( 404 === $code ) {
			set_site_transient( $key, array( 'none' => true ), WEEK_IN_SECONDS );
			return null;
		}
		$data = json_decode( (string) wp_remote_retrieve_body( $response ), true );
		if ( 200 !== $code || empty( $data['files'] ) || ! is_array( $data['files'] ) ) {
			return false;
		}
		$sums = array();
		foreach ( $data['files'] as $path => $hashes ) {
			$sums[ $path ] = isset( $hashes['md5'] ) ? (array) $hashes['md5'] : array();
		}
		set_site_transient( $key, $sums, WEEK_IN_SECONDS );
		return $sums;
	}

	/**
	 * One plugin against its WordPress.org checksums.
	 *
	 * @param string $slug Folder.
	 * @return array
	 */
	private function scan_plugin( $slug ) {
		$plugins = self::plugins();
		if ( ! isset( $plugins[ $slug ] ) ) {
			return array(
				'findings' => array(),
				'note'     => '',
			);
		}
		$sums = self::plugin_checksums( $slug, $plugins[ $slug ]['version'] );
		if ( null === $sums ) {
			return $this->scan_baseline( 'plugins/' . $slug, __( 'Not from WordPress.org, so compared with the previous scan instead of official checksums.', 'jat-site-shield' ) );
		}
		if ( false === $sums ) {
			return array(
				'findings' => array(),
				'note'     => __( 'Could not download checksums this time.', 'jat-site-shield' ),
			);
		}

		$dir      = WP_PLUGIN_DIR . '/' . $slug;
		$findings = array();
		foreach ( $sums as $path => $md5s ) {
			$abs = $dir . '/' . $path;
			if ( ! file_exists( $abs ) ) {
				continue; // Missing plugin files are not a security risk.
			}
			if ( $md5s && ! in_array( md5_file( $abs ), $md5s, true ) ) {
				$findings[] = self::finding( $abs, 'plugin_modified', preg_match( self::PHP_EXT, $path ) ? 'critical' : 'notice', $plugins[ $slug ]['name'] );
			}
		}

		$it = new \RecursiveIteratorIterator( new \RecursiveDirectoryIterator( $dir, \FilesystemIterator::SKIP_DOTS ) );
		foreach ( $it as $file ) {
			if ( ! $file->isFile() || ! preg_match( self::PHP_EXT, $file->getFilename() ) ) {
				continue;
			}
			$rel = substr( wp_normalize_path( $file->getPathname() ), strlen( wp_normalize_path( $dir ) ) + 1 );
			if ( ! isset( $sums[ $rel ] ) ) {
				$findings[] = self::finding( $file->getPathname(), 'plugin_unknown', 'critical', $plugins[ $slug ]['name'] );
			}
		}

		return array(
			'findings' => $findings,
			'note'     => '',
		);
	}

	/**
	 * Top-level parts of the uploads folder, so each scans as its own step.
	 *
	 * @return string[]
	 */
	private static function upload_parts() {
		$base  = trailingslashit( wp_get_upload_dir()['basedir'] );
		$parts = array( '.' );
		foreach ( self::subdirs( $base ) as $name ) { // Includes hidden folders such as ".cache".
			$children = self::subdirs( $base . $name );
			if ( ! $children ) {
				$parts[] = $name;
				continue;
			}
			// Split big folders (uploads/2024 with its month folders) into one step
			// per sub-folder, so a step never runs long enough to time out.
			$parts[] = $name . '/.';
			foreach ( $children as $child ) {
				$parts[] = $name . '/' . $child;
			}
		}
		return $parts;
	}

	/**
	 * Real (non-symlink) sub-folders of a folder, hidden ones included.
	 *
	 * @param string $dir Folder.
	 * @return string[] Names.
	 */
	private static function subdirs( $dir ) {
		$dir = trailingslashit( $dir );
		$out = array();
		foreach ( (array) @scandir( $dir ) as $name ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( '.' !== $name && '..' !== $name && is_dir( $dir . $name ) && ! is_link( $dir . $name ) ) {
				$out[] = $name;
			}
		}
		return $out;
	}

	/**
	 * PHP files inside one part of uploads.
	 *
	 * @param string $part Sub-folder, or "." for files directly in uploads.
	 * @return array
	 */
	private function scan_uploads( $part ) {
		$base     = trailingslashit( wp_get_upload_dir()['basedir'] );
		$findings = array();
		$files    = array();

		$segments = explode( '/', $part );
		foreach ( $segments as $segment ) {
			if ( '' === $segment || '..' === $segment || count( $segments ) > 2 ) {
				return array(
					'findings' => array(),
					'note'     => '',
				);
			}
		}
		$flat = '.' === end( $segments );
		if ( $flat ) {
			array_pop( $segments );
		}
		$rel = implode( '/', $segments );

		if ( $flat ) {
			$dir = '' === $rel ? $base : trailingslashit( $base . $rel );
			if ( '' !== $rel && ( ! is_dir( $dir ) || is_link( untrailingslashit( $dir ) ) ) ) {
				return array(
					'findings' => array(),
					'note'     => '',
				);
			}
			foreach ( (array) @scandir( $dir ) as $name ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				if ( is_file( $dir . $name ) ) {
					$files[] = $dir . $name; // Hidden files included.
				}
			}
		} else {
			$dir = $base . $rel;
			if ( ! is_dir( $dir ) || is_link( $dir ) ) {
				return array(
					'findings' => array(),
					'note'     => '',
				);
			}
			$it = new \RecursiveIteratorIterator( new \RecursiveDirectoryIterator( $dir, \FilesystemIterator::SKIP_DOTS ) );
			foreach ( $it as $file ) {
				if ( $file->isFile() ) {
					$files[] = $file->getPathname();
				}
			}
		}

		foreach ( $files as $abs ) {
			if ( ! preg_match( self::PHP_EXT, $abs ) ) {
				continue;
			}
			if ( self::is_silence_stub( $abs ) ) {
				continue;
			}
			$findings[] = self::finding( $abs, 'uploads_php', 'critical', __( 'PHP files do not belong in uploads. Inspect it with JAT Shell Scanner before deleting.', 'jat-site-shield' ) );
		}

		return array(
			'findings' => $findings,
			'note'     => '',
		);
	}

	/**
	 * Drop-ins and files WordPress itself allows directly in wp-content.
	 *
	 * @var string[]
	 */
	const CONTENT_ALLOWED = array( 'index.php', 'advanced-cache.php', 'object-cache.php', 'db.php', 'db-error.php', 'install.php', 'maintenance.php', 'php-error.php', 'fatal-error-handler.php', 'sunrise.php', 'blog-deleted.php', 'blog-inactive.php', 'blog-suspended.php', 'jatss-key.php' );

	/**
	 * PHP files directly in wp-content that aren't known drop-ins.
	 *
	 * @return array
	 */
	private function scan_content_root() {
		$findings = array();
		$base     = trailingslashit( WP_CONTENT_DIR );
		foreach ( (array) @scandir( $base ) as $name ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( ! is_file( $base . $name ) || ! preg_match( self::PHP_EXT, $name ) ) {
				continue;
			}
			if ( in_array( strtolower( $name ), self::CONTENT_ALLOWED, true ) ) {
				continue;
			}
			$findings[] = self::finding( $base . $name, 'content_unknown', 'warning', __( 'Not a WordPress drop-in. Check what put it here.', 'jat-site-shield' ) );
		}
		return array(
			'findings' => $findings,
			'note'     => '',
		);
	}

	/**
	 * Compare a folder's PHP files with the previous scan. Used for themes,
	 * mu-plugins and plugins without official checksums. The first scan (and
	 * the first scan after an update) only records a baseline.
	 *
	 * @param string $rel  Folder relative to wp-content (e.g. "themes/astra").
	 * @param string $note Note to keep with the result.
	 * @return array
	 */
	private function scan_baseline( $rel, $note ) {
		$rel = trim( str_replace( '..', '', $rel ), '/' );
		$dir = trailingslashit( WP_CONTENT_DIR ) . $rel;
		if ( '' === $rel || ! is_dir( $dir ) || is_link( $dir ) ) {
			return array(
				'findings' => array(),
				'note'     => '',
			);
		}

		$now = array();
		$it  = new \RecursiveIteratorIterator( new \RecursiveDirectoryIterator( $dir, \FilesystemIterator::SKIP_DOTS ) );
		foreach ( $it as $file ) {
			if ( $file->isFile() && preg_match( self::PHP_EXT, $file->getFilename() ) ) {
				$now[ self::relative( $file->getPathname() ) ] = sha1_file( $file->getPathname() );
			}
		}

		$all    = (array) get_option( self::BASE_OPTION, array() );
		$rebase = (array) get_option( self::REBASE_OPT, array() );
		$prev   = isset( $all[ $rel ] ) ? (array) $all[ $rel ] : null;

		$findings = array();
		if ( null !== $prev && ! in_array( $rel, $rebase, true ) ) {
			foreach ( $now as $path => $hash ) {
				if ( ! isset( $prev[ $path ] ) ) {
					$findings[] = self::finding( ABSPATH . $path, 'new_php', 'warning', $rel );
				} elseif ( $prev[ $path ] !== $hash ) {
					$findings[] = self::finding( ABSPATH . $path, 'changed_php', 'warning', $rel );
				}
			}
		}

		if ( null === $prev || in_array( $rel, $rebase, true ) ) {
			$all[ $rel ] = $now;
			update_option( self::BASE_OPTION, $all, false );
			update_option( self::REBASE_OPT, array_values( array_diff( $rebase, array( $rel ) ) ), false );
			if ( null === $prev ) {
				$note = trim( $note . ' ' . __( 'Baseline recorded on this scan.', 'jat-site-shield' ) );
			}
		}

		return array(
			'findings' => $findings,
			'note'     => $note,
		);
	}

	/**
	 * Accept a baseline finding by folding the file's current hash into the baseline.
	 *
	 * @param string $path Path relative to ABSPATH.
	 */
	private static function accept_into_baseline( $path ) {
		$all     = (array) get_option( self::BASE_OPTION, array() );
		$content = trailingslashit( self::relative( WP_CONTENT_DIR ) );
		foreach ( array_keys( $all ) as $rel ) {
			if ( 0 === strpos( $path, $content . $rel . '/' ) ) {
				$abs                  = ABSPATH . $path;
				$all[ $rel ][ $path ] = is_file( $abs ) ? sha1_file( $abs ) : '';
				update_option( self::BASE_OPTION, $all, false );
				return;
			}
		}
	}

	/**
	 * The harmless "Silence is golden" index.php many plugins drop in folders.
	 *
	 * @param string $abs Path.
	 * @return bool
	 */
	private static function is_silence_stub( $abs ) {
		if ( 'index.php' !== strtolower( basename( $abs ) ) || filesize( $abs ) > 200 ) {
			return false;
		}
		$body = (string) file_get_contents( $abs ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		$body = preg_replace( '#/\*.*?\*/|//[^\n]*|\#[^\n]*#s', '', $body );
		return (bool) preg_match( '/^\s*<\?php\s*(\?>)?\s*$/i', $body );
	}
}
