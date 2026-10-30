<?php
/**
 * Admin screens.
 *
 * @package JATSiteShield
 */

namespace JATSiteShield\Admin;

use JATSiteShield\Event_Log;
use JATSiteShield\Modules\File_Integrity;
use JATSiteShield\Modules\Hardening;
use JATSiteShield\Modules\Login_Protection;
use JATSiteShield\Modules\Login_Url;
use JATSiteShield\Modules\Two_Factor;
use JATSiteShield\Plugin;
use JATSiteShield\Request;
use JATSiteShield\Settings;
use JATSiteShield\Totp;

defined( 'ABSPATH' ) || exit;

/**
 * Overview, activity log, file integrity and settings screens.
 */
class Admin {

	const CAP  = 'manage_options';
	const SLUG = 'jat-site-shield';

	/**
	 * Hook in.
	 */
	public function register() {
		add_action( 'admin_menu', array( $this, 'menu' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'assets' ) );
		add_action( 'admin_post_jatss_save', array( $this, 'save_settings' ) );
		add_action( 'admin_post_jatss_unlock', array( $this, 'unlock' ) );
		add_action( 'admin_post_jatss_scan', array( $this, 'run_scan' ) );
		add_action( 'admin_post_jatss_ack', array( $this, 'acknowledge' ) );
		add_action( 'admin_post_jatss_ack_all', array( $this, 'acknowledge_all' ) );
		add_action( 'admin_post_jatss_export', array( $this, 'export_csv' ) );
		add_action( 'admin_post_jatss_test_uploads', array( $this, 'test_uploads' ) );
		add_action( 'admin_post_jatss_test_alert', array( $this, 'test_alert' ) );
		add_filter( 'plugin_action_links_' . JATSS_BASENAME, array( $this, 'action_links' ) );
		add_action( 'admin_notices', array( $this, 'notices' ) );
		add_action( 'admin_init', array( $this, 'privacy_policy' ) );
	}

	/**
	 * Suggested privacy policy text (Settings > Privacy).
	 */
	public function privacy_policy() {
		if ( ! function_exists( 'wp_add_privacy_policy_content' ) ) {
			return;
		}
		$text  = '<p>' . esc_html__( 'To protect this site from attacks, we record security events such as logins, failed login attempts and changes to user accounts. Each record can include your username, your IP address and your browser’s user agent.', 'jat-site-shield' ) . '</p>';
		$text .= '<p>' . esc_html(
			sprintf(
				/* translators: %d: days */
				__( 'These records are kept for %d days and are only visible to site administrators. They are not shared with anyone.', 'jat-site-shield' ),
				(int) Settings::get( 'log_retention_days' )
			)
		) . '</p>';
		wp_add_privacy_policy_content( 'JAT Site Shield', wp_kses_post( $text ) );
	}

	/**
	 * Menu.
	 */
	public function menu() {
		$critical = $this->unseen_critical();
		$bubble   = $critical ? ' <span class="awaiting-mod"><span class="pending-count">' . (int) $critical . '</span></span>' : '';

		add_menu_page( __( 'Site Shield', 'jat-site-shield' ), __( 'Site Shield', 'jat-site-shield' ) . $bubble, self::CAP, self::SLUG, array( $this, 'page_overview' ), 'dashicons-shield', 80 );
		add_submenu_page( self::SLUG, __( 'Overview', 'jat-site-shield' ), __( 'Overview', 'jat-site-shield' ), self::CAP, self::SLUG, array( $this, 'page_overview' ) );
		add_submenu_page( self::SLUG, __( 'Activity log', 'jat-site-shield' ), __( 'Activity log', 'jat-site-shield' ), self::CAP, self::SLUG . '-log', array( $this, 'page_log' ) );
		add_submenu_page( self::SLUG, __( 'File integrity', 'jat-site-shield' ), __( 'File integrity', 'jat-site-shield' ), self::CAP, self::SLUG . '-files', array( $this, 'page_files' ) );
		add_submenu_page( self::SLUG, __( 'Settings', 'jat-site-shield' ), __( 'Settings', 'jat-site-shield' ), self::CAP, self::SLUG . '-settings', array( $this, 'page_settings' ) );
	}

	/**
	 * Critical events since the user last opened the overview.
	 *
	 * @return int
	 */
	private function unseen_critical() {
		if ( ! current_user_can( self::CAP ) ) {
			return 0;
		}
		$seen = (int) get_user_meta( get_current_user_id(), 'jatss_seen', true );
		$key  = 'jatss_crit_' . get_current_user_id();
		$n    = get_transient( $key );
		if ( false === $n ) {
			$since = gmdate( 'Y-m-d H:i:s', max( $seen, time() - 30 * DAY_IN_SECONDS ) );
			$n     = Event_Log::counts_since( $since )['critical'];
			set_transient( $key, $n, 5 * MINUTE_IN_SECONDS );
		}
		return (int) $n;
	}

	/**
	 * Styles on our screens.
	 *
	 * @param string $hook Screen hook.
	 */
	public function assets( $hook ) {
		if ( false !== strpos( (string) $hook, self::SLUG ) ) {
			wp_enqueue_style( 'jatss-admin', JATSS_URL . 'assets/admin.css', array(), JATSS_VERSION );
		}
	}

	/**
	 * Settings link on the Plugins screen.
	 *
	 * @param array $links Links.
	 * @return array
	 */
	public function action_links( $links ) {
		array_unshift( $links, '<a href="' . esc_url( admin_url( 'admin.php?page=' . self::SLUG . '-settings' ) ) . '">' . esc_html__( 'Settings', 'jat-site-shield' ) . '</a>' );
		return $links;
	}

	/**
	 * Safe-mode warning everywhere in the dashboard.
	 */
	public function notices() {
		if ( current_user_can( self::CAP ) && Request::proxy_misconfigured() ) {
			echo '<div class="notice notice-warning"><p><strong>' . esc_html__( 'Site Shield can’t see real visitor IPs.', 'jat-site-shield' ) . '</strong> ' . esc_html__( 'Requests carry a Cloudflare visitor header but reach WordPress through a proxy Site Shield doesn’t trust, usually a web server on the same machine. Until that’s fixed, visitors may share one address and a few wrong passwords could lock out everyone. Add the proxy’s address under Trusted proxies in Site Shield settings.', 'jat-site-shield' ) . '</p></div>';
		}
		if ( JATSS_SAFE_MODE && current_user_can( self::CAP ) ) {
			echo '<div class="notice notice-error"><p><strong>' . esc_html__( 'Site Shield safe mode is on.', 'jat-site-shield' ) . '</strong> ' . esc_html__( 'The custom login URL, two-factor and login lockouts are paused. Remove JATSS_SAFE_MODE from wp-config.php when you are back in.', 'jat-site-shield' ) . '</p></div>';
		}
	}

	/* ------------------------------------------------------------------ */
	/* Status checks                                                       */
	/* ------------------------------------------------------------------ */

	/**
	 * Protection checklist (also used by `wp jat-shield status`).
	 *
	 * @return array[] label, ok, note.
	 */
	public static function checks() {
		$s      = Settings::all();
		$checks = array();

		$checks[] = array(
			'label' => __( 'Login lockouts', 'jat-site-shield' ),
			'ok'    => $s['login_protection'],
			/* translators: 1: attempts, 2: minutes */
			'note'  => $s['login_protection'] ? sprintf( __( '%1$d failures locks an IP out for %2$d minutes.', 'jat-site-shield' ), $s['login_max_attempts'], $s['login_lockout_minutes'] ) : __( 'Anyone can guess passwords without limit.', 'jat-site-shield' ),
		);

		$required   = (array) $s['twofa_required_roles'];
		$unenrolled = array();
		if ( $s['twofa_enabled'] && $required ) {
			foreach ( get_users( array( 'role__in' => $required, 'fields' => array( 'ID', 'user_login' ), 'number' => 200 ) ) as $u ) {
				if ( ! Two_Factor::is_enrolled( $u->ID ) ) {
					$unenrolled[] = $u->user_login;
				}
			}
		}
		$checks[] = array(
			'label' => __( 'Two-factor for required roles', 'jat-site-shield' ),
			'ok'    => $s['twofa_enabled'] && $required && ! $unenrolled,
			'note'  => ! $s['twofa_enabled'] || ! $required
				? __( 'Not required for any role.', 'jat-site-shield' )
				: ( $unenrolled
					/* translators: %s: usernames */
					? sprintf( __( 'Not set up yet: %s (they must enroll at next login).', 'jat-site-shield' ), implode( ', ', array_slice( $unenrolled, 0, 10 ) ) )
					/* translators: %s: roles */
					: sprintf( __( 'Required and set up for: %s.', 'jat-site-shield' ), implode( ', ', $required ) ) ),
		);

		$checks[] = array(
			'label' => __( 'Custom login URL', 'jat-site-shield' ),
			'ok'    => Login_Url::enabled() || ( $s['custom_login_enabled'] && ( defined( 'WP_CLI' ) && WP_CLI ) ),
			'note'  => $s['custom_login_enabled'] ? Login_Url::url() : __( 'Optional. Bots go straight to wp-login.php.', 'jat-site-shield' ),
		);

		$xmlrpc_note = Hardening::xmlrpc_needed() ? __( 'Left on because Jetpack needs it.', 'jat-site-shield' ) : __( 'Brute-force and pingback attacks over xmlrpc.php.', 'jat-site-shield' );
		$checks[]    = array(
			'label' => __( 'XML-RPC blocked', 'jat-site-shield' ),
			'ok'    => $s['harden_xmlrpc'] && ! Hardening::xmlrpc_needed(),
			'note'  => $xmlrpc_note,
		);
		$checks[]    = array(
			'label' => __( 'Username scanning blocked', 'jat-site-shield' ),
			'ok'    => $s['harden_user_enum'],
			'note'  => __( '?author=, REST /users, oEmbed and the users sitemap.', 'jat-site-shield' ),
		);
		$checks[]    = array(
			'label' => __( 'Theme and plugin editor off', 'jat-site-shield' ),
			'ok'    => defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT,
			'note'  => __( 'A stolen admin login can\'t edit PHP from the dashboard.', 'jat-site-shield' ),
		);
		$checks[]    = array(
			'label' => __( 'PHP blocked in uploads', 'jat-site-shield' ),
			'ok'    => $s['harden_uploads_php'] && 'executes' !== get_option( 'jatss_uploads_test' ),
			'note'  => 'executes' === get_option( 'jatss_uploads_test' )
				? __( 'Test showed PHP still runs in uploads. Your server may ignore .htaccess (nginx); ask your host to block it.', 'jat-site-shield' )
				: ( 'blocked' === get_option( 'jatss_uploads_test' ) ? __( 'Verified by a live test.', 'jat-site-shield' ) : __( 'Rules written; run the test on the Settings screen to confirm.', 'jat-site-shield' ) ),
		);
		$checks[]    = array(
			'label' => __( 'Security headers', 'jat-site-shield' ),
			'ok'    => $s['harden_headers'],
			'note'  => __( 'nosniff, frame protection, referrer and permissions policy.', 'jat-site-shield' ),
		);
		$checks[]    = array(
			'label' => __( 'HTTPS', 'jat-site-shield' ),
			'ok'    => 0 === strpos( home_url(), 'https://' ),
			'note'  => 0 === strpos( home_url(), 'https://' ) ? __( 'Site address uses HTTPS.', 'jat-site-shield' ) : __( 'Site address is not HTTPS; logins travel unencrypted.', 'jat-site-shield' ),
		);
		// Visitors use HTTPS but WordPress sees plain HTTP: almost always Cloudflare's
		// "Flexible" mode or a proxy that doesn't pass the scheme on.
		if ( 0 === strpos( home_url(), 'https://' ) && ! is_ssl() && ! ( defined( 'WP_CLI' ) && WP_CLI ) && ! wp_doing_cron() ) {
			$checks[] = array(
				'label' => __( 'HTTPS all the way to the server', 'jat-site-shield' ),
				'ok'    => false,
				'note'  => Request::via_cloudflare()
					? __( 'Cloudflare is connecting to your server over plain HTTP (Flexible mode). Set Cloudflare SSL/TLS to Full (strict).', 'jat-site-shield' )
					: __( 'WordPress sees this page as plain HTTP although the site address is HTTPS. A proxy is probably not passing the HTTPS scheme on; ask your host.', 'jat-site-shield' ),
			);
		}
		$checks[]    = array(
			'label' => __( 'Activity log and alerts', 'jat-site-shield' ),
			'ok'    => $s['log_enabled'],
			/* translators: %s: emails */
			'note'  => sprintf( __( 'Alerts to %s.', 'jat-site-shield' ), implode( ', ', \JATSiteShield\Alerts::recipients() ) ),
		);

		$last     = File_Integrity::last();
		$checks[] = array(
			'label' => __( 'File integrity monitoring', 'jat-site-shield' ),
			'ok'    => $s['fim_enabled'] && $last && time() - $last['finished'] < 3 * DAY_IN_SECONDS,
			'note'  => ! $s['fim_enabled'] ? __( 'Off.', 'jat-site-shield' ) : ( $last
				/* translators: %s: time ago */
				? sprintf( __( 'Last scan %s ago.', 'jat-site-shield' ), human_time_diff( $last['finished'] ) )
				: __( 'No scan yet.', 'jat-site-shield' ) ) . ( defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON ? ' ' . __( 'WP-Cron is turned off on this site, so make sure a server cron job runs wp-cron.php.', 'jat-site-shield' ) : '' ),
		);

		$key_ok   = defined( 'JATSS_SECRET_KEY' ) || is_readable( Totp::key_file() );
		$checks[] = array(
			'label' => __( 'Two-factor key kept outside the database', 'jat-site-shield' ),
			'ok'    => $key_ok,
			'note'  => defined( 'JATSS_SECRET_KEY' )
				? __( 'Set with JATSS_SECRET_KEY in wp-config.php.', 'jat-site-shield' )
				: ( $key_ok
					? __( 'Stored in wp-content/jatss-key.php. Keep it in backups and migrations.', 'jat-site-shield' )
					: __( 'wp-content isn’t writable, so secrets fall back to the WordPress salts and break if they’re changed. Add JATSS_SECRET_KEY to wp-config.php.', 'jat-site-shield' ) ),
		);

		$checks[] = array(
			'label'    => __( 'Cloudflare in front of the site', 'jat-site-shield' ),
			'ok'       => Request::via_cloudflare(),
			'optional' => true,
			'note'     => Request::via_cloudflare()
				? __( 'Requests come through Cloudflare and real visitor IPs are used.', 'jat-site-shield' )
				: __( 'Optional. Cloudflare’s free plan blocks attacks before they reach your server. See the setup guide linked in Settings.', 'jat-site-shield' ),
		);

		$debug    = defined( 'WP_DEBUG_DISPLAY' ) ? WP_DEBUG_DISPLAY : true;
		$checks[] = array(
			'label' => __( 'Errors hidden from visitors', 'jat-site-shield' ),
			'ok'    => ! ( defined( 'WP_DEBUG' ) && WP_DEBUG && $debug ),
			'note'  => __( 'WP_DEBUG with display on leaks file paths to visitors.', 'jat-site-shield' ),
		);

		$admin_user = get_user_by( 'login', 'admin' );
		$checks[]   = array(
			'label' => __( 'No "admin" username', 'jat-site-shield' ),
			'ok'    => ! $admin_user,
			'note'  => $admin_user ? __( 'An account named "admin" is the first one bots guess. Create a new admin and delete it.', 'jat-site-shield' ) : __( 'Good.', 'jat-site-shield' ),
		);

		return $checks;
	}

	/* ------------------------------------------------------------------ */
	/* Screens                                                             */
	/* ------------------------------------------------------------------ */

	/**
	 * Page header with flash message.
	 *
	 * @param string $title Title.
	 */
	private function header( $title ) {
		echo '<div class="wrap jatss"><h1 class="jatss-title">' . esc_html( $title ) . '</h1>';
		// phpcs:disable WordPress.Security.NonceVerification.Recommended
		if ( ! empty( $_GET['jatss_msg'] ) ) {
			$type = ! empty( $_GET['jatss_err'] ) ? 'error' : 'success';
			echo '<div class="notice notice-' . esc_attr( $type ) . ' is-dismissible"><p>' . esc_html( sanitize_text_field( wp_unslash( $_GET['jatss_msg'] ) ) ) . '</p></div>';
		}
		// phpcs:enable
	}

	/**
	 * Overview.
	 */
	public function page_overview() {
		update_user_meta( get_current_user_id(), 'jatss_seen', time() );
		delete_transient( 'jatss_crit_' . get_current_user_id() );

		$all_checks = self::checks();
		$checks     = array_values( array_filter( $all_checks, static function ( $c ) { return empty( $c['optional'] ); } ) );
		$ok         = count( array_filter( wp_list_pluck( $checks, 'ok' ) ) );
		$day    = Event_Log::counts_since( gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS ) );
		$week   = Event_Log::counts_since( gmdate( 'Y-m-d H:i:s', time() - WEEK_IN_SECONDS ) );
		$recent = Event_Log::query(
			array(
				'severity' => 'warning',
				'per_page' => 8,
			)
		);
		$locks  = Login_Protection::lockouts();
		$last   = File_Integrity::last();

		$this->header( __( 'JAT Site Shield', 'jat-site-shield' ) );
		?>
		<?php
		$off        = array_values( array_filter( $checks, static function ( $c ) { return ! $c['ok']; } ) );
		$open_files = $last ? array_filter( $last['findings'], static function ( $f ) { return 'info' !== $f['severity'] && ! File_Integrity::is_acknowledged( $f ); } ) : array();
		$crit_files = array_filter( $open_files, static function ( $f ) { return 'critical' === $f['severity']; } );
		$s          = Settings::all();

		if ( $crit_files || $day['critical'] ) {
			$verdict = 'bad';
			$sentence = __( 'Something on this site needs your attention.', 'jat-site-shield' );
		} elseif ( $off || $open_files ) {
			$verdict = 'warn';
			/* translators: %d: number of protections that are off */
			$sentence = $off ? sprintf( _n( '%d protection is off.', '%d protections are off.', count( $off ), 'jat-site-shield' ), count( $off ) ) : __( 'Some files need a look.', 'jat-site-shield' );
		} else {
			$verdict  = 'ok';
			$sentence = __( 'This site is locked down.', 'jat-site-shield' );
		}

		// Logins tile.
		$twofa_ok  = $s['twofa_enabled'] && (array) $s['twofa_required_roles'];
		$since     = gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS );
		$login_bad = 0 < Event_Log::query( array( 'severity' => 'critical', 'type' => 'auth.', 'since' => $since, 'per_page' => 1 ) )['total']
			|| 0 < Event_Log::query( array( 'severity' => 'critical', 'type' => '2fa.', 'since' => $since, 'per_page' => 1 ) )['total'];
		$login_ok  = $s['login_protection'] && $twofa_ok;
		// Hardening tile.
		$hard_keys = array( 'harden_xmlrpc', 'harden_user_enum', 'harden_file_edit', 'harden_uploads_php', 'harden_headers', 'harden_hide_version' );
		$hard_on   = count( array_filter( array_map( static function ( $k ) use ( $s ) { return (bool) $s[ $k ]; }, $hard_keys ) ) );
		?>
		<div class="jatss-hero jatss-v-<?php echo esc_attr( $verdict ); ?>">
			<p class="jatss-sentence"><?php echo esc_html( $sentence ); ?></p>
			<p class="jatss-meta">
				<?php
				printf(
					/* translators: 1: protections on, 2: total, 3: events in the last 7 days */
					esc_html__( '%1$d of %2$d protections on. %3$d security events in the last 7 days.', 'jat-site-shield' ),
					(int) $ok,
					(int) count( $checks ),
					(int) ( $week['info'] + $week['notice'] + $week['warning'] + $week['critical'] )
				);
				?>
			</p>
			<div class="jatss-doors">
				<?php
				$this->door(
					__( 'Logins', 'jat-site-shield' ),
					__( 'Lockouts and two-factor', 'jat-site-shield' ),
					$login_bad ? 'bad' : ( $login_ok ? 'ok' : 'warn' ),
					$login_bad ? __( 'Under attack', 'jat-site-shield' ) : ( $login_ok ? __( 'Protected', 'jat-site-shield' ) : __( 'Needs setup', 'jat-site-shield' ) ),
					/* translators: %d: number of locked out IPs */
					sprintf( _n( '%d IP locked out right now.', '%d IPs locked out right now.', count( $locks ), 'jat-site-shield' ), count( $locks ) )
				);
				$this->door(
					__( 'Hardening', 'jat-site-shield' ),
					__( 'WordPress settings', 'jat-site-shield' ),
					$hard_on === count( $hard_keys ) ? 'ok' : 'warn',
					$hard_on === count( $hard_keys ) ? __( 'All on', 'jat-site-shield' ) : __( 'Some off', 'jat-site-shield' ),
					/* translators: 1: on, 2: total */
					sprintf( __( '%1$d of %2$d hardening options on.', 'jat-site-shield' ), $hard_on, count( $hard_keys ) )
				);
				$this->door(
					__( 'Files', 'jat-site-shield' ),
					__( 'Integrity check', 'jat-site-shield' ),
					! $last ? 'warn' : ( $crit_files ? 'bad' : ( $open_files ? 'warn' : 'ok' ) ),
					! $last ? __( 'Not checked yet', 'jat-site-shield' ) : ( $open_files
						/* translators: %d: files */
						? sprintf( _n( '%d file to review', '%d files to review', count( $open_files ), 'jat-site-shield' ), count( $open_files ) )
						: __( 'No changes', 'jat-site-shield' ) ),
					$last
						/* translators: %s: time ago */
						? sprintf( __( 'Checked %s ago.', 'jat-site-shield' ), human_time_diff( $last['finished'] ) )
						: __( 'Runs daily, or start one on the File integrity screen.', 'jat-site-shield' )
				);
				?>
			</div>
		</div>

		<div class="jatss-columns">
			<div class="jatss-panel">
				<h2><?php esc_html_e( 'Protection checklist', 'jat-site-shield' ); ?></h2>
				<ul class="jatss-checks">
					<?php foreach ( $all_checks as $c ) : ?>
						<?php $tone = $c['ok'] ? 'is-ok' : ( empty( $c['optional'] ) ? 'is-off' : 'is-info' ); ?>
						<li class="<?php echo esc_attr( $tone ); ?>">
							<span class="dashicons <?php echo esc_attr( 'is-ok' === $tone ? 'dashicons-yes-alt' : ( 'is-off' === $tone ? 'dashicons-warning' : 'dashicons-info-outline' ) ); ?>" aria-hidden="true"></span>
							<div><strong><?php echo esc_html( $c['label'] ); ?></strong><span class="screen-reader-text"> — <?php echo 'is-ok' === $tone ? esc_html__( 'on', 'jat-site-shield' ) : ( 'is-off' === $tone ? esc_html__( 'needs attention', 'jat-site-shield' ) : esc_html__( 'optional', 'jat-site-shield' ) ); ?></span><br /><span class="description"><?php echo esc_html( $c['note'] ); ?></span></div>
						</li>
					<?php endforeach; ?>
				</ul>
			</div>

			<div>
				<div class="jatss-panel">
					<h2><?php esc_html_e( 'Needs a look', 'jat-site-shield' ); ?></h2>
					<?php if ( ! $recent['rows'] ) : ?>
						<p class="description"><?php esc_html_e( 'No warnings or critical events. Quiet is good.', 'jat-site-shield' ); ?></p>
					<?php else : ?>
						<ul class="jatss-events">
							<?php foreach ( $recent['rows'] as $e ) : ?>
								<li class="jatss-s-<?php echo esc_attr( $e['severity'] ); ?>"><span class="jatss-sev jatss-sev-<?php echo esc_attr( $e['severity'] ); ?>"><?php echo esc_html( ucfirst( $e['severity'] ) ); ?></span> <?php echo esc_html( $e['message'] ); ?> <span class="description"><?php echo esc_html( human_time_diff( strtotime( $e['created_at'] . ' UTC' ) ) ); ?> <?php esc_html_e( 'ago', 'jat-site-shield' ); ?></span></li>
							<?php endforeach; ?>
						</ul>
						<p><a href="<?php echo esc_url( admin_url( 'admin.php?page=' . self::SLUG . '-log' ) ); ?>"><?php esc_html_e( 'Full activity log', 'jat-site-shield' ); ?></a></p>
					<?php endif; ?>
				</div>

				<div class="jatss-panel">
					<h2><?php esc_html_e( 'Lockouts', 'jat-site-shield' ); ?></h2>
					<?php if ( ! $locks ) : ?>
						<p class="description"><?php esc_html_e( 'No IPs are locked out.', 'jat-site-shield' ); ?></p>
					<?php else : ?>
						<table class="widefat striped">
							<tbody>
							<?php foreach ( array_slice( $locks, 0, 15, true ) as $ip => $until ) : ?>
								<tr><td><code><?php echo esc_html( $ip ); ?></code></td><td><?php /* translators: %s: time */ printf( esc_html__( 'for %s', 'jat-site-shield' ), esc_html( human_time_diff( $until ) ) ); ?></td>
									<td class="jatss-right"><?php $this->post_button( 'jatss_unlock', array( 'ip' => $ip ), __( 'Unlock', 'jat-site-shield' ), 'button-small' ); ?></td></tr>
							<?php endforeach; ?>
							</tbody>
						</table>
						<p><?php $this->post_button( 'jatss_unlock', array( 'ip' => 'all' ), __( 'Unlock all', 'jat-site-shield' ), 'button-small' ); ?></p>
					<?php endif; ?>
					<p class="description">
						<?php
						/* translators: %s: IP */
						printf( esc_html__( 'Your IP right now: %s', 'jat-site-shield' ), '<code>' . esc_html( Request::ip() ) . '</code>' );
						?>
					</p>
				</div>

				<div class="jatss-panel">
					<h2><?php esc_html_e( 'File integrity', 'jat-site-shield' ); ?></h2>
					<?php $this->fim_summary( $last ); ?>
				</div>
			</div>
		</div>
		<?php $this->about(); ?>
		</div>
		<?php
	}

	/**
	 * One summary tile in the overview.
	 *
	 * @param string $title Title.
	 * @param string $sub   Muted subtitle.
	 * @param string $tone  ok|warn|bad.
	 * @param string $state Big state text.
	 * @param string $note  Note.
	 */
	private function door( $title, $sub, $tone, $state, $note ) {
		?>
		<div class="jatss-door jatss-tone-<?php echo esc_attr( $tone ); ?>">
			<p class="jatss-door-title"><?php echo esc_html( $title ); ?> <span><?php echo esc_html( $sub ); ?></span></p>
			<p class="jatss-door-state"><?php echo esc_html( $state ); ?></p>
			<p class="jatss-door-note"><?php echo esc_html( $note ); ?></p>
		</div>
		<?php
	}

	/**
	 * Footer with links, shown on the plugin's own screens.
	 */
	private function about() {
		$base = 'https://jeremyanderson.tech/';
		?>
		<aside class="jatss-about" aria-label="<?php esc_attr_e( 'About this plugin', 'jat-site-shield' ); ?>">
			<p>
				<strong><?php esc_html_e( 'Free and open source, by Jeremy Anderson.', 'jat-site-shield' ); ?></strong>
				<?php esc_html_e( 'Need hands-on help locking down or cleaning up a WordPress site? I build and look after WordPress sites.', 'jat-site-shield' ); ?>
			</p>
			<p class="jatss-about-links">
				<a class="button" href="<?php echo esc_url( $base . 'book-a-call/' ); ?>" target="_blank" rel="noopener"><?php esc_html_e( 'Book a call', 'jat-site-shield' ); ?></a>
				<a href="<?php echo esc_url( $base . 'services/' ); ?>" target="_blank" rel="noopener"><?php esc_html_e( 'Services', 'jat-site-shield' ); ?></a>
				<a href="<?php echo esc_url( 'https://wordpress.org/support/plugin/jat-site-shield/' ); ?>" target="_blank" rel="noopener"><?php esc_html_e( 'Report a problem', 'jat-site-shield' ); ?></a>
			</p>
		</aside>
		<?php
	}

	/**
	 * Short file-integrity summary.
	 *
	 * @param array|null $last Last scan.
	 */
	private function fim_summary( $last ) {
		$state = File_Integrity::state();
		if ( 'running' === $state['status'] ) {
			/* translators: 1: done, 2: total */
			echo '<p>' . esc_html( sprintf( __( 'Scan running: %1$d of %2$d steps done.', 'jat-site-shield' ), $state['done'], $state['total'] ) ) . '</p>';
			return;
		}
		if ( ! $last ) {
			echo '<p class="description">' . esc_html__( 'No scan yet.', 'jat-site-shield' ) . '</p>';
			$this->post_button( 'jatss_scan', array(), __( 'Scan now', 'jat-site-shield' ), 'button-primary' );
			return;
		}
		$open = array_filter(
			$last['findings'],
			static function ( $f ) {
				return 'info' !== $f['severity'] && ! File_Integrity::is_acknowledged( $f );
			}
		);
		/* translators: %s: time */
		echo '<p>' . esc_html( sprintf( __( 'Last scan %s ago.', 'jat-site-shield' ), human_time_diff( $last['finished'] ) ) ) . ' ';
		if ( $open ) {
			/* translators: %d: count */
			echo '<strong class="jatss-sev-critical">' . esc_html( sprintf( _n( '%d file needs review.', '%d files need review.', count( $open ), 'jat-site-shield' ), count( $open ) ) ) . '</strong>';
		} else {
			echo esc_html__( 'Nothing needs review.', 'jat-site-shield' );
		}
		echo '</p><p><a href="' . esc_url( admin_url( 'admin.php?page=' . self::SLUG . '-files' ) ) . '">' . esc_html__( 'See results', 'jat-site-shield' ) . '</a></p>';
	}

	/**
	 * Activity log.
	 */
	public function page_log() {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended
		$severity = isset( $_GET['severity'] ) ? sanitize_key( $_GET['severity'] ) : '';
		$type     = isset( $_GET['type'] ) ? sanitize_text_field( wp_unslash( $_GET['type'] ) ) : '';
		$search   = isset( $_GET['s'] ) ? sanitize_text_field( wp_unslash( $_GET['s'] ) ) : '';
		$paged    = isset( $_GET['paged'] ) ? max( 1, absint( $_GET['paged'] ) ) : 1;
		// phpcs:enable
		$result = Event_Log::query(
			array(
				'severity' => $severity,
				'type'     => $type,
				'search'   => $search,
				'page'     => $paged,
				'per_page' => 50,
			)
		);
		$pages  = max( 1, (int) ceil( $result['total'] / 50 ) );
		$types  = array(
			''        => __( 'All events', 'jat-site-shield' ),
			'auth.'   => __( 'Logins', 'jat-site-shield' ),
			'2fa.'    => __( 'Two-factor', 'jat-site-shield' ),
			'user.'   => __( 'Users', 'jat-site-shield' ),
			'plugin.' => __( 'Plugins', 'jat-site-shield' ),
			'theme.'  => __( 'Themes', 'jat-site-shield' ),
			'option.' => __( 'Settings', 'jat-site-shield' ),
			'fim.'    => __( 'File integrity', 'jat-site-shield' ),
			'harden.' => __( 'Blocked probes', 'jat-site-shield' ),
		);

		$this->header( __( 'Activity log', 'jat-site-shield' ) );
		?>
		<form method="get" class="jatss-filters">
			<input type="hidden" name="page" value="<?php echo esc_attr( self::SLUG . '-log' ); ?>" />
			<label class="screen-reader-text" for="jatss-sev"><?php esc_html_e( 'Minimum severity', 'jat-site-shield' ); ?></label>
			<select name="severity" id="jatss-sev">
				<option value=""><?php esc_html_e( 'Any severity', 'jat-site-shield' ); ?></option>
				<?php foreach ( array( 'notice', 'warning', 'critical' ) as $sev ) : ?>
					<?php /* translators: %s: severity */ ?>
					<option value="<?php echo esc_attr( $sev ); ?>" <?php selected( $severity, $sev ); ?>><?php echo esc_html( sprintf( __( '%s and above', 'jat-site-shield' ), ucfirst( $sev ) ) ); ?></option>
				<?php endforeach; ?>
			</select>
			<label class="screen-reader-text" for="jatss-type"><?php esc_html_e( 'Event type', 'jat-site-shield' ); ?></label>
			<select name="type" id="jatss-type">
				<?php foreach ( $types as $value => $label ) : ?>
					<option value="<?php echo esc_attr( $value ); ?>" <?php selected( $type, $value ); ?>><?php echo esc_html( $label ); ?></option>
				<?php endforeach; ?>
			</select>
			<label class="screen-reader-text" for="jatss-s"><?php esc_html_e( 'Search', 'jat-site-shield' ); ?></label>
			<input type="search" id="jatss-s" name="s" value="<?php echo esc_attr( $search ); ?>" placeholder="<?php esc_attr_e( 'User, IP or text', 'jat-site-shield' ); ?>" />
			<button class="button"><?php esc_html_e( 'Filter', 'jat-site-shield' ); ?></button>
			<a class="button" href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=jatss_export&severity=' . rawurlencode( $severity ) . '&type=' . rawurlencode( $type ) . '&s=' . rawurlencode( $search ) ), 'jatss_export' ) ); ?>"><?php esc_html_e( 'Export CSV', 'jat-site-shield' ); ?></a>
			<span class="jatss-count">
				<?php
				/* translators: %s: count */
				echo esc_html( sprintf( _n( '%s event', '%s events', $result['total'], 'jat-site-shield' ), number_format_i18n( $result['total'] ) ) );
				?>
			</span>
		</form>

		<table class="widefat jatss-table jatss-log">
			<thead><tr>
				<th scope="col"><?php esc_html_e( 'When', 'jat-site-shield' ); ?></th>
				<th scope="col"><?php esc_html_e( 'Severity', 'jat-site-shield' ); ?></th>
				<th scope="col"><?php esc_html_e( 'Event', 'jat-site-shield' ); ?></th>
				<th scope="col"><?php esc_html_e( 'User', 'jat-site-shield' ); ?></th>
				<th scope="col"><?php esc_html_e( 'IP', 'jat-site-shield' ); ?></th>
			</tr></thead>
			<tbody>
			<?php if ( ! $result['rows'] ) : ?>
				<tr><td colspan="5"><?php esc_html_e( 'No events match.', 'jat-site-shield' ); ?></td></tr>
			<?php endif; ?>
			<?php foreach ( $result['rows'] as $e ) : ?>
				<tr class="jatss-s-<?php echo esc_attr( $e['severity'] ); ?>">
					<td class="jatss-nowrap" title="<?php echo esc_attr( $e['created_at'] . ' UTC' ); ?>"><?php echo esc_html( get_date_from_gmt( $e['created_at'], 'M j, H:i:s' ) ); ?></td>
					<td><span class="jatss-sev jatss-sev-<?php echo esc_attr( $e['severity'] ); ?>"><?php echo esc_html( ucfirst( $e['severity'] ) ); ?></span></td>
					<td><?php echo esc_html( $e['message'] ); ?><br /><code class="jatss-type"><?php echo esc_html( $e['event_type'] ); ?></code></td>
					<td><?php echo '' !== $e['username'] ? esc_html( $e['username'] ) : '&mdash;'; ?></td>
					<td><code><?php echo esc_html( $e['ip'] ); ?></code></td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
		<?php if ( $pages > 1 ) : ?>
			<div class="tablenav"><div class="tablenav-pages">
				<?php
				echo wp_kses_post(
					paginate_links(
						array(
							'base'    => add_query_arg( 'paged', '%#%' ),
							'format'  => '',
							'current' => $paged,
							'total'   => $pages,
						)
					)
				);
				?>
			</div></div>
		<?php endif; ?>
		<p class="description">
			<?php
			/* translators: %d: days */
			echo esc_html( sprintf( __( 'Events are kept for %d days.', 'jat-site-shield' ), Settings::get( 'log_retention_days' ) ) );
			?>
		</p>
		<?php $this->about(); ?>
		</div>
		<?php
	}

	/**
	 * File integrity.
	 */
	public function page_files() {
		$last  = File_Integrity::last();
		$state = File_Integrity::state();
		$this->header( __( 'File integrity', 'jat-site-shield' ) );
		?>
		<div class="jatss-panel">
			<p><?php esc_html_e( 'Compares WordPress core and WordPress.org plugins with their official checksums, and looks for PHP files where they don\'t belong. Runs daily.', 'jat-site-shield' ); ?></p>
			<?php if ( 'running' === $state['status'] ) : ?>
				<?php /* translators: 1: done, 2: total */ ?>
				<p><strong><?php echo esc_html( sprintf( __( 'Scan running: %1$d of %2$d steps done. Reload to see progress.', 'jat-site-shield' ), $state['done'], $state['total'] ) ); ?></strong></p>
			<?php else : ?>
				<?php $this->post_button( 'jatss_scan', array(), __( 'Scan now', 'jat-site-shield' ), 'button-primary' ); ?>
			<?php endif; ?>
		</div>

		<?php if ( $last ) : ?>
			<?php
			$open = array();
			$info = array();
			$ack  = array();
			foreach ( $last['findings'] as $f ) {
				if ( File_Integrity::is_acknowledged( $f ) ) {
					$ack[] = $f;
				} elseif ( 'info' === $f['severity'] ) {
					$info[] = $f;
				} else {
					$open[] = $f;
				}
			}
			$order = array_flip( array_reverse( Event_Log::SEVERITIES ) );
			usort(
				$open,
				static function ( $a, $b ) use ( $order ) {
					return $order[ $a['severity'] ] <=> $order[ $b['severity'] ];
				}
			);
			?>
			<h2>
				<?php
				/* translators: %s: time */
				echo esc_html( sprintf( __( 'Results from %s ago', 'jat-site-shield' ), human_time_diff( $last['finished'] ) ) );
				?>
			</h2>
			<?php if ( ! $open ) : ?>
				<div class="notice notice-success inline"><p><?php esc_html_e( 'No files need review.', 'jat-site-shield' ); ?></p></div>
			<?php else : ?>
				<p><?php esc_html_e( 'Check each file. If it is yours and expected, accept it; it will be reported again only if it changes. If you don\'t recognise it, inspect it with JAT Shell Scanner or restore the original.', 'jat-site-shield' ); ?></p>
				<?php $this->findings_table( $open, true ); ?>
				<p><?php $this->post_button( 'jatss_ack_all', array(), __( 'Accept all of these', 'jat-site-shield' ), 'button-link-delete' ); ?> <span class="description"><?php esc_html_e( 'Only after checking them, for example after a theme you built was edited.', 'jat-site-shield' ); ?></span></p>
			<?php endif; ?>

			<?php if ( $info ) : ?>
				<details class="jatss-details"><summary><?php /* translators: %d: count */ echo esc_html( sprintf( _n( '%d informational item', '%d informational items', count( $info ), 'jat-site-shield' ), count( $info ) ) ); ?></summary>
					<?php $this->findings_table( $info, false ); ?>
				</details>
			<?php endif; ?>
			<?php if ( $ack ) : ?>
				<details class="jatss-details"><summary><?php /* translators: %d: count */ echo esc_html( sprintf( _n( '%d accepted file', '%d accepted files', count( $ack ), 'jat-site-shield' ), count( $ack ) ) ); ?></summary>
					<?php $this->findings_table( $ack, false ); ?>
				</details>
			<?php endif; ?>
			<?php if ( ! empty( $last['notes'] ) ) : ?>
				<details class="jatss-details"><summary><?php esc_html_e( 'Scan notes', 'jat-site-shield' ); ?></summary>
					<ul><?php foreach ( $last['notes'] as $target => $note ) : ?><li><code><?php echo esc_html( $target ); ?></code> — <?php echo esc_html( $note ); ?></li><?php endforeach; ?></ul>
				</details>
			<?php endif; ?>
		<?php endif; ?>
		<?php $this->about(); ?>
		</div>
		<?php
	}

	/**
	 * Findings table.
	 *
	 * @param array $findings Findings.
	 * @param bool  $actions  Show accept buttons.
	 */
	private function findings_table( array $findings, $actions ) {
		?>
		<table class="widefat jatss-table">
			<thead><tr>
				<th scope="col"><?php esc_html_e( 'Severity', 'jat-site-shield' ); ?></th>
				<th scope="col"><?php esc_html_e( 'File', 'jat-site-shield' ); ?></th>
				<th scope="col"><?php esc_html_e( 'Issue', 'jat-site-shield' ); ?></th>
				<th scope="col"><?php esc_html_e( 'Modified', 'jat-site-shield' ); ?></th>
				<?php if ( $actions ) : ?><th scope="col"><span class="screen-reader-text"><?php esc_html_e( 'Actions', 'jat-site-shield' ); ?></span></th><?php endif; ?>
			</tr></thead>
			<tbody>
			<?php foreach ( array_slice( $findings, 0, 500 ) as $f ) : ?>
				<tr class="jatss-s-<?php echo esc_attr( $f['severity'] ); ?>">
					<td><span class="jatss-sev jatss-sev-<?php echo esc_attr( $f['severity'] ); ?>"><?php echo esc_html( ucfirst( $f['severity'] ) ); ?></span></td>
					<td><code><?php echo esc_html( $f['path'] ); ?></code><?php echo $f['detail'] ? '<br /><span class="description">' . esc_html( $f['detail'] ) . '</span>' : ''; ?></td>
					<td><?php echo esc_html( File_Integrity::kind_label( $f['kind'], true ) ); ?></td>
					<td class="jatss-nowrap"><?php echo $f['mtime'] ? esc_html( wp_date( 'M j Y, H:i', $f['mtime'] ) ) : '&mdash;'; ?></td>
					<?php if ( $actions ) : ?>
						<td class="jatss-right"><?php $this->post_button( 'jatss_ack', array( 'path' => $f['path'] ), __( 'Accept', 'jat-site-shield' ), 'button-small' ); ?></td>
					<?php endif; ?>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
		<?php
	}

	/**
	 * Settings.
	 */
	public function page_settings() {
		$s     = Settings::all();
		$roles = wp_roles()->get_names();
		$this->header( __( 'Settings', 'jat-site-shield' ) );
		?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="jatss-settings">
			<input type="hidden" name="action" value="jatss_save" />
			<?php wp_nonce_field( 'jatss_save' ); ?>

			<div class="jatss-panel">
				<h2><?php esc_html_e( 'Login protection', 'jat-site-shield' ); ?></h2>
				<table class="form-table" role="presentation">
					<?php $this->toggle( 'login_protection', __( 'Lock out IPs after failed logins', 'jat-site-shield' ) ); ?>
					<tr><th scope="row"><?php esc_html_e( 'Limits', 'jat-site-shield' ); ?></th><td class="jatss-inline-fields">
						<?php
						printf(
							/* translators: 1: attempts input, 2: window input, 3: lockout input */
							esc_html__( 'After %1$s failures in %2$s minutes, lock out for %3$s minutes.', 'jat-site-shield' ),
							$this->number( 'login_max_attempts' ), // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
							$this->number( 'login_window_minutes' ), // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
							$this->number( 'login_lockout_minutes' ) // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
						);
						echo '<br />';
						printf(
							/* translators: 1: count input, 2: hours input */
							esc_html__( 'After %1$s lockouts, lock out for %2$s hours.', 'jat-site-shield' ),
							$this->number( 'login_long_lockouts' ), // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
							$this->number( 'login_long_hours' ) // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
						);
						?>
					</td></tr>
					<?php $this->toggle( 'login_generic_errors', __( 'Don\'t reveal whether a username exists', 'jat-site-shield' ), __( 'Login and password-reset forms give the same answer either way.', 'jat-site-shield' ) ); ?>
					<tr><th scope="row"><label for="login_allowlist"><?php esc_html_e( 'Never lock out', 'jat-site-shield' ); ?></label></th><td>
						<textarea name="login_allowlist" id="login_allowlist" rows="3" class="large-text code" placeholder="203.0.113.10&#10;198.51.100.0/24"><?php echo esc_textarea( $s['login_allowlist'] ); ?></textarea>
						<?php /* translators: %s: IP */ ?>
						<p class="description"><?php echo wp_kses( sprintf( __( 'One IP or CIDR range per line, such as your office. Your IP right now: %s', 'jat-site-shield' ), '<code>' . esc_html( Request::ip() ) . '</code>' ), array( 'code' => array() ) ); ?></p>
					</td></tr>
					<?php $this->toggle( 'custom_login_enabled', __( 'Move the login page', 'jat-site-shield' ), __( 'wp-login.php and /wp-admin return "Not Found" to logged-out visitors. Bookmark the new address before saving. Login links your theme shows to logged-out visitors (such as "Log in to reply") will also return "Not Found".', 'jat-site-shield' ), is_multisite() ); ?>
					<tr><th scope="row"><label for="custom_login_slug"><?php esc_html_e( 'Login address', 'jat-site-shield' ); ?></label></th><td>
						<code><?php echo esc_html( trailingslashit( home_url() ) ); ?></code><input type="text" name="custom_login_slug" id="custom_login_slug" value="<?php echo esc_attr( $s['custom_login_slug'] ); ?>" class="regular-text" placeholder="<?php echo esc_attr( 'team-' . strtolower( wp_generate_password( 6, false ) ) ); ?>" />
						<p class="description"><?php esc_html_e( 'Locked out? Add define( \'JATSS_SAFE_MODE\', true ); to wp-config.php, or run: wp jat-shield login-url', 'jat-site-shield' ); ?></p>
					</td></tr>
				</table>
			</div>

			<div class="jatss-panel">
				<h2><?php esc_html_e( 'Two-factor authentication', 'jat-site-shield' ); ?></h2>
				<table class="form-table" role="presentation">
					<?php $this->toggle( 'twofa_enabled', __( 'Allow two-factor with an authenticator app', 'jat-site-shield' ) ); ?>
					<tr><th scope="row"><?php esc_html_e( 'Required for', 'jat-site-shield' ); ?></th><td>
						<fieldset><legend class="screen-reader-text"><?php esc_html_e( 'Roles that must use two-factor', 'jat-site-shield' ); ?></legend>
						<?php foreach ( $roles as $role => $name ) : ?>
							<label class="jatss-check"><input type="checkbox" name="twofa_required_roles[]" value="<?php echo esc_attr( $role ); ?>" <?php checked( in_array( $role, (array) $s['twofa_required_roles'], true ) ); ?> /> <?php echo esc_html( translate_user_role( $name ) ); ?></label>
						<?php endforeach; ?>
						</fieldset>
						<p class="description"><?php esc_html_e( 'People in these roles must set up two-factor before they can use the dashboard.', 'jat-site-shield' ); ?></p>
					</td></tr>
					<?php $this->toggle( 'twofa_block_xmlrpc', __( 'Block password logins over XML-RPC for two-factor users', 'jat-site-shield' ), __( 'Otherwise XML-RPC would skip the second step. Apps can use application passwords.', 'jat-site-shield' ) ); ?>
				</table>
			</div>

			<div class="jatss-panel">
				<h2><?php esc_html_e( 'Hardening', 'jat-site-shield' ); ?></h2>
				<table class="form-table" role="presentation">
					<?php $this->toggle( 'harden_xmlrpc', __( 'Block XML-RPC', 'jat-site-shield' ), Hardening::xmlrpc_needed() ? __( 'Jetpack is active and needs XML-RPC, so it stays on.', 'jat-site-shield' ) : __( 'Stops brute force and pingback abuse through xmlrpc.php.', 'jat-site-shield' ) ); ?>
					<?php $this->toggle( 'harden_user_enum', __( 'Block username scanning', 'jat-site-shield' ) ); ?>
					<?php $this->toggle( 'harden_file_edit', __( 'Turn off the theme and plugin file editor', 'jat-site-shield' ), defined( 'DISALLOW_FILE_EDIT' ) && ! $s['harden_file_edit'] ? __( 'Already set in wp-config.php.', 'jat-site-shield' ) : '' ); ?>
					<?php $this->toggle( 'harden_uploads_php', __( 'Block PHP in the uploads folder', 'jat-site-shield' ), __( 'Writes an .htaccess rule (Apache and LiteSpeed). On nginx-only hosts, ask the host to add the equivalent rule.', 'jat-site-shield' ) ); ?>
					<tr><th scope="row"></th><td>
						<?php
						$test = get_option( 'jatss_uploads_test' );
						if ( $test ) {
							$labels = array(
								'blocked'  => __( 'Last test: PHP is blocked in uploads.', 'jat-site-shield' ),
								'executes' => __( 'Last test: PHP still runs in uploads!', 'jat-site-shield' ),
								'unknown'  => __( 'Last test could not reach the site.', 'jat-site-shield' ),
							);
							echo '<p class="' . ( 'executes' === $test ? 'jatss-sev-critical' : 'description' ) . '">' . esc_html( $labels[ $test ] ) . '</p>';
						}
						?>
						<button type="submit" class="button" form="jatss-test-uploads"><?php esc_html_e( 'Test it now', 'jat-site-shield' ); ?></button>
					</td></tr>
					<?php $this->toggle( 'harden_headers', __( 'Send security headers', 'jat-site-shield' ) ); ?>
					<?php $this->toggle( 'harden_hsts', __( 'Send HSTS (force HTTPS in browsers for a year)', 'jat-site-shield' ), __( 'Only turn on once the whole site works over HTTPS.', 'jat-site-shield' ) ); ?>
					<?php $this->toggle( 'harden_hide_version', __( 'Hide the WordPress version', 'jat-site-shield' ) ); ?>
					<?php $this->toggle( 'harden_app_passwords', __( 'Turn off application passwords', 'jat-site-shield' ), __( 'Breaks the WordPress mobile app and integrations that use them.', 'jat-site-shield' ) ); ?>
				</table>
			</div>

			<div class="jatss-panel">
				<h2><?php esc_html_e( 'Monitoring and alerts', 'jat-site-shield' ); ?></h2>
				<table class="form-table" role="presentation">
					<?php $this->toggle( 'log_enabled', __( 'Keep an activity log', 'jat-site-shield' ) ); ?>
					<tr><th scope="row"><label for="log_retention_days"><?php esc_html_e( 'Keep events for', 'jat-site-shield' ); ?></label></th><td><?php echo $this->number( 'log_retention_days' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?> <?php esc_html_e( 'days', 'jat-site-shield' ); ?></td></tr>
					<tr><th scope="row"><label for="alert_emails"><?php esc_html_e( 'Email alerts to', 'jat-site-shield' ); ?></label></th><td>
						<input type="text" name="alert_emails" id="alert_emails" class="large-text" value="<?php echo esc_attr( $s['alert_emails'] ); ?>" placeholder="<?php echo esc_attr( get_option( 'admin_email' ) ); ?>" />
						<p class="description"><?php esc_html_e( 'Comma-separated. Empty sends to the site admin email. At most 10 alerts an hour.', 'jat-site-shield' ); ?></p>
						<p><button type="submit" class="button" form="jatss-test-alert"><?php esc_html_e( 'Send a test alert', 'jat-site-shield' ); ?></button></p>
					</td></tr>
					<tr><th scope="row"><label for="alert_min_severity"><?php esc_html_e( 'Alert on', 'jat-site-shield' ); ?></label></th><td>
						<select name="alert_min_severity" id="alert_min_severity">
							<option value="critical" <?php selected( $s['alert_min_severity'], 'critical' ); ?>><?php esc_html_e( 'Critical events only', 'jat-site-shield' ); ?></option>
							<option value="warning" <?php selected( $s['alert_min_severity'], 'warning' ); ?>><?php esc_html_e( 'Warnings and critical events', 'jat-site-shield' ); ?></option>
						</select>
					</td></tr>
					<?php $this->toggle( 'fim_enabled', __( 'Daily file integrity scan', 'jat-site-shield' ) ); ?>
					<?php $this->toggle( 'fim_plugins', __( 'Include WordPress.org plugins', 'jat-site-shield' ) ); ?>
				</table>
			</div>

			<div class="jatss-panel">
				<h2><?php esc_html_e( 'Network', 'jat-site-shield' ); ?></h2>
				<table class="form-table" role="presentation">
					<tr><th scope="row"><label for="ip_source"><?php esc_html_e( 'Visitor IP comes from', 'jat-site-shield' ); ?></label></th><td>
						<select name="ip_source" id="ip_source">
							<?php foreach ( Request::ip_sources() as $key => $label ) : ?>
								<option value="<?php echo esc_attr( $key ); ?>" <?php selected( $s['ip_source'], $key ); ?>><?php echo esc_html( $label ); ?></option>
							<?php endforeach; ?>
						</select>
						<p class="description"><?php esc_html_e( 'Automatic works for most sites, including sites behind Cloudflare. Only change it if every visitor shows the same IP below. A header is only believed when the request really comes from Cloudflare, a private network or a trusted proxy.', 'jat-site-shield' ); ?></p>
					</td></tr>
					<tr><th scope="row"><?php esc_html_e( 'This request', 'jat-site-shield' ); ?></th><td>
						<table class="widefat jatss-table jatss-ipcheck">
							<tbody>
							<?php foreach ( Request::diagnostics() as $key => $value ) : ?>
								<tr><td><code><?php echo esc_html( $key ); ?></code></td><td><?php echo '' !== $value ? '<code>' . esc_html( $value ) . '</code>' : '&mdash;'; ?></td></tr>
							<?php endforeach; ?>
							<tr class="jatss-s-ok"><td><strong><?php esc_html_e( 'Site Shield uses', 'jat-site-shield' ); ?></strong></td><td><code><?php echo esc_html( Request::ip() ); ?></code><?php echo Request::via_cloudflare() ? ' ' . esc_html__( '(through Cloudflare)', 'jat-site-shield' ) : ''; ?></td></tr>
							</tbody>
						</table>
						<p class="description"><?php esc_html_e( 'The last row should be your own public IP. If it shows a private address such as 127.0.0.1 or 10.x, add that address under Trusted proxies.', 'jat-site-shield' ); ?></p>
					</td></tr>
					<tr><th scope="row"><label for="trusted_proxies"><?php esc_html_e( 'Trusted proxies', 'jat-site-shield' ); ?></label></th><td>
						<textarea name="trusted_proxies" id="trusted_proxies" rows="2" class="large-text code" placeholder="203.0.113.0/24"><?php echo esc_textarea( $s['trusted_proxies'] ); ?></textarea>
						<p class="description"><?php esc_html_e( 'Addresses of proxies between visitors and WordPress that you control: a load balancer, Sucuri, or a web server on the same machine (127.0.0.1) that passes Cloudflare’s header on. Cloudflare itself needs no entry.', 'jat-site-shield' ); ?></p>
					</td></tr>
					<tr><th scope="row"><?php esc_html_e( 'Cloudflare', 'jat-site-shield' ); ?></th><td>
						<p><?php esc_html_e( 'Cloudflare’s free plan blocks attacks before they reach your server and works alongside Site Shield.', 'jat-site-shield' ); ?> <a href="<?php echo esc_url( 'https://github.com/CptNope/JAT-Site-Shield/blob/main/docs/cloudflare.md' ); ?>" target="_blank" rel="noopener"><?php esc_html_e( 'Free Cloudflare setup guide', 'jat-site-shield' ); ?></a></p>
					</td></tr>
				</table>
			</div>

			<?php submit_button( __( 'Save settings', 'jat-site-shield' ) ); ?>
		</form>
		<form id="jatss-test-alert" method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<input type="hidden" name="action" value="jatss_test_alert" />
			<?php wp_nonce_field( 'jatss_test_alert' ); ?>
		</form>
		<form id="jatss-test-uploads" method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<input type="hidden" name="action" value="jatss_test_uploads" />
			<?php wp_nonce_field( 'jatss_test_uploads' ); ?>
		</form>
		<?php $this->about(); ?>
		</div>
		<?php
	}

	/**
	 * A checkbox row.
	 *
	 * @param string $key      Setting.
	 * @param string $label    Label.
	 * @param string $help     Help text.
	 * @param bool   $disabled Disabled.
	 */
	private function toggle( $key, $label, $help = '', $disabled = false ) {
		$value = Settings::get( $key );
		?>
		<tr><th scope="row"></th><td>
			<input type="hidden" name="<?php echo esc_attr( $key ); ?>" value="0" />
			<label><input type="checkbox" name="<?php echo esc_attr( $key ); ?>" id="<?php echo esc_attr( $key ); ?>" value="1" <?php checked( $value ); ?> <?php disabled( $disabled ); ?> /> <strong><?php echo esc_html( $label ); ?></strong></label>
			<?php if ( $help ) : ?><p class="description"><?php echo esc_html( $help ); ?></p><?php endif; ?>
		</td></tr>
		<?php
	}

	/**
	 * A small number input (returns HTML).
	 *
	 * @param string $key Setting.
	 * @return string
	 */
	private function number( $key ) {
		return '<input type="number" min="1" class="small-text" name="' . esc_attr( $key ) . '" id="' . esc_attr( $key ) . '" value="' . esc_attr( (string) Settings::get( $key ) ) . '" />';
	}

	/**
	 * A one-button POST form.
	 *
	 * @param string $action admin-post action.
	 * @param array  $fields Hidden fields.
	 * @param string $label  Button text.
	 * @param string $class  Button class.
	 */
	private function post_button( $action, array $fields, $label, $class = '' ) {
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" class="jatss-inline">';
		echo '<input type="hidden" name="action" value="' . esc_attr( $action ) . '" />';
		foreach ( $fields as $name => $value ) {
			echo '<input type="hidden" name="' . esc_attr( $name ) . '" value="' . esc_attr( $value ) . '" />';
		}
		wp_nonce_field( $action );
		echo '<button type="submit" class="button ' . esc_attr( $class ) . '">' . esc_html( $label ) . '</button></form>';
	}

	/* ------------------------------------------------------------------ */
	/* Handlers                                                            */
	/* ------------------------------------------------------------------ */

	/**
	 * Check capability and nonce.
	 *
	 * @param string $action Nonce action.
	 */
	private function guard( $action ) {
		if ( ! current_user_can( self::CAP ) ) {
			wp_die( esc_html__( 'You are not allowed to do that.', 'jat-site-shield' ), 403 );
		}
		check_admin_referer( $action );
	}

	/**
	 * Back to a screen with a message.
	 *
	 * @param string $page  Page slug suffix.
	 * @param string $msg   Message.
	 * @param bool   $error Error.
	 */
	private function back( $page, $msg, $error = false ) {
		$args = array(
			'page'         => self::SLUG . $page,
			'jatss_msg' => rawurlencode( $msg ),
		);
		if ( $error ) {
			$args['jatss_err'] = 1;
		}
		wp_safe_redirect( add_query_arg( $args, admin_url( 'admin.php' ) ) );
		exit;
	}

	/**
	 * Save settings.
	 */
	public function save_settings() {
		$this->guard( 'jatss_save' );
		$input = array();
		foreach ( array_keys( Settings::defaults() ) as $key ) {
			if ( isset( $_POST[ $key ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
				$input[ $key ] = is_array( $_POST[ $key ] ) ? array_map( 'sanitize_text_field', wp_unslash( $_POST[ $key ] ) ) : wp_unslash( $_POST[ $key ] ); // phpcs:ignore WordPress.Security
			}
		}
		// Unticking every role sends nothing.
		if ( ! isset( $_POST['twofa_required_roles'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			$input['twofa_required_roles'] = array();
		}

		$was_uploads = Settings::get( 'harden_uploads_php' );
		$result      = Settings::update( $input );
		if ( is_wp_error( $result ) ) {
			$this->back( '-settings', $result->get_error_message(), true );
		}

		if ( Settings::get( 'harden_uploads_php' ) !== $was_uploads || Settings::get( 'harden_uploads_php' ) ) {
			Hardening::write_uploads_rules( (bool) Settings::get( 'harden_uploads_php' ) );
			delete_option( 'jatss_uploads_test' );
		}

		$msg = __( 'Settings saved.', 'jat-site-shield' );
		if ( in_array( 'custom_login_slug', $result, true ) || in_array( 'custom_login_enabled', $result, true ) ) {
			if ( Settings::get( 'custom_login_enabled' ) ) {
				/* translators: %s: URL */
				$msg .= ' ' . sprintf( __( 'Your login page is now %s — bookmark it.', 'jat-site-shield' ), Login_Url::url() );
				Event_Log::log( 'shield.login_url_changed', 'warning', __( 'The login address was changed.', 'jat-site-shield' ) );
			}
		}
		$this->back( '-settings', $msg );
	}

	/**
	 * Unlock an IP.
	 */
	public function unlock() {
		$this->guard( 'jatss_unlock' );
		$ip = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( 'all' !== $ip && ! Request::is_valid_ip_or_cidr( $ip ) ) {
			$this->back( '', __( 'Not a valid IP.', 'jat-site-shield' ), true );
		}
		$n = Login_Protection::unlock( $ip );
		/* translators: %d: count */
		$this->back( '', sprintf( _n( '%d lockout lifted.', '%d lockouts lifted.', $n, 'jat-site-shield' ), $n ) );
	}

	/**
	 * Start a scan and run the first part now.
	 */
	public function run_scan() {
		$this->guard( 'jatss_scan' );
		$fim = Plugin::instance()->module( 'fim' );
		$fim->start_scan( 'manual' );
		$fim->tick( 15 );
		$state = File_Integrity::state();
		$msg   = 'running' === $state['status']
			? __( 'Scan started. It continues in the background; reload in a minute.', 'jat-site-shield' )
			: __( 'Scan finished.', 'jat-site-shield' );
		$this->back( '-files', $msg );
	}

	/**
	 * Accept a finding.
	 */
	public function acknowledge() {
		$this->guard( 'jatss_ack' );
		$path = isset( $_POST['path'] ) ? wp_unslash( $_POST['path'] ) : ''; // phpcs:ignore WordPress.Security
		$ok   = File_Integrity::acknowledge( (string) $path );
		$this->back( '-files', $ok ? __( 'Accepted. It will be reported again if the file changes.', 'jat-site-shield' ) : __( 'That finding was not found.', 'jat-site-shield' ), ! $ok );
	}

	/**
	 * Accept every open finding.
	 */
	public function acknowledge_all() {
		$this->guard( 'jatss_ack_all' );
		$n = File_Integrity::acknowledge_all();
		/* translators: %d: count */
		$this->back( '-files', sprintf( _n( '%d finding accepted.', '%d findings accepted.', $n, 'jat-site-shield' ), $n ) );
	}

	/**
	 * Test PHP execution in uploads.
	 */
	public function test_uploads() {
		$this->guard( 'jatss_test_uploads' );
		$result = Hardening::test_uploads_php();
		update_option( 'jatss_uploads_test', $result, false );
		if ( 'executes' === $result ) {
			Event_Log::log( 'harden.uploads_php_executes', 'warning', __( 'Test showed PHP files can run from the uploads folder.', 'jat-site-shield' ) );
		}
		$msgs = array(
			'blocked'  => __( 'PHP is blocked in uploads.', 'jat-site-shield' ),
			'executes' => __( 'PHP still runs in uploads. The server is probably ignoring .htaccess; ask your host to block PHP in wp-content/uploads.', 'jat-site-shield' ),
			'unknown'  => __( 'The site could not reach itself to run the test (loopback request failed).', 'jat-site-shield' ),
		);
		$this->back( '-settings', $msgs[ $result ], 'executes' === $result );
	}

	/**
	 * Send a test alert email.
	 */
	public function test_alert() {
		$this->guard( 'jatss_test_alert' );
		$ok = \JATSiteShield\Alerts::send_test();
		$this->back(
			'-settings',
			$ok
				/* translators: %s: email addresses */
				? sprintf( __( 'Test alert sent to %s. If it doesn’t arrive within a few minutes, check spam, then set up an SMTP plugin so this site can send email reliably.', 'jat-site-shield' ), implode( ', ', \JATSiteShield\Alerts::recipients() ) )
				: __( 'WordPress couldn’t send the email. This site can’t send mail yet; set up an SMTP plugin, or alerts won’t reach you.', 'jat-site-shield' ),
			! $ok
		);
	}

	/**
	 * Download the filtered log as CSV.
	 */
	public function export_csv() {
		if ( ! current_user_can( self::CAP ) ) {
			wp_die( esc_html__( 'You are not allowed to do that.', 'jat-site-shield' ), 403 );
		}
		check_admin_referer( 'jatss_export' );
		// phpcs:disable WordPress.Security.NonceVerification.Recommended
		$args = array(
			'severity' => isset( $_GET['severity'] ) ? sanitize_key( $_GET['severity'] ) : '',
			'type'     => isset( $_GET['type'] ) ? sanitize_text_field( wp_unslash( $_GET['type'] ) ) : '',
			'search'   => isset( $_GET['s'] ) ? sanitize_text_field( wp_unslash( $_GET['s'] ) ) : '',
			'per_page' => 500,
		);
		// phpcs:enable
		nocache_headers();
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="jat-site-shield-log-' . gmdate( 'Y-m-d' ) . '.csv"' );
		$out = fopen( 'php://output', 'w' ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		fputcsv( $out, array( 'time_utc', 'severity', 'event', 'message', 'user', 'ip', 'user_agent', 'object_type', 'object_id', 'context' ), ',', '"', '\\' );
		for ( $page = 1; $page <= 200; $page++ ) {
			$args['page'] = $page;
			$rows         = Event_Log::query( $args )['rows'];
			foreach ( $rows as $r ) {
				$line = array( $r['created_at'], $r['severity'], $r['event_type'], $r['message'], $r['username'], $r['ip'], $r['user_agent'], $r['object_type'], $r['object_id'], (string) $r['context'] );
				// Stop spreadsheet formula injection.
				foreach ( $line as &$cell ) {
					if ( is_string( $cell ) && preg_match( '/^[=+\-@\t\r]/', $cell ) ) {
						$cell = "'" . $cell;
					}
				}
				unset( $cell );
				fputcsv( $out, $line, ',', '"', '\\' );
			}
			if ( count( $rows ) < 500 ) {
				break;
			}
		}
		fclose( $out ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		exit;
	}
}
