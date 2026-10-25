<?php
/**
 * Admin screens.
 *
 * @package AndersonSiteShield
 */

namespace AndersonSiteShield\Admin;

use AndersonSiteShield\Event_Log;
use AndersonSiteShield\Modules\File_Integrity;
use AndersonSiteShield\Modules\Hardening;
use AndersonSiteShield\Modules\Login_Protection;
use AndersonSiteShield\Modules\Login_Url;
use AndersonSiteShield\Modules\Two_Factor;
use AndersonSiteShield\Plugin;
use AndersonSiteShield\Request;
use AndersonSiteShield\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Overview, activity log, file integrity and settings screens.
 */
class Admin {

	const CAP  = 'manage_options';
	const SLUG = 'anderson-site-shield';

	/**
	 * Hook in.
	 */
	public function register() {
		add_action( 'admin_menu', array( $this, 'menu' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'assets' ) );
		add_action( 'admin_post_anshield_save', array( $this, 'save_settings' ) );
		add_action( 'admin_post_anshield_unlock', array( $this, 'unlock' ) );
		add_action( 'admin_post_anshield_scan', array( $this, 'run_scan' ) );
		add_action( 'admin_post_anshield_ack', array( $this, 'acknowledge' ) );
		add_action( 'admin_post_anshield_ack_all', array( $this, 'acknowledge_all' ) );
		add_action( 'admin_post_anshield_export', array( $this, 'export_csv' ) );
		add_action( 'admin_post_anshield_test_uploads', array( $this, 'test_uploads' ) );
		add_filter( 'plugin_action_links_' . ANSHIELD_BASENAME, array( $this, 'action_links' ) );
		add_action( 'admin_notices', array( $this, 'notices' ) );
	}

	/**
	 * Menu.
	 */
	public function menu() {
		$critical = $this->unseen_critical();
		$bubble   = $critical ? ' <span class="awaiting-mod"><span class="pending-count">' . (int) $critical . '</span></span>' : '';

		add_menu_page( __( 'Site Shield', 'anderson-site-shield' ), __( 'Site Shield', 'anderson-site-shield' ) . $bubble, self::CAP, self::SLUG, array( $this, 'page_overview' ), 'dashicons-shield', 80 );
		add_submenu_page( self::SLUG, __( 'Overview', 'anderson-site-shield' ), __( 'Overview', 'anderson-site-shield' ), self::CAP, self::SLUG, array( $this, 'page_overview' ) );
		add_submenu_page( self::SLUG, __( 'Activity log', 'anderson-site-shield' ), __( 'Activity log', 'anderson-site-shield' ), self::CAP, self::SLUG . '-log', array( $this, 'page_log' ) );
		add_submenu_page( self::SLUG, __( 'File integrity', 'anderson-site-shield' ), __( 'File integrity', 'anderson-site-shield' ), self::CAP, self::SLUG . '-files', array( $this, 'page_files' ) );
		add_submenu_page( self::SLUG, __( 'Settings', 'anderson-site-shield' ), __( 'Settings', 'anderson-site-shield' ), self::CAP, self::SLUG . '-settings', array( $this, 'page_settings' ) );
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
		$seen = (int) get_user_meta( get_current_user_id(), 'anshield_seen', true );
		$key  = 'anshield_crit_' . get_current_user_id();
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
			wp_enqueue_style( 'anshield-admin', ANSHIELD_URL . 'assets/admin.css', array(), ANSHIELD_VERSION );
		}
	}

	/**
	 * Settings link on the Plugins screen.
	 *
	 * @param array $links Links.
	 * @return array
	 */
	public function action_links( $links ) {
		array_unshift( $links, '<a href="' . esc_url( admin_url( 'admin.php?page=' . self::SLUG . '-settings' ) ) . '">' . esc_html__( 'Settings', 'anderson-site-shield' ) . '</a>' );
		return $links;
	}

	/**
	 * Safe-mode warning everywhere in the dashboard.
	 */
	public function notices() {
		if ( current_user_can( self::CAP ) && Request::proxy_misconfigured() ) {
			echo '<div class="notice notice-warning"><p><strong>' . esc_html__( 'Site Shield: this site is behind Cloudflare.', 'anderson-site-shield' ) . '</strong> ' . esc_html__( 'Every visitor currently shares a Cloudflare IP, so a few wrong passwords can lock out everyone. Set "Visitor IP comes from" to Cloudflare in Site Shield settings.', 'anderson-site-shield' ) . '</p></div>';
		}
		if ( ANSHIELD_SAFE_MODE && current_user_can( self::CAP ) ) {
			echo '<div class="notice notice-error"><p><strong>' . esc_html__( 'Site Shield safe mode is on.', 'anderson-site-shield' ) . '</strong> ' . esc_html__( 'The custom login URL, two-factor and login lockouts are paused. Remove ANSHIELD_SAFE_MODE from wp-config.php when you are back in.', 'anderson-site-shield' ) . '</p></div>';
		}
	}

	/* ------------------------------------------------------------------ */
	/* Status checks                                                       */
	/* ------------------------------------------------------------------ */

	/**
	 * Protection checklist (also used by `wp site-shield status`).
	 *
	 * @return array[] label, ok, note.
	 */
	public static function checks() {
		$s      = Settings::all();
		$checks = array();

		$checks[] = array(
			'label' => __( 'Login lockouts', 'anderson-site-shield' ),
			'ok'    => $s['login_protection'],
			/* translators: 1: attempts, 2: minutes */
			'note'  => $s['login_protection'] ? sprintf( __( '%1$d failures locks an IP out for %2$d minutes.', 'anderson-site-shield' ), $s['login_max_attempts'], $s['login_lockout_minutes'] ) : __( 'Anyone can guess passwords without limit.', 'anderson-site-shield' ),
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
			'label' => __( 'Two-factor for required roles', 'anderson-site-shield' ),
			'ok'    => $s['twofa_enabled'] && $required && ! $unenrolled,
			'note'  => ! $s['twofa_enabled'] || ! $required
				? __( 'Not required for any role.', 'anderson-site-shield' )
				: ( $unenrolled
					/* translators: %s: usernames */
					? sprintf( __( 'Not set up yet: %s (they must enroll at next login).', 'anderson-site-shield' ), implode( ', ', array_slice( $unenrolled, 0, 10 ) ) )
					/* translators: %s: roles */
					: sprintf( __( 'Required and set up for: %s.', 'anderson-site-shield' ), implode( ', ', $required ) ) ),
		);

		$checks[] = array(
			'label' => __( 'Custom login URL', 'anderson-site-shield' ),
			'ok'    => Login_Url::enabled() || ( $s['custom_login_enabled'] && ( defined( 'WP_CLI' ) && WP_CLI ) ),
			'note'  => $s['custom_login_enabled'] ? Login_Url::url() : __( 'Optional. Bots go straight to wp-login.php.', 'anderson-site-shield' ),
		);

		$xmlrpc_note = Hardening::xmlrpc_needed() ? __( 'Left on because Jetpack needs it.', 'anderson-site-shield' ) : __( 'Brute-force and pingback attacks over xmlrpc.php.', 'anderson-site-shield' );
		$checks[]    = array(
			'label' => __( 'XML-RPC blocked', 'anderson-site-shield' ),
			'ok'    => $s['harden_xmlrpc'] && ! Hardening::xmlrpc_needed(),
			'note'  => $xmlrpc_note,
		);
		$checks[]    = array(
			'label' => __( 'Username scanning blocked', 'anderson-site-shield' ),
			'ok'    => $s['harden_user_enum'],
			'note'  => __( '?author=, REST /users, oEmbed and the users sitemap.', 'anderson-site-shield' ),
		);
		$checks[]    = array(
			'label' => __( 'Theme and plugin editor off', 'anderson-site-shield' ),
			'ok'    => defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT,
			'note'  => __( 'A stolen admin login can\'t edit PHP from the dashboard.', 'anderson-site-shield' ),
		);
		$checks[]    = array(
			'label' => __( 'PHP blocked in uploads', 'anderson-site-shield' ),
			'ok'    => $s['harden_uploads_php'] && 'executes' !== get_option( 'anshield_uploads_test' ),
			'note'  => 'executes' === get_option( 'anshield_uploads_test' )
				? __( 'Test showed PHP still runs in uploads. Your server may ignore .htaccess (nginx); ask your host to block it.', 'anderson-site-shield' )
				: ( 'blocked' === get_option( 'anshield_uploads_test' ) ? __( 'Verified by a live test.', 'anderson-site-shield' ) : __( 'Rules written; run the test on the Settings screen to confirm.', 'anderson-site-shield' ) ),
		);
		$checks[]    = array(
			'label' => __( 'Security headers', 'anderson-site-shield' ),
			'ok'    => $s['harden_headers'],
			'note'  => __( 'nosniff, frame protection, referrer and permissions policy.', 'anderson-site-shield' ),
		);
		$checks[]    = array(
			'label' => __( 'HTTPS', 'anderson-site-shield' ),
			'ok'    => 0 === strpos( home_url(), 'https://' ),
			'note'  => 0 === strpos( home_url(), 'https://' ) ? __( 'Site address uses HTTPS.', 'anderson-site-shield' ) : __( 'Site address is not HTTPS; logins travel unencrypted.', 'anderson-site-shield' ),
		);
		$checks[]    = array(
			'label' => __( 'Activity log and alerts', 'anderson-site-shield' ),
			'ok'    => $s['log_enabled'],
			/* translators: %s: emails */
			'note'  => sprintf( __( 'Alerts to %s.', 'anderson-site-shield' ), implode( ', ', \AndersonSiteShield\Alerts::recipients() ) ),
		);

		$last     = File_Integrity::last();
		$checks[] = array(
			'label' => __( 'File integrity monitoring', 'anderson-site-shield' ),
			'ok'    => $s['fim_enabled'] && $last && time() - $last['finished'] < 3 * DAY_IN_SECONDS,
			'note'  => ! $s['fim_enabled'] ? __( 'Off.', 'anderson-site-shield' ) : ( $last
				/* translators: %s: time ago */
				? sprintf( __( 'Last scan %s ago.', 'anderson-site-shield' ), human_time_diff( $last['finished'] ) )
				: __( 'No scan yet.', 'anderson-site-shield' ) ),
		);

		$debug    = defined( 'WP_DEBUG_DISPLAY' ) ? WP_DEBUG_DISPLAY : true;
		$checks[] = array(
			'label' => __( 'Errors hidden from visitors', 'anderson-site-shield' ),
			'ok'    => ! ( defined( 'WP_DEBUG' ) && WP_DEBUG && $debug ),
			'note'  => __( 'WP_DEBUG with display on leaks file paths to visitors.', 'anderson-site-shield' ),
		);

		$admin_user = get_user_by( 'login', 'admin' );
		$checks[]   = array(
			'label' => __( 'No "admin" username', 'anderson-site-shield' ),
			'ok'    => ! $admin_user,
			'note'  => $admin_user ? __( 'An account named "admin" is the first one bots guess. Create a new admin and delete it.', 'anderson-site-shield' ) : __( 'Good.', 'anderson-site-shield' ),
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
		echo '<div class="wrap anshield-wrap"><h1 class="anshield-title"><span class="dashicons dashicons-shield" aria-hidden="true"></span> ' . esc_html( $title ) . '</h1>';
		// phpcs:disable WordPress.Security.NonceVerification.Recommended
		if ( ! empty( $_GET['anshield_msg'] ) ) {
			$type = ! empty( $_GET['anshield_err'] ) ? 'error' : 'success';
			echo '<div class="notice notice-' . esc_attr( $type ) . ' is-dismissible"><p>' . esc_html( sanitize_text_field( wp_unslash( $_GET['anshield_msg'] ) ) ) . '</p></div>';
		}
		// phpcs:enable
	}

	/**
	 * Overview.
	 */
	public function page_overview() {
		update_user_meta( get_current_user_id(), 'anshield_seen', time() );
		delete_transient( 'anshield_crit_' . get_current_user_id() );

		$checks = self::checks();
		$ok     = count( array_filter( wp_list_pluck( $checks, 'ok' ) ) );
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

		$this->header( __( 'Site Shield', 'anderson-site-shield' ) );
		?>
		<div class="anshield-grid">
			<div class="anshield-card anshield-score">
				<div class="anshield-score-num"><?php echo (int) $ok; ?><span>/<?php echo (int) count( $checks ); ?></span></div>
				<div><?php esc_html_e( 'protections in place', 'anderson-site-shield' ); ?></div>
			</div>
			<div class="anshield-card">
				<div class="anshield-stat"><span class="anshield-stat-num anshield-sev-critical"><?php echo (int) $day['critical']; ?></span><?php esc_html_e( 'critical, 24 h', 'anderson-site-shield' ); ?></div>
				<div class="anshield-stat"><span class="anshield-stat-num anshield-sev-warning"><?php echo (int) $day['warning']; ?></span><?php esc_html_e( 'warnings, 24 h', 'anderson-site-shield' ); ?></div>
			</div>
			<div class="anshield-card">
				<div class="anshield-stat"><span class="anshield-stat-num"><?php echo (int) count( $locks ); ?></span><?php esc_html_e( 'IPs locked out now', 'anderson-site-shield' ); ?></div>
				<div class="anshield-stat"><span class="anshield-stat-num"><?php echo (int) ( $week['info'] + $week['notice'] + $week['warning'] + $week['critical'] ); ?></span><?php esc_html_e( 'events, 7 days', 'anderson-site-shield' ); ?></div>
			</div>
		</div>

		<div class="anshield-columns">
			<div class="anshield-card">
				<h2><?php esc_html_e( 'Protection checklist', 'anderson-site-shield' ); ?></h2>
				<ul class="anshield-checks">
					<?php foreach ( $checks as $c ) : ?>
						<li class="<?php echo $c['ok'] ? 'is-ok' : 'is-off'; ?>">
							<span class="dashicons <?php echo $c['ok'] ? 'dashicons-yes-alt' : 'dashicons-warning'; ?>" aria-hidden="true"></span>
							<div><strong><?php echo esc_html( $c['label'] ); ?></strong><span class="screen-reader-text"> — <?php echo $c['ok'] ? esc_html__( 'on', 'anderson-site-shield' ) : esc_html__( 'needs attention', 'anderson-site-shield' ); ?></span><br /><span class="description"><?php echo esc_html( $c['note'] ); ?></span></div>
						</li>
					<?php endforeach; ?>
				</ul>
			</div>

			<div>
				<div class="anshield-card">
					<h2><?php esc_html_e( 'Needs a look', 'anderson-site-shield' ); ?></h2>
					<?php if ( ! $recent['rows'] ) : ?>
						<p class="description"><?php esc_html_e( 'No warnings or critical events. Quiet is good.', 'anderson-site-shield' ); ?></p>
					<?php else : ?>
						<ul class="anshield-events">
							<?php foreach ( $recent['rows'] as $e ) : ?>
								<li><span class="anshield-pill anshield-pill-<?php echo esc_attr( $e['severity'] ); ?>"><?php echo esc_html( $e['severity'] ); ?></span> <?php echo esc_html( $e['message'] ); ?> <span class="description"><?php echo esc_html( human_time_diff( strtotime( $e['created_at'] . ' UTC' ) ) ); ?> <?php esc_html_e( 'ago', 'anderson-site-shield' ); ?></span></li>
							<?php endforeach; ?>
						</ul>
						<p><a href="<?php echo esc_url( admin_url( 'admin.php?page=' . self::SLUG . '-log' ) ); ?>"><?php esc_html_e( 'Full activity log →', 'anderson-site-shield' ); ?></a></p>
					<?php endif; ?>
				</div>

				<div class="anshield-card">
					<h2><?php esc_html_e( 'Lockouts', 'anderson-site-shield' ); ?></h2>
					<?php if ( ! $locks ) : ?>
						<p class="description"><?php esc_html_e( 'No IPs are locked out.', 'anderson-site-shield' ); ?></p>
					<?php else : ?>
						<table class="widefat striped">
							<tbody>
							<?php foreach ( array_slice( $locks, 0, 15, true ) as $ip => $until ) : ?>
								<tr><td><code><?php echo esc_html( $ip ); ?></code></td><td><?php /* translators: %s: time */ printf( esc_html__( 'for %s', 'anderson-site-shield' ), esc_html( human_time_diff( $until ) ) ); ?></td>
									<td class="anshield-right"><?php $this->post_button( 'anshield_unlock', array( 'ip' => $ip ), __( 'Unlock', 'anderson-site-shield' ), 'button-small' ); ?></td></tr>
							<?php endforeach; ?>
							</tbody>
						</table>
						<p><?php $this->post_button( 'anshield_unlock', array( 'ip' => 'all' ), __( 'Unlock all', 'anderson-site-shield' ), 'button-small' ); ?></p>
					<?php endif; ?>
					<p class="description">
						<?php
						/* translators: %s: IP */
						printf( esc_html__( 'Your IP right now: %s', 'anderson-site-shield' ), '<code>' . esc_html( Request::ip() ) . '</code>' );
						?>
					</p>
				</div>

				<div class="anshield-card">
					<h2><?php esc_html_e( 'File integrity', 'anderson-site-shield' ); ?></h2>
					<?php $this->fim_summary( $last ); ?>
				</div>
			</div>
		</div>
		</div>
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
			echo '<p>' . esc_html( sprintf( __( 'Scan running: %1$d of %2$d steps done.', 'anderson-site-shield' ), $state['done'], $state['total'] ) ) . '</p>';
			return;
		}
		if ( ! $last ) {
			echo '<p class="description">' . esc_html__( 'No scan yet.', 'anderson-site-shield' ) . '</p>';
			$this->post_button( 'anshield_scan', array(), __( 'Scan now', 'anderson-site-shield' ), 'button-primary' );
			return;
		}
		$open = array_filter(
			$last['findings'],
			static function ( $f ) {
				return 'info' !== $f['severity'] && ! File_Integrity::is_acknowledged( $f );
			}
		);
		/* translators: %s: time */
		echo '<p>' . esc_html( sprintf( __( 'Last scan %s ago.', 'anderson-site-shield' ), human_time_diff( $last['finished'] ) ) ) . ' ';
		if ( $open ) {
			/* translators: %d: count */
			echo '<strong class="anshield-sev-critical">' . esc_html( sprintf( _n( '%d file needs review.', '%d files need review.', count( $open ), 'anderson-site-shield' ), count( $open ) ) ) . '</strong>';
		} else {
			echo esc_html__( 'Nothing needs review.', 'anderson-site-shield' );
		}
		echo '</p><p><a href="' . esc_url( admin_url( 'admin.php?page=' . self::SLUG . '-files' ) ) . '">' . esc_html__( 'See results →', 'anderson-site-shield' ) . '</a></p>';
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
			''        => __( 'All events', 'anderson-site-shield' ),
			'auth.'   => __( 'Logins', 'anderson-site-shield' ),
			'2fa.'    => __( 'Two-factor', 'anderson-site-shield' ),
			'user.'   => __( 'Users', 'anderson-site-shield' ),
			'plugin.' => __( 'Plugins', 'anderson-site-shield' ),
			'theme.'  => __( 'Themes', 'anderson-site-shield' ),
			'option.' => __( 'Settings', 'anderson-site-shield' ),
			'fim.'    => __( 'File integrity', 'anderson-site-shield' ),
			'harden.' => __( 'Blocked probes', 'anderson-site-shield' ),
		);

		$this->header( __( 'Activity log', 'anderson-site-shield' ) );
		?>
		<form method="get" class="anshield-filters">
			<input type="hidden" name="page" value="<?php echo esc_attr( self::SLUG . '-log' ); ?>" />
			<label class="screen-reader-text" for="anshield-sev"><?php esc_html_e( 'Minimum severity', 'anderson-site-shield' ); ?></label>
			<select name="severity" id="anshield-sev">
				<option value=""><?php esc_html_e( 'Any severity', 'anderson-site-shield' ); ?></option>
				<?php foreach ( array( 'notice', 'warning', 'critical' ) as $sev ) : ?>
					<?php /* translators: %s: severity */ ?>
					<option value="<?php echo esc_attr( $sev ); ?>" <?php selected( $severity, $sev ); ?>><?php echo esc_html( sprintf( __( '%s and above', 'anderson-site-shield' ), ucfirst( $sev ) ) ); ?></option>
				<?php endforeach; ?>
			</select>
			<label class="screen-reader-text" for="anshield-type"><?php esc_html_e( 'Event type', 'anderson-site-shield' ); ?></label>
			<select name="type" id="anshield-type">
				<?php foreach ( $types as $value => $label ) : ?>
					<option value="<?php echo esc_attr( $value ); ?>" <?php selected( $type, $value ); ?>><?php echo esc_html( $label ); ?></option>
				<?php endforeach; ?>
			</select>
			<label class="screen-reader-text" for="anshield-s"><?php esc_html_e( 'Search', 'anderson-site-shield' ); ?></label>
			<input type="search" id="anshield-s" name="s" value="<?php echo esc_attr( $search ); ?>" placeholder="<?php esc_attr_e( 'User, IP or text', 'anderson-site-shield' ); ?>" />
			<button class="button"><?php esc_html_e( 'Filter', 'anderson-site-shield' ); ?></button>
			<a class="button" href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=anshield_export&severity=' . rawurlencode( $severity ) . '&type=' . rawurlencode( $type ) . '&s=' . rawurlencode( $search ) ), 'anshield_export' ) ); ?>"><?php esc_html_e( 'Export CSV', 'anderson-site-shield' ); ?></a>
			<span class="anshield-count">
				<?php
				/* translators: %s: count */
				echo esc_html( sprintf( _n( '%s event', '%s events', $result['total'], 'anderson-site-shield' ), number_format_i18n( $result['total'] ) ) );
				?>
			</span>
		</form>

		<table class="widefat striped anshield-log">
			<thead><tr>
				<th scope="col"><?php esc_html_e( 'When', 'anderson-site-shield' ); ?></th>
				<th scope="col"><?php esc_html_e( 'Severity', 'anderson-site-shield' ); ?></th>
				<th scope="col"><?php esc_html_e( 'Event', 'anderson-site-shield' ); ?></th>
				<th scope="col"><?php esc_html_e( 'User', 'anderson-site-shield' ); ?></th>
				<th scope="col"><?php esc_html_e( 'IP', 'anderson-site-shield' ); ?></th>
			</tr></thead>
			<tbody>
			<?php if ( ! $result['rows'] ) : ?>
				<tr><td colspan="5"><?php esc_html_e( 'No events match.', 'anderson-site-shield' ); ?></td></tr>
			<?php endif; ?>
			<?php foreach ( $result['rows'] as $e ) : ?>
				<tr>
					<td class="anshield-nowrap" title="<?php echo esc_attr( $e['created_at'] . ' UTC' ); ?>"><?php echo esc_html( get_date_from_gmt( $e['created_at'], 'M j, H:i:s' ) ); ?></td>
					<td><span class="anshield-pill anshield-pill-<?php echo esc_attr( $e['severity'] ); ?>"><?php echo esc_html( $e['severity'] ); ?></span></td>
					<td><?php echo esc_html( $e['message'] ); ?><br /><code class="anshield-type"><?php echo esc_html( $e['event_type'] ); ?></code></td>
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
			echo esc_html( sprintf( __( 'Events are kept for %d days.', 'anderson-site-shield' ), Settings::get( 'log_retention_days' ) ) );
			?>
		</p>
		</div>
		<?php
	}

	/**
	 * File integrity.
	 */
	public function page_files() {
		$last  = File_Integrity::last();
		$state = File_Integrity::state();
		$this->header( __( 'File integrity', 'anderson-site-shield' ) );
		?>
		<div class="anshield-card">
			<p><?php esc_html_e( 'Compares WordPress core and WordPress.org plugins with their official checksums, and looks for PHP files where they don\'t belong. Runs daily.', 'anderson-site-shield' ); ?></p>
			<?php if ( 'running' === $state['status'] ) : ?>
				<?php /* translators: 1: done, 2: total */ ?>
				<p><strong><?php echo esc_html( sprintf( __( 'Scan running: %1$d of %2$d steps done. Reload to see progress.', 'anderson-site-shield' ), $state['done'], $state['total'] ) ); ?></strong></p>
			<?php else : ?>
				<?php $this->post_button( 'anshield_scan', array(), __( 'Scan now', 'anderson-site-shield' ), 'button-primary' ); ?>
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
				echo esc_html( sprintf( __( 'Results from %s ago', 'anderson-site-shield' ), human_time_diff( $last['finished'] ) ) );
				?>
			</h2>
			<?php if ( ! $open ) : ?>
				<div class="notice notice-success inline"><p><?php esc_html_e( 'No files need review.', 'anderson-site-shield' ); ?></p></div>
			<?php else : ?>
				<p><?php esc_html_e( 'Check each file. If it is yours and expected, accept it; it will be reported again only if it changes. If you don\'t recognise it, inspect it with Anderson Shell Scanner or restore the original.', 'anderson-site-shield' ); ?></p>
				<?php $this->findings_table( $open, true ); ?>
				<p><?php $this->post_button( 'anshield_ack_all', array(), __( 'Accept all of these', 'anderson-site-shield' ), 'button-link-delete' ); ?> <span class="description"><?php esc_html_e( 'Only after checking them, for example after a theme you built was edited.', 'anderson-site-shield' ); ?></span></p>
			<?php endif; ?>

			<?php if ( $info ) : ?>
				<details class="anshield-details"><summary><?php /* translators: %d: count */ echo esc_html( sprintf( _n( '%d informational item', '%d informational items', count( $info ), 'anderson-site-shield' ), count( $info ) ) ); ?></summary>
					<?php $this->findings_table( $info, false ); ?>
				</details>
			<?php endif; ?>
			<?php if ( $ack ) : ?>
				<details class="anshield-details"><summary><?php /* translators: %d: count */ echo esc_html( sprintf( _n( '%d accepted file', '%d accepted files', count( $ack ), 'anderson-site-shield' ), count( $ack ) ) ); ?></summary>
					<?php $this->findings_table( $ack, false ); ?>
				</details>
			<?php endif; ?>
			<?php if ( ! empty( $last['notes'] ) ) : ?>
				<details class="anshield-details"><summary><?php esc_html_e( 'Scan notes', 'anderson-site-shield' ); ?></summary>
					<ul><?php foreach ( $last['notes'] as $target => $note ) : ?><li><code><?php echo esc_html( $target ); ?></code> — <?php echo esc_html( $note ); ?></li><?php endforeach; ?></ul>
				</details>
			<?php endif; ?>
		<?php endif; ?>
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
		<table class="widefat striped">
			<thead><tr>
				<th scope="col"><?php esc_html_e( 'Severity', 'anderson-site-shield' ); ?></th>
				<th scope="col"><?php esc_html_e( 'File', 'anderson-site-shield' ); ?></th>
				<th scope="col"><?php esc_html_e( 'Issue', 'anderson-site-shield' ); ?></th>
				<th scope="col"><?php esc_html_e( 'Modified', 'anderson-site-shield' ); ?></th>
				<?php if ( $actions ) : ?><th scope="col"><span class="screen-reader-text"><?php esc_html_e( 'Actions', 'anderson-site-shield' ); ?></span></th><?php endif; ?>
			</tr></thead>
			<tbody>
			<?php foreach ( array_slice( $findings, 0, 500 ) as $f ) : ?>
				<tr>
					<td><span class="anshield-pill anshield-pill-<?php echo esc_attr( $f['severity'] ); ?>"><?php echo esc_html( $f['severity'] ); ?></span></td>
					<td><code><?php echo esc_html( $f['path'] ); ?></code><?php echo $f['detail'] ? '<br /><span class="description">' . esc_html( $f['detail'] ) . '</span>' : ''; ?></td>
					<td><?php echo esc_html( File_Integrity::kind_label( $f['kind'], true ) ); ?></td>
					<td class="anshield-nowrap"><?php echo $f['mtime'] ? esc_html( wp_date( 'M j Y, H:i', $f['mtime'] ) ) : '&mdash;'; ?></td>
					<?php if ( $actions ) : ?>
						<td class="anshield-right"><?php $this->post_button( 'anshield_ack', array( 'path' => $f['path'] ), __( 'Accept', 'anderson-site-shield' ), 'button-small' ); ?></td>
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
		$this->header( __( 'Site Shield settings', 'anderson-site-shield' ) );
		?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="anshield-settings">
			<input type="hidden" name="action" value="anshield_save" />
			<?php wp_nonce_field( 'anshield_save' ); ?>

			<div class="anshield-card">
				<h2><?php esc_html_e( 'Login protection', 'anderson-site-shield' ); ?></h2>
				<table class="form-table" role="presentation">
					<?php $this->toggle( 'login_protection', __( 'Lock out IPs after failed logins', 'anderson-site-shield' ) ); ?>
					<tr><th scope="row"><?php esc_html_e( 'Limits', 'anderson-site-shield' ); ?></th><td class="anshield-inline-fields">
						<?php
						printf(
							/* translators: 1: attempts input, 2: window input, 3: lockout input */
							esc_html__( 'After %1$s failures in %2$s minutes, lock out for %3$s minutes.', 'anderson-site-shield' ),
							$this->number( 'login_max_attempts' ), // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
							$this->number( 'login_window_minutes' ), // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
							$this->number( 'login_lockout_minutes' ) // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
						);
						echo '<br />';
						printf(
							/* translators: 1: count input, 2: hours input */
							esc_html__( 'After %1$s lockouts, lock out for %2$s hours.', 'anderson-site-shield' ),
							$this->number( 'login_long_lockouts' ), // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
							$this->number( 'login_long_hours' ) // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
						);
						?>
					</td></tr>
					<?php $this->toggle( 'login_generic_errors', __( 'Don\'t reveal whether a username exists', 'anderson-site-shield' ), __( 'Login and password-reset forms give the same answer either way.', 'anderson-site-shield' ) ); ?>
					<tr><th scope="row"><label for="login_allowlist"><?php esc_html_e( 'Never lock out', 'anderson-site-shield' ); ?></label></th><td>
						<textarea name="login_allowlist" id="login_allowlist" rows="3" class="large-text code" placeholder="203.0.113.10&#10;198.51.100.0/24"><?php echo esc_textarea( $s['login_allowlist'] ); ?></textarea>
						<?php /* translators: %s: IP */ ?>
						<p class="description"><?php echo wp_kses( sprintf( __( 'One IP or CIDR range per line, such as your office. Your IP right now: %s', 'anderson-site-shield' ), '<code>' . esc_html( Request::ip() ) . '</code>' ), array( 'code' => array() ) ); ?></p>
					</td></tr>
					<?php $this->toggle( 'custom_login_enabled', __( 'Move the login page', 'anderson-site-shield' ), __( 'wp-login.php and /wp-admin return "Not Found" to logged-out visitors. Bookmark the new address before saving. Login links your theme shows to logged-out visitors (such as "Log in to reply") will also return "Not Found".', 'anderson-site-shield' ), is_multisite() ); ?>
					<tr><th scope="row"><label for="custom_login_slug"><?php esc_html_e( 'Login address', 'anderson-site-shield' ); ?></label></th><td>
						<code><?php echo esc_html( trailingslashit( home_url() ) ); ?></code><input type="text" name="custom_login_slug" id="custom_login_slug" value="<?php echo esc_attr( $s['custom_login_slug'] ); ?>" class="regular-text" placeholder="<?php echo esc_attr( 'team-' . strtolower( wp_generate_password( 6, false ) ) ); ?>" />
						<p class="description"><?php esc_html_e( 'Locked out? Add define( \'ANSHIELD_SAFE_MODE\', true ); to wp-config.php, or run: wp site-shield login-url', 'anderson-site-shield' ); ?></p>
					</td></tr>
				</table>
			</div>

			<div class="anshield-card">
				<h2><?php esc_html_e( 'Two-factor authentication', 'anderson-site-shield' ); ?></h2>
				<table class="form-table" role="presentation">
					<?php $this->toggle( 'twofa_enabled', __( 'Allow two-factor with an authenticator app', 'anderson-site-shield' ) ); ?>
					<tr><th scope="row"><?php esc_html_e( 'Required for', 'anderson-site-shield' ); ?></th><td>
						<fieldset><legend class="screen-reader-text"><?php esc_html_e( 'Roles that must use two-factor', 'anderson-site-shield' ); ?></legend>
						<?php foreach ( $roles as $role => $name ) : ?>
							<label class="anshield-check"><input type="checkbox" name="twofa_required_roles[]" value="<?php echo esc_attr( $role ); ?>" <?php checked( in_array( $role, (array) $s['twofa_required_roles'], true ) ); ?> /> <?php echo esc_html( translate_user_role( $name ) ); ?></label>
						<?php endforeach; ?>
						</fieldset>
						<p class="description"><?php esc_html_e( 'People in these roles must set up two-factor before they can use the dashboard.', 'anderson-site-shield' ); ?></p>
					</td></tr>
					<?php $this->toggle( 'twofa_block_xmlrpc', __( 'Block password logins over XML-RPC for two-factor users', 'anderson-site-shield' ), __( 'Otherwise XML-RPC would skip the second step. Apps can use application passwords.', 'anderson-site-shield' ) ); ?>
				</table>
			</div>

			<div class="anshield-card">
				<h2><?php esc_html_e( 'Hardening', 'anderson-site-shield' ); ?></h2>
				<table class="form-table" role="presentation">
					<?php $this->toggle( 'harden_xmlrpc', __( 'Block XML-RPC', 'anderson-site-shield' ), Hardening::xmlrpc_needed() ? __( 'Jetpack is active and needs XML-RPC, so it stays on.', 'anderson-site-shield' ) : __( 'Stops brute force and pingback abuse through xmlrpc.php.', 'anderson-site-shield' ) ); ?>
					<?php $this->toggle( 'harden_user_enum', __( 'Block username scanning', 'anderson-site-shield' ) ); ?>
					<?php $this->toggle( 'harden_file_edit', __( 'Turn off the theme and plugin file editor', 'anderson-site-shield' ), defined( 'DISALLOW_FILE_EDIT' ) && ! $s['harden_file_edit'] ? __( 'Already set in wp-config.php.', 'anderson-site-shield' ) : '' ); ?>
					<?php $this->toggle( 'harden_uploads_php', __( 'Block PHP in the uploads folder', 'anderson-site-shield' ), __( 'Writes an .htaccess rule (Apache and LiteSpeed). On nginx-only hosts, ask the host to add the equivalent rule.', 'anderson-site-shield' ) ); ?>
					<tr><th scope="row"></th><td>
						<?php
						$test = get_option( 'anshield_uploads_test' );
						if ( $test ) {
							$labels = array(
								'blocked'  => __( 'Last test: PHP is blocked in uploads.', 'anderson-site-shield' ),
								'executes' => __( 'Last test: PHP still runs in uploads!', 'anderson-site-shield' ),
								'unknown'  => __( 'Last test could not reach the site.', 'anderson-site-shield' ),
							);
							echo '<p class="' . ( 'executes' === $test ? 'anshield-sev-critical' : 'description' ) . '">' . esc_html( $labels[ $test ] ) . '</p>';
						}
						?>
						<button type="submit" class="button" form="anshield-test-uploads"><?php esc_html_e( 'Test it now', 'anderson-site-shield' ); ?></button>
					</td></tr>
					<?php $this->toggle( 'harden_headers', __( 'Send security headers', 'anderson-site-shield' ) ); ?>
					<?php $this->toggle( 'harden_hsts', __( 'Send HSTS (force HTTPS in browsers for a year)', 'anderson-site-shield' ), __( 'Only turn on once the whole site works over HTTPS.', 'anderson-site-shield' ) ); ?>
					<?php $this->toggle( 'harden_hide_version', __( 'Hide the WordPress version', 'anderson-site-shield' ) ); ?>
					<?php $this->toggle( 'harden_app_passwords', __( 'Turn off application passwords', 'anderson-site-shield' ), __( 'Breaks the WordPress mobile app and integrations that use them.', 'anderson-site-shield' ) ); ?>
				</table>
			</div>

			<div class="anshield-card">
				<h2><?php esc_html_e( 'Monitoring and alerts', 'anderson-site-shield' ); ?></h2>
				<table class="form-table" role="presentation">
					<?php $this->toggle( 'log_enabled', __( 'Keep an activity log', 'anderson-site-shield' ) ); ?>
					<tr><th scope="row"><label for="log_retention_days"><?php esc_html_e( 'Keep events for', 'anderson-site-shield' ); ?></label></th><td><?php echo $this->number( 'log_retention_days' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?> <?php esc_html_e( 'days', 'anderson-site-shield' ); ?></td></tr>
					<tr><th scope="row"><label for="alert_emails"><?php esc_html_e( 'Email alerts to', 'anderson-site-shield' ); ?></label></th><td>
						<input type="text" name="alert_emails" id="alert_emails" class="large-text" value="<?php echo esc_attr( $s['alert_emails'] ); ?>" placeholder="<?php echo esc_attr( get_option( 'admin_email' ) ); ?>" />
						<p class="description"><?php esc_html_e( 'Comma-separated. Empty sends to the site admin email. At most 10 alerts an hour.', 'anderson-site-shield' ); ?></p>
					</td></tr>
					<tr><th scope="row"><label for="alert_min_severity"><?php esc_html_e( 'Alert on', 'anderson-site-shield' ); ?></label></th><td>
						<select name="alert_min_severity" id="alert_min_severity">
							<option value="critical" <?php selected( $s['alert_min_severity'], 'critical' ); ?>><?php esc_html_e( 'Critical events only', 'anderson-site-shield' ); ?></option>
							<option value="warning" <?php selected( $s['alert_min_severity'], 'warning' ); ?>><?php esc_html_e( 'Warnings and critical events', 'anderson-site-shield' ); ?></option>
						</select>
					</td></tr>
					<?php $this->toggle( 'fim_enabled', __( 'Daily file integrity scan', 'anderson-site-shield' ) ); ?>
					<?php $this->toggle( 'fim_plugins', __( 'Include WordPress.org plugins', 'anderson-site-shield' ) ); ?>
				</table>
			</div>

			<div class="anshield-card">
				<h2><?php esc_html_e( 'Network', 'anderson-site-shield' ); ?></h2>
				<table class="form-table" role="presentation">
					<tr><th scope="row"><label for="ip_source"><?php esc_html_e( 'Visitor IP comes from', 'anderson-site-shield' ); ?></label></th><td>
						<select name="ip_source" id="ip_source">
							<?php foreach ( Request::ip_sources() as $key => $label ) : ?>
								<option value="<?php echo esc_attr( $key ); ?>" <?php selected( $s['ip_source'], $key ); ?>><?php echo esc_html( $label ); ?></option>
							<?php endforeach; ?>
						</select>
						<p class="description"><?php esc_html_e( 'Only change this if the site is behind Cloudflare or a proxy and every visitor shows the same IP. The header is only believed when the request really comes from Cloudflare, a private network, or a trusted proxy below.', 'anderson-site-shield' ); ?></p>
					</td></tr>
					<tr><th scope="row"><label for="trusted_proxies"><?php esc_html_e( 'Trusted proxies', 'anderson-site-shield' ); ?></label></th><td>
						<textarea name="trusted_proxies" id="trusted_proxies" rows="2" class="large-text code" placeholder="203.0.113.0/24"><?php echo esc_textarea( $s['trusted_proxies'] ); ?></textarea>
						<p class="description"><?php esc_html_e( 'Public IPs or ranges of your own load balancer or proxy (Sucuri, a CDN). Leave empty for Cloudflare or a proxy on the same server.', 'anderson-site-shield' ); ?></p>
					</td></tr>
				</table>
			</div>

			<?php submit_button( __( 'Save settings', 'anderson-site-shield' ) ); ?>
		</form>
		<form id="anshield-test-uploads" method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<input type="hidden" name="action" value="anshield_test_uploads" />
			<?php wp_nonce_field( 'anshield_test_uploads' ); ?>
		</form>
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
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" class="anshield-inline">';
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
			wp_die( esc_html__( 'You are not allowed to do that.', 'anderson-site-shield' ), 403 );
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
			'anshield_msg' => rawurlencode( $msg ),
		);
		if ( $error ) {
			$args['anshield_err'] = 1;
		}
		wp_safe_redirect( add_query_arg( $args, admin_url( 'admin.php' ) ) );
		exit;
	}

	/**
	 * Save settings.
	 */
	public function save_settings() {
		$this->guard( 'anshield_save' );
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
			delete_option( 'anshield_uploads_test' );
		}

		$msg = __( 'Settings saved.', 'anderson-site-shield' );
		if ( in_array( 'custom_login_slug', $result, true ) || in_array( 'custom_login_enabled', $result, true ) ) {
			if ( Settings::get( 'custom_login_enabled' ) ) {
				/* translators: %s: URL */
				$msg .= ' ' . sprintf( __( 'Your login page is now %s — bookmark it.', 'anderson-site-shield' ), Login_Url::url() );
				Event_Log::log( 'shield.login_url_changed', 'warning', __( 'The login address was changed.', 'anderson-site-shield' ) );
			}
		}
		$this->back( '-settings', $msg );
	}

	/**
	 * Unlock an IP.
	 */
	public function unlock() {
		$this->guard( 'anshield_unlock' );
		$ip = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( 'all' !== $ip && ! Request::is_valid_ip_or_cidr( $ip ) ) {
			$this->back( '', __( 'Not a valid IP.', 'anderson-site-shield' ), true );
		}
		$n = Login_Protection::unlock( $ip );
		/* translators: %d: count */
		$this->back( '', sprintf( _n( '%d lockout lifted.', '%d lockouts lifted.', $n, 'anderson-site-shield' ), $n ) );
	}

	/**
	 * Start a scan and run the first part now.
	 */
	public function run_scan() {
		$this->guard( 'anshield_scan' );
		$fim = Plugin::instance()->module( 'fim' );
		$fim->start_scan( 'manual' );
		$fim->tick( 15 );
		$state = File_Integrity::state();
		$msg   = 'running' === $state['status']
			? __( 'Scan started. It continues in the background; reload in a minute.', 'anderson-site-shield' )
			: __( 'Scan finished.', 'anderson-site-shield' );
		$this->back( '-files', $msg );
	}

	/**
	 * Accept a finding.
	 */
	public function acknowledge() {
		$this->guard( 'anshield_ack' );
		$path = isset( $_POST['path'] ) ? wp_unslash( $_POST['path'] ) : ''; // phpcs:ignore WordPress.Security
		$ok   = File_Integrity::acknowledge( (string) $path );
		$this->back( '-files', $ok ? __( 'Accepted. It will be reported again if the file changes.', 'anderson-site-shield' ) : __( 'That finding was not found.', 'anderson-site-shield' ), ! $ok );
	}

	/**
	 * Accept every open finding.
	 */
	public function acknowledge_all() {
		$this->guard( 'anshield_ack_all' );
		$n = File_Integrity::acknowledge_all();
		/* translators: %d: count */
		$this->back( '-files', sprintf( _n( '%d finding accepted.', '%d findings accepted.', $n, 'anderson-site-shield' ), $n ) );
	}

	/**
	 * Test PHP execution in uploads.
	 */
	public function test_uploads() {
		$this->guard( 'anshield_test_uploads' );
		$result = Hardening::test_uploads_php();
		update_option( 'anshield_uploads_test', $result, false );
		if ( 'executes' === $result ) {
			Event_Log::log( 'harden.uploads_php_executes', 'warning', __( 'Test showed PHP files can run from the uploads folder.', 'anderson-site-shield' ) );
		}
		$msgs = array(
			'blocked'  => __( 'PHP is blocked in uploads.', 'anderson-site-shield' ),
			'executes' => __( 'PHP still runs in uploads. The server is probably ignoring .htaccess; ask your host to block PHP in wp-content/uploads.', 'anderson-site-shield' ),
			'unknown'  => __( 'The site could not reach itself to run the test (loopback request failed).', 'anderson-site-shield' ),
		);
		$this->back( '-settings', $msgs[ $result ], 'executes' === $result );
	}

	/**
	 * Download the filtered log as CSV.
	 */
	public function export_csv() {
		if ( ! current_user_can( self::CAP ) ) {
			wp_die( esc_html__( 'You are not allowed to do that.', 'anderson-site-shield' ), 403 );
		}
		check_admin_referer( 'anshield_export' );
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
		header( 'Content-Disposition: attachment; filename="site-shield-log-' . gmdate( 'Y-m-d' ) . '.csv"' );
		$out = fopen( 'php://output', 'w' ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		fputcsv( $out, array( 'time_utc', 'severity', 'event', 'message', 'user', 'ip', 'user_agent', 'object_type', 'object_id', 'context' ) );
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
				fputcsv( $out, $line );
			}
			if ( count( $rows ) < 500 ) {
				break;
			}
		}
		fclose( $out ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		exit;
	}
}
