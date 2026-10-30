<?php
/**
 * Login protection: failed-login lockouts and generic error messages.
 *
 * @package JATSiteShield
 */

namespace JATSiteShield\Modules;

use JATSiteShield\Event_Log;
use JATSiteShield\Request;
use JATSiteShield\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Counts failed logins per IP and locks the IP out after too many.
 * Repeat offenders get a long lockout.
 */
class Login_Protection {

	const LOCKOUTS_OPTION = 'jatss_lockouts';

	/**
	 * The real failure reason before generic_error() hid it.
	 *
	 * @var string
	 */
	private $original_reason = '';

	/**
	 * Hook in.
	 */
	public function register() {
		if ( ! Settings::get( 'login_protection' ) ) {
			return;
		}
		add_filter( 'authenticate', array( $this, 'skip_password_check' ), 1, 1 );
		add_filter( 'authenticate', array( $this, 'enforce_lockout' ), 99, 1 );
		add_action( 'wp_login_failed', array( $this, 'record_failure' ), 10, 2 );
		add_action( 'wp_login', array( $this, 'clear_failures' ), 10, 0 );

		if ( Settings::get( 'login_generic_errors' ) ) {
			add_filter( 'authenticate', array( $this, 'generic_error' ), 100, 1 );
			add_action( 'login_form_lostpassword', array( $this, 'hide_unknown_reset_user' ) );
		}
	}

	/**
	 * Whether lockouts are active for this request.
	 *
	 * @return bool
	 */
	private function active() {
		return ! JATSS_SAFE_MODE && ! Request::is_allowlisted();
	}

	/**
	 * Transient key for an IP.
	 *
	 * @param string $ip IP.
	 * @return string
	 */
	private static function key( $ip ) {
		return 'jatss_lp_' . md5( Request::bucket( $ip ) );
	}

	/**
	 * State for an IP.
	 *
	 * @param string $ip IP.
	 * @return array fails (timestamps), locked_until, lockouts (timestamps).
	 */
	private static function state( $ip ) {
		$state = get_transient( self::key( $ip ) );
		return wp_parse_args(
			is_array( $state ) ? $state : array(),
			array(
				'fails'        => array(),
				'locked_until' => 0,
				'lockouts'     => array(),
			)
		);
	}

	/**
	 * Save state for an IP.
	 *
	 * @param string $ip    IP.
	 * @param array  $state State.
	 */
	private static function save_state( $ip, array $state ) {
		$ttl = max( (int) Settings::get( 'login_long_hours' ) * HOUR_IN_SECONDS, (int) $state['locked_until'] - time() );
		set_transient( self::key( $ip ), $state, max( HOUR_IN_SECONDS, $ttl ) );
	}

	/**
	 * Seconds an IP remains locked out (0 if not locked).
	 *
	 * @param string $ip IP.
	 * @return int
	 */
	public static function remaining_lockout( $ip ) {
		$state = self::state( $ip );
		return max( 0, (int) $state['locked_until'] - time() );
	}

	/**
	 * While locked out, don't spend CPU hashing passwords at all.
	 *
	 * @param mixed $user Result so far.
	 * @return mixed
	 */
	public function skip_password_check( $user ) {
		if ( $this->active() && self::remaining_lockout( Request::ip() ) > 0 ) {
			remove_filter( 'authenticate', 'wp_authenticate_username_password', 20 );
			remove_filter( 'authenticate', 'wp_authenticate_email_password', 20 );
		}
		return $user;
	}

	/**
	 * Block authentication while the IP is locked out, even with a correct password.
	 *
	 * @param \WP_User|\WP_Error|null $user Result so far.
	 * @return \WP_User|\WP_Error|null
	 */
	public function enforce_lockout( $user ) {
		if ( ! $this->active() ) {
			return $user;
		}
		$remaining = self::remaining_lockout( Request::ip() );
		if ( $remaining > 0 ) {
			return new \WP_Error(
				'jatss_locked',
				sprintf(
					/* translators: %d: minutes */
					__( '<strong>Error:</strong> Too many failed login attempts. Try again in %d minutes.', 'jat-site-shield' ),
					max( 1, (int) ceil( $remaining / 60 ) )
				)
			);
		}
		return $user;
	}

	/**
	 * Count a failed login and lock out the IP when it crosses the limit.
	 *
	 * @param string         $username Attempted username.
	 * @param \WP_Error|null $error    Why it failed.
	 */
	public function record_failure( $username, $error = null ) {
		if ( $error instanceof \WP_Error && $error->get_error_code() === 'jatss_locked' ) {
			return;
		}
		if ( ! $this->active() ) {
			return;
		}

		$ip     = Request::ip();
		$now    = time();
		$window = (int) Settings::get( 'login_window_minutes' ) * MINUTE_IN_SECONDS;
		$state  = self::state( $ip );

		$state['fails']   = array_values( array_filter( $state['fails'], static function ( $t ) use ( $now, $window ) {
			return $t > $now - $window;
		} ) );
		$state['fails'][] = $now;

		$is_2fa = $error instanceof \WP_Error && 'jatss_2fa_failed' === $error->get_error_code();
		if ( ! $is_2fa ) { // Two-factor failures are already logged as 2fa.failed.
			Event_Log::log(
				'auth.login_failed',
				'info',
				sprintf(
					/* translators: %s: username */
					__( 'Failed login for "%s".', 'jat-site-shield' ),
					$username
				),
				array(
					'user_id'  => 0,
					'username' => $username,
					'context'  => array(
						'reason'   => '' !== $this->original_reason ? $this->original_reason : ( $error instanceof \WP_Error ? $error->get_error_code() : 'unknown' ),
						'attempts' => count( $state['fails'] ),
						'xmlrpc'   => defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST,
					),
				)
			);
		}

		self::track_username( $username );

		if ( count( $state['fails'] ) >= (int) Settings::get( 'login_max_attempts' ) ) {
			$long_window       = (int) Settings::get( 'login_long_hours' ) * HOUR_IN_SECONDS;
			$state['lockouts'] = array_values( array_filter( $state['lockouts'], static function ( $t ) use ( $now, $long_window ) {
				return $t > $now - $long_window;
			} ) );
			$state['lockouts'][] = $now;
			$is_long             = count( $state['lockouts'] ) >= (int) Settings::get( 'login_long_lockouts' );
			$duration            = $is_long ? $long_window : (int) Settings::get( 'login_lockout_minutes' ) * MINUTE_IN_SECONDS;

			$state['locked_until'] = $now + $duration;
			$state['fails']        = array();
			self::remember_lockout( Request::bucket( $ip ), $state['locked_until'] );

			Event_Log::log(
				$is_long ? 'auth.lockout_long' : 'auth.lockout',
				'warning',
				sprintf(
					/* translators: 1: IP, 2: minutes */
					__( 'Locked out %1$s for %2$d minutes after repeated failed logins.', 'jat-site-shield' ),
					$ip,
					(int) round( $duration / 60 )
				),
				array(
					'user_id'     => 0,
					'username'    => $username,
					'object_type' => 'ip',
					'object_id'   => $ip,
					'context'     => array( 'long' => $is_long ),
				)
			);
		}

		self::save_state( $ip, $state );
	}

	/**
	 * Count failures per username across all IPs. A spike means a distributed
	 * attack that per-IP lockouts can't stop; it is reported once an hour.
	 * The account itself is not locked, so attackers can't lock out the owner.
	 *
	 * @param string $username Attempted username.
	 */
	private static function track_username( $username ) {
		$key   = 'jatss_uf_' . md5( strtolower( (string) $username ) );
		$count = (int) get_transient( $key ) + 1;
		set_transient( $key, $count, HOUR_IN_SECONDS );
		if ( 50 === $count && get_user_by( 'login', $username ) ) {
			Event_Log::log(
				'auth.distributed_attack',
				'warning',
				sprintf(
					/* translators: %s: username */
					__( '50 failed logins for "%s" from many IPs in the last hour. Make sure this account has a strong password and two-factor.', 'jat-site-shield' ),
					$username
				),
				array(
					'user_id'  => 0,
					'username' => $username,
				)
			);
		}
	}

	/**
	 * A successful login clears the IP's failure count.
	 */
	public function clear_failures() {
		$ip    = Request::ip();
		$state = self::state( $ip );
		if ( $state['fails'] ) {
			$state['fails'] = array();
			self::save_state( $ip, $state );
		}
	}

	/**
	 * Replace "unknown username" and "wrong password" with one message.
	 *
	 * @param \WP_User|\WP_Error|null $user Result so far.
	 * @return \WP_User|\WP_Error|null
	 */
	public function generic_error( $user ) {
		if ( ! $user instanceof \WP_Error ) {
			return $user;
		}
		$leaky = array( 'invalid_username', 'invalid_email', 'incorrect_password' );
		if ( array_intersect( $leaky, $user->get_error_codes() ) ) {
			$this->original_reason = $user->get_error_code();
			return new \WP_Error(
				'incorrect_password',
				sprintf(
					/* translators: %s: lost password URL */
					__( '<strong>Error:</strong> The username, email address or password is incorrect. <a href="%s">Lost your password?</a>', 'jat-site-shield' ),
					esc_url( wp_lostpassword_url() )
				)
			);
		}
		return $user;
	}

	/**
	 * On the lost-password form, answer the same way whether or not the
	 * account exists, so the form can't be used to find usernames.
	 */
	public function hide_unknown_reset_user() {
		if ( 'POST' !== ( isset( $_SERVER['REQUEST_METHOD'] ) ? $_SERVER['REQUEST_METHOD'] : '' ) || empty( $_POST['user_login'] ) || ! is_string( $_POST['user_login'] ) ) { // phpcs:ignore WordPress.Security
			return;
		}
		$login = trim( wp_unslash( $_POST['user_login'] ) ); // phpcs:ignore WordPress.Security
		$user  = get_user_by( 'login', $login );
		if ( ! $user && strpos( $login, '@' ) ) {
			$user = get_user_by( 'email', $login );
		}
		if ( $user ) {
			return;
		}
		Event_Log::log_throttled( 'auth.reset_unknown_user', 'info', __( 'Password reset requested for an unknown account.', 'jat-site-shield' ) );
		if ( $this->active() ) {
			$this->record_failure( $login, new \WP_Error( 'invalidcombo', 'Unknown account on lost password form.' ) );
		}

		// Redirect exactly as core does for a real account, so the two can't be told apart.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput
		$redirect_to = ! empty( $_REQUEST['redirect_to'] ) && is_string( $_REQUEST['redirect_to'] ) ? wp_unslash( $_REQUEST['redirect_to'] ) : 'wp-login.php?checkemail=confirm';
		/** This filter is documented in wp-login.php */
		$redirect_to = apply_filters( 'lostpassword_redirect', $redirect_to ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
		wp_safe_redirect( $redirect_to );
		exit;
	}

	/**
	 * Keep a short list of current lockouts for the admin screen.
	 *
	 * @param string $ip    IP.
	 * @param int    $until Unix time.
	 */
	private static function remember_lockout( $ip, $until ) {
		$list        = self::lockouts();
		$list[ $ip ] = (int) $until;
		arsort( $list );
		update_option( self::LOCKOUTS_OPTION, array_slice( $list, 0, 200, true ), false );
	}

	/**
	 * Current lockouts: ip => until.
	 *
	 * @return array
	 */
	public static function lockouts() {
		$list = get_option( self::LOCKOUTS_OPTION, array() );
		$now  = time();
		return array_filter( is_array( $list ) ? $list : array(), static function ( $until ) use ( $now ) {
			return (int) $until > $now;
		} );
	}

	/**
	 * Lift a lockout early.
	 *
	 * @param string $ip IP, or 'all'.
	 * @return int Lockouts cleared.
	 */
	public static function unlock( $ip ) {
		$list  = self::lockouts();
		$ips   = 'all' === $ip ? array_keys( $list ) : array( $ip );
		$count = 0;
		foreach ( $ips as $one ) {
			delete_transient( self::key( $one ) );
			if ( isset( $list[ $one ] ) ) {
				unset( $list[ $one ] );
				++$count;
			}
		}
		update_option( self::LOCKOUTS_OPTION, $list, false );
		if ( $count ) {
			Event_Log::log( 'auth.unlock', 'notice', sprintf( /* translators: %s: IP or "all" */ __( 'Login lockout lifted for %s.', 'jat-site-shield' ), $ip ) );
		}
		return $count;
	}
}
