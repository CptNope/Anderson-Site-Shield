<?php
/**
 * Two-factor authentication (TOTP + backup codes).
 *
 * @package AndersonSiteShield
 */

namespace AndersonSiteShield\Modules;

use AndersonSiteShield\Event_Log;
use AndersonSiteShield\Settings;
use AndersonSiteShield\Totp;
use AndersonSiteShield\Modules\Login_Protection;
use AndersonSiteShield\Modules\Login_Url;

defined( 'ABSPATH' ) || exit;

/**
 * Adds a second login step for enrolled users and makes required roles enroll.
 */
class Two_Factor {

	const META_SECRET  = 'anshield_totp_secret';
	const META_PENDING = 'anshield_totp_pending';
	const META_LAST    = 'anshield_totp_last_step';
	const META_BACKUP  = 'anshield_backup_codes';
	const META_LOGIN   = 'anshield_2fa_login';
	const META_FAILS   = 'anshield_2fa_fails';

	const SETUP_PAGE   = 'anderson-site-shield-2fa';
	const LOGIN_ACTION = 'anshield_2fa';
	const TOKEN_TTL    = 600;
	const MAX_ATTEMPTS = 5;
	const BACKUP_COUNT = 10;
	const USER_FAILS   = 10; // Wrong codes per user per hour, across all IPs.

	/**
	 * Hook in.
	 */
	public function register() {
		if ( ! Settings::get( 'twofa_enabled' ) ) {
			return;
		}

		add_action( 'admin_menu', array( $this, 'add_setup_page' ) );
		add_action( 'show_user_profile', array( $this, 'profile_section' ) );
		add_action( 'edit_user_profile', array( $this, 'profile_section' ) );
		add_action( 'edit_user_profile_update', array( $this, 'handle_admin_reset' ) );

		if ( ANSHIELD_SAFE_MODE ) {
			return;
		}

		// Late, so CAPTCHA and similar checks registered at normal priorities run first.
		add_filter( 'authenticate', array( $this, 'intercept_login' ), 9999, 3 );
		add_action( 'login_form_' . self::LOGIN_ACTION, array( $this, 'login_step' ) );
		add_action( 'admin_init', array( $this, 'enforce_enrollment' ), 1 );
		add_filter( 'rest_authentication_errors', array( $this, 'block_pending_rest' ), 101 ); // After core's cookie and nonce check.
		add_filter( 'wp_login_errors', array( $this, 'login_notice' ) );
		add_filter( 'attach_session_information', array( $this, 'mark_session' ), 10, 2 );
		add_action( 'init', array( $this, 'verify_session' ), 1 );
	}

	/**
	 * Set while login_step() is creating a session that passed two-factor.
	 *
	 * @var bool
	 */
	private $verified_login = false;

	/**
	 * Record on the session itself that it passed two-factor.
	 *
	 * @param array $info    Session data.
	 * @param int   $user_id User ID.
	 * @return array
	 */
	public function mark_session( $info, $user_id ) {
		if ( $this->verified_login ) {
			$info['anshield_2fa'] = time();
		}
		return $info;
	}

	/**
	 * Mark the current session as verified (after enrolling).
	 *
	 * @param int $user_id User ID.
	 */
	private static function mark_current_session( $user_id ) {
		$token = wp_get_session_token();
		if ( ! $token ) {
			return;
		}
		$manager = \WP_Session_Tokens::get_instance( $user_id );
		$session = $manager->get( $token );
		if ( is_array( $session ) ) {
			$session['anshield_2fa'] = time();
			$manager->update( $token, $session );
		}
	}

	/**
	 * End any logged-in session of an enrolled user that never passed
	 * two-factor: logins made by code that calls wp_set_auth_cookie()
	 * directly (social login, magic links, "log in as" tools) can't skip it.
	 */
	public function verify_session() {
		if ( ! is_user_logged_in() || did_action( 'application_password_did_authenticate' ) ) {
			return;
		}
		$user_id = get_current_user_id();
		if ( ! self::is_enrolled( $user_id ) ) {
			return;
		}
		$token = wp_get_session_token();
		if ( ! $token ) {
			return;
		}
		$manager = \WP_Session_Tokens::get_instance( $user_id );
		$session = $manager->get( $token );
		if ( is_array( $session ) && ! empty( $session['anshield_2fa'] ) ) {
			return;
		}

		$manager->destroy( $token );
		wp_clear_auth_cookie();
		wp_set_current_user( 0 );
		$user = get_userdata( $user_id );
		Event_Log::log(
			'2fa.session_rejected',
			'critical',
			sprintf( /* translators: %s: username */ __( 'Ended a session for %s that skipped two-factor (a login made outside the normal login form).', 'anderson-site-shield' ), $user ? $user->user_login : '#' . $user_id ),
			array( 'user_id' => $user_id )
		);
		if ( ! wp_doing_ajax() && ! wp_doing_cron() && ! ( defined( 'REST_REQUEST' ) && REST_REQUEST ) && ( is_admin() || 'GET' === ( isset( $_SERVER['REQUEST_METHOD'] ) ? $_SERVER['REQUEST_METHOD'] : '' ) ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
			wp_safe_redirect( self::login_page_url() );
			exit;
		}
	}

	/**
	 * Login page URL, honouring the custom login address even for logged-out
	 * requests that aren't on the login page (third-party login forms).
	 *
	 * @param array $args Query args.
	 * @return string
	 */
	public static function login_page_url( array $args = array() ) {
		if ( Login_Url::enabled() ) {
			return Login_Url::url( http_build_query( $args, '', '&' ) );
		}
		return add_query_arg( $args, site_url( 'wp-login.php', 'login' ) );
	}

	/**
	 * Per-user lock so parallel requests can't race the attempt counters or
	 * spend one code twice. add_option() is atomic (unique option name).
	 *
	 * @param int $user_id User ID.
	 * @return bool
	 */
	private static function lock( $user_id ) {
		$name = 'anshield_2fa_lock_' . (int) $user_id;
		if ( add_option( $name, time(), '', false ) ) {
			return true;
		}
		if ( (int) get_option( $name ) < time() - 15 ) {
			delete_option( $name );
			return add_option( $name, time(), '', false );
		}
		return false;
	}

	/**
	 * Release the per-user lock.
	 *
	 * @param int $user_id User ID.
	 */
	private static function unlock( $user_id ) {
		delete_option( 'anshield_2fa_lock_' . (int) $user_id );
	}

	/**
	 * Explain why the user is back on the login form.
	 *
	 * @param \WP_Error $errors Login messages.
	 * @return \WP_Error
	 */
	public function login_notice( $errors ) {
		if ( isset( $_GET['anshield_expired'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$errors->add( 'anshield_expired', __( 'Your two-factor step expired or had too many wrong codes. Sign in again.', 'anderson-site-shield' ), 'message' );
		}
		return $errors;
	}

	/**
	 * Wrong-code count for a user in the last hour.
	 *
	 * @param int  $user_id User ID.
	 * @param bool $add     Add one.
	 * @return int
	 */
	private static function user_failures( $user_id, $add = false ) {
		$state = get_user_meta( $user_id, self::META_FAILS, true );
		if ( ! is_array( $state ) || time() - (int) $state['since'] > HOUR_IN_SECONDS ) {
			$state = array(
				'since' => time(),
				'count' => 0,
			);
		}
		if ( $add ) {
			++$state['count'];
			update_user_meta( $user_id, self::META_FAILS, $state );
		}
		return (int) $state['count'];
	}

	/* ------------------------------------------------------------------ */
	/* State helpers                                                       */
	/* ------------------------------------------------------------------ */

	/**
	 * The user's decrypted secret, or false.
	 *
	 * @param int $user_id User ID.
	 * @return string|false
	 */
	public static function secret( $user_id ) {
		$stored = get_user_meta( $user_id, self::META_SECRET, true );
		return $stored ? Totp::decrypt( $stored ) : false;
	}

	/**
	 * Whether the user has 2FA turned on.
	 *
	 * @param int $user_id User ID.
	 * @return bool
	 */
	public static function is_enrolled( $user_id ) {
		return '' !== (string) get_user_meta( $user_id, self::META_SECRET, true );
	}

	/**
	 * Enrolled, but the secret can't be decrypted (the key file was lost or
	 * ANSHIELD_SECRET_KEY changed). Logins are refused until an admin resets it.
	 *
	 * @param int $user_id User ID.
	 * @return bool
	 */
	public static function is_broken( $user_id ) {
		return self::is_enrolled( $user_id ) && false === self::secret( $user_id );
	}

	/**
	 * Whether the user's role requires 2FA.
	 *
	 * @param \WP_User $user User.
	 * @return bool
	 */
	public static function is_required( $user ) {
		$roles = (array) Settings::get( 'twofa_required_roles' );
		return (bool) array_intersect( $roles, (array) $user->roles );
	}

	/**
	 * Remove a user's 2FA completely.
	 *
	 * @param int    $user_id User ID.
	 * @param string $why     Log reason.
	 */
	public static function reset( $user_id, $why ) {
		foreach ( array( self::META_SECRET, self::META_PENDING, self::META_LAST, self::META_BACKUP, self::META_LOGIN, self::META_FAILS ) as $key ) {
			delete_user_meta( $user_id, $key );
		}
		$user = get_userdata( $user_id );
		Event_Log::log(
			'2fa.reset',
			'warning',
			sprintf(
				/* translators: 1: username, 2: reason */
				__( 'Two-factor was reset for %1$s (%2$s).', 'anderson-site-shield' ),
				$user ? $user->user_login : '#' . $user_id,
				$why
			),
			array(
				'object_type' => 'user',
				'object_id'   => $user_id,
			)
		);
	}

	/**
	 * Make new backup codes. Returns the plain codes once; only hashes are stored.
	 *
	 * @param int $user_id User ID.
	 * @return string[]
	 */
	public static function new_backup_codes( $user_id ) {
		$plain  = array();
		$hashes = array();
		for ( $i = 0; $i < self::BACKUP_COUNT; $i++ ) {
			$raw      = strtolower( Totp::base32_encode( random_bytes( 5 ) ) );
			$code     = substr( $raw, 0, 4 ) . '-' . substr( $raw, 4, 4 );
			$plain[]  = $code;
			$hashes[] = wp_hash_password( $code );
		}
		update_user_meta( $user_id, self::META_BACKUP, $hashes );
		return $plain;
	}

	/**
	 * Check a TOTP or backup code, consuming it on success.
	 *
	 * @param int    $user_id User ID.
	 * @param string $input   Code typed.
	 * @return string|false 'totp' or 'backup' on success.
	 */
	public static function check_code( $user_id, $input ) {
		$input  = strtolower( trim( (string) $input ) );
		$secret = self::secret( $user_id );
		if ( false === $secret ) {
			return false;
		}

		if ( preg_match( '/^\d{3}\s?\d{3}$/', $input ) ) {
			$step = Totp::verify( $secret, $input, (int) get_user_meta( $user_id, self::META_LAST, true ) );
			if ( false !== $step ) {
				update_user_meta( $user_id, self::META_LAST, $step );
				if ( 0 === strpos( (string) get_user_meta( $user_id, self::META_SECRET, true ), 'v1:' ) && Totp::dedicated_key() ) {
					update_user_meta( $user_id, self::META_SECRET, Totp::encrypt( $secret ) );
				}
				return 'totp';
			}
			return false;
		}

		$input = preg_replace( '/[^a-z2-7]/', '', $input );
		if ( 8 !== strlen( $input ) ) {
			return false;
		}
		$input  = substr( $input, 0, 4 ) . '-' . substr( $input, 4 );
		$hashes = (array) get_user_meta( $user_id, self::META_BACKUP, true );
		foreach ( $hashes as $i => $hash ) {
			if ( wp_check_password( $input, $hash ) ) {
				unset( $hashes[ $i ] );
				update_user_meta( $user_id, self::META_BACKUP, array_values( $hashes ) );
				return 'backup';
			}
		}
		return false;
	}

	/* ------------------------------------------------------------------ */
	/* Login                                                               */
	/* ------------------------------------------------------------------ */

	/**
	 * After the password check, send enrolled users to the code step.
	 *
	 * @param \WP_User|\WP_Error|null $user     Result so far.
	 * @param string                  $username Username.
	 * @param string                  $password Password.
	 * @return \WP_User|\WP_Error|null
	 */
	public function intercept_login( $user, $username = '', $password = '' ) {
		if ( ! $user instanceof \WP_User || ! self::is_enrolled( $user->ID ) ) {
			return $user;
		}

		if ( self::is_broken( $user->ID ) ) {
			Event_Log::log_throttled( '2fa.key_missing', 'critical', sprintf( /* translators: %s: username */ __( 'Two-factor secret for %s cannot be decrypted (encryption key missing or changed). Login refused; reset two-factor for the user.', 'anderson-site-shield' ), $user->user_login ) );
			return new \WP_Error( 'anshield_2fa_broken', __( '<strong>Error:</strong> Two-factor for this account needs to be reset by an administrator.', 'anderson-site-shield' ) );
		}

		// Application passwords are separate, revocable credentials; let them through.
		if ( did_action( 'application_password_did_authenticate' ) ) {
			return $user;
		}

		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			if ( Settings::get( 'twofa_block_xmlrpc' ) ) {
				return new \WP_Error( 'anshield_2fa_xmlrpc', __( 'This account uses two-factor authentication and cannot sign in over XML-RPC. Use an application password.', 'anderson-site-shield' ) );
			}
			return $user;
		}

		if ( wp_doing_ajax() || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) {
			return new \WP_Error( 'anshield_2fa_required', __( 'Two-factor authentication is required. Sign in from the login page.', 'anderson-site-shield' ) );
		}

		// phpcs:disable WordPress.Security.NonceVerification.Missing
		$redirect = isset( $_REQUEST['redirect_to'] ) && is_string( $_REQUEST['redirect_to'] ) ? wp_unslash( $_REQUEST['redirect_to'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$remember = ! empty( $_POST['rememberme'] );
		$interim  = ! empty( $_REQUEST['interim-login'] );
		// phpcs:enable

		$token = wp_generate_password( 40, false );
		update_user_meta(
			$user->ID,
			self::META_LOGIN,
			array(
				'hash'     => wp_hash( $token ),
				'expires'  => time() + self::TOKEN_TTL,
				'attempts' => 0,
				'remember' => $remember,
				'interim'  => $interim,
				'redirect' => esc_url_raw( $redirect ),
			)
		);

		$args = array(
			'action' => self::LOGIN_ACTION,
			'uid'    => $user->ID,
			'token'  => $token,
		);
		if ( $interim ) {
			$args['interim-login'] = 1;
		}
		$url = self::login_page_url( $args );
		wp_safe_redirect( $url );
		exit;
	}

	/**
	 * Load and validate the pending login for this request.
	 *
	 * @param int    $uid   User ID.
	 * @param string $token Token.
	 * @return array|false
	 */
	private function pending_login( $uid, $token ) {
		$state = get_user_meta( $uid, self::META_LOGIN, true );
		if ( ! is_array( $state ) || empty( $state['hash'] ) || time() > (int) $state['expires'] ) {
			return false;
		}
		if ( ! hash_equals( $state['hash'], wp_hash( $token ) ) ) {
			return false;
		}
		return $state;
	}

	/**
	 * The code step on wp-login.php?action=anshield_2fa.
	 */
	public function login_step() {
		// phpcs:disable WordPress.Security.NonceVerification
		$uid   = isset( $_REQUEST['uid'] ) ? absint( $_REQUEST['uid'] ) : 0;
		$token = isset( $_REQUEST['token'] ) && is_string( $_REQUEST['token'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['token'] ) ) : '';
		// phpcs:enable

		$user  = $uid ? get_userdata( $uid ) : false;
		$state = $user ? $this->pending_login( $uid, $token ) : false;

		if ( ! $user || ! $state ) {
			wp_safe_redirect( add_query_arg( 'anshield_expired', '1', wp_login_url() ) );
			exit;
		}

		$error = '';
		$ip    = \AndersonSiteShield\Request::ip();
		if ( Settings::get( 'login_protection' ) && ! \AndersonSiteShield\Request::is_allowlisted() && Login_Protection::remaining_lockout( $ip ) > 0 ) {
			$this->render_login_step( $uid, $token, __( '<strong>Error:</strong> Too many failed login attempts from your network. Try again later.', 'anderson-site-shield' ), true );
			exit;
		}
		if ( self::user_failures( $uid ) >= self::USER_FAILS ) {
			$this->render_login_step( $uid, $token, __( '<strong>Error:</strong> Too many wrong codes for this account. Try again in an hour.', 'anderson-site-shield' ), true );
			exit;
		}
		if ( 'POST' === ( isset( $_SERVER['REQUEST_METHOD'] ) ? $_SERVER['REQUEST_METHOD'] : '' ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
			$code = isset( $_POST['anshield_code'] ) && is_string( $_POST['anshield_code'] ) ? sanitize_text_field( wp_unslash( $_POST['anshield_code'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing

			if ( ! self::lock( $uid ) ) {
				$this->render_login_step( $uid, $token, __( '<strong>Error:</strong> Another attempt is in progress. Try again in a moment.', 'anderson-site-shield' ) );
				exit;
			}
			// Re-read inside the lock so parallel requests see each other's attempts.
			$state = $this->pending_login( $uid, $token );
			if ( ! $state ) {
				self::unlock( $uid );
				wp_safe_redirect( add_query_arg( 'anshield_expired', '1', wp_login_url() ) );
				exit;
			}
			$method = self::check_code( $uid, $code );

			if ( $method ) {
				delete_user_meta( $uid, self::META_LOGIN );
				delete_user_meta( $uid, self::META_FAILS );
				self::unlock( $uid );
				$this->verified_login = true;
				wp_set_auth_cookie( $uid, ! empty( $state['remember'] ), is_ssl() );
				$this->verified_login = false;
				Event_Log::log(
					'2fa.success',
					'backup' === $method ? 'notice' : 'info',
					'backup' === $method
						? sprintf( /* translators: %s: username */ __( '%s signed in with a backup code.', 'anderson-site-shield' ), $user->user_login )
						: sprintf( /* translators: %s: username */ __( '%s passed two-factor.', 'anderson-site-shield' ), $user->user_login ),
					array(
						'user_id' => $uid,
						'context' => array(
							'method'       => $method,
							'backups_left' => count( (array) get_user_meta( $uid, self::META_BACKUP, true ) ),
						),
					)
				);
				/** This action is documented in wp-includes/user.php */
				do_action( 'wp_login', $user->user_login, $user );

				if ( ! empty( $state['interim'] ) ) {
					// Session-expired popup in the dashboard: show core's "logged in" page so the popup closes.
					global $interim_login;
					$interim_login = 'success'; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
					login_header( '', '<p class="message">' . esc_html__( 'You have logged in successfully.', 'anderson-site-shield' ) . '</p>' );
					echo '</div>';
					/** This action is documented in wp-login.php */
					do_action( 'login_footer' ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
					echo '</body></html>';
					exit;
				}

				$requested = (string) $state['redirect'];
				$redirect  = '' !== $requested ? $requested : admin_url();
				$redirect  = apply_filters( 'login_redirect', $redirect, $requested, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
				if ( ( empty( $redirect ) || admin_url() === $redirect ) && ! $user->has_cap( 'edit_posts' ) ) {
					$redirect = admin_url( 'profile.php' );
				}
				wp_safe_redirect( $redirect );
				exit;
			}

			$state['attempts'] = (int) $state['attempts'] + 1;
			$user_fails        = self::user_failures( $uid, true );
			if ( 3 === $user_fails ) {
				Event_Log::log(
					'2fa.password_compromise_suspected',
					'critical',
					sprintf( /* translators: %s: username */ __( 'Someone entered the correct password for %s but failed two-factor 3 times. The password may be known to an attacker; change it.', 'anderson-site-shield' ), $user->user_login ),
					array( 'user_id' => $uid )
				);
			}
			Event_Log::log(
				'2fa.failed',
				'warning',
				sprintf( /* translators: %s: username */ __( 'Wrong two-factor code for %s.', 'anderson-site-shield' ), $user->user_login ),
				array(
					'user_id' => $uid,
					'context' => array( 'attempts' => $state['attempts'] ),
				)
			);
			/** Count it toward the IP lockout too. */
			do_action( 'wp_login_failed', $user->user_login, new \WP_Error( 'anshield_2fa_failed', 'Wrong two-factor code.' ) );

			if ( $state['attempts'] >= self::MAX_ATTEMPTS ) {
				delete_user_meta( $uid, self::META_LOGIN );
				self::unlock( $uid );
				wp_safe_redirect( add_query_arg( 'anshield_expired', '1', wp_login_url() ) );
				exit;
			}
			update_user_meta( $uid, self::META_LOGIN, $state );
			self::unlock( $uid );
			$error = __( '<strong>Error:</strong> That code is not correct. Try the newest code in your app.', 'anderson-site-shield' );
		}

		$this->render_login_step( $uid, $token, $error );
		exit;
	}

	/**
	 * Draw the code form using WordPress's own login page chrome.
	 *
	 * @param int    $uid   User ID.
	 * @param string $token Token.
	 * @param string $error Error HTML.
	 */
	private function render_login_step( $uid, $token, $error, $blocked = false ) {
		$wp_error = new \WP_Error();
		if ( $error ) {
			$wp_error->add( 'anshield_2fa', $error );
		}
		login_header( __( 'Two-factor authentication', 'anderson-site-shield' ), '', $wp_error );
		if ( $blocked ) {
			login_footer();
			return;
		}
		$action = add_query_arg( 'action', self::LOGIN_ACTION, site_url( 'wp-login.php', 'login_post' ) );
		?>
		<form name="anshield_2fa" id="loginform" action="<?php echo esc_url( $action ); ?>" method="post" autocomplete="off">
			<p><?php esc_html_e( 'Enter the 6-digit code from your authenticator app, or one of your backup codes.', 'anderson-site-shield' ); ?></p>
			<p>
				<label for="anshield_code"><?php esc_html_e( 'Authentication code', 'anderson-site-shield' ); ?></label>
				<input type="text" name="anshield_code" id="anshield_code" class="input" value="" size="20" inputmode="numeric" autocomplete="one-time-code" autofocus required />
			</p>
			<input type="hidden" name="uid" value="<?php echo esc_attr( $uid ); ?>" />
			<input type="hidden" name="token" value="<?php echo esc_attr( $token ); ?>" />
			<?php if ( ! empty( $_REQUEST['interim-login'] ) ) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended ?>
				<input type="hidden" name="interim-login" value="1" />
			<?php endif; ?>
			<p class="submit">
				<input type="submit" class="button button-primary button-large" value="<?php esc_attr_e( 'Verify', 'anderson-site-shield' ); ?>" />
			</p>
		</form>
		<?php
		login_footer( 'anshield_code' );
	}

	/* ------------------------------------------------------------------ */
	/* Enrollment                                                          */
	/* ------------------------------------------------------------------ */

	/**
	 * Users with a required role must enroll before using the dashboard.
	 */
	public function enforce_enrollment() {
		if ( ! self::pending_enrollment() ) {
			return;
		}
		if ( wp_doing_ajax() ) {
			wp_die( '-1', 403 );
		}
		$page = isset( $_GET['page'] ) ? sanitize_key( $_GET['page'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		global $pagenow;
		if ( self::SETUP_PAGE === $page ) {
			return;
		}
		if ( 'admin-post.php' === $pagenow ) {
			wp_die( esc_html__( 'Set up two-factor authentication first.', 'anderson-site-shield' ), 403 );
		}
		wp_safe_redirect( admin_url( 'admin.php?page=' . self::SETUP_PAGE . '&required=1' ) );
		exit;
	}

	/**
	 * Whether the current user must enroll and hasn't yet.
	 *
	 * @return bool
	 */
	private static function pending_enrollment() {
		if ( ! is_user_logged_in() ) {
			return false;
		}
		$user = wp_get_current_user();
		return self::is_required( $user ) && ! self::is_enrolled( $user->ID );
	}

	/**
	 * Users who still have to enroll can't use the REST API with their cookie.
	 *
	 * @param mixed $result Earlier result.
	 * @return mixed
	 */
	public function block_pending_rest( $result ) {
		if ( is_wp_error( $result ) || did_action( 'application_password_did_authenticate' ) ) {
			return $result;
		}
		if ( self::pending_enrollment() ) {
			return new \WP_Error( 'anshield_2fa_setup', __( 'Set up two-factor authentication before using the API.', 'anderson-site-shield' ), array( 'status' => 403 ) );
		}
		return $result;
	}

	/**
	 * Register the setup screen (reachable by every logged-in user).
	 */
	public function add_setup_page() {
		add_submenu_page(
			'profile.php',
			__( 'Two-factor authentication', 'anderson-site-shield' ),
			__( 'Two-factor', 'anderson-site-shield' ),
			'read',
			self::SETUP_PAGE,
			array( $this, 'render_setup_page' )
		);
		// Users with menu access to Users see it under Users > Profile instead.
		if ( current_user_can( 'list_users' ) ) {
			add_submenu_page(
				'users.php',
				__( 'Two-factor authentication', 'anderson-site-shield' ),
				__( 'Two-factor', 'anderson-site-shield' ),
				'read',
				self::SETUP_PAGE,
				array( $this, 'render_setup_page' )
			);
			remove_submenu_page( 'profile.php', self::SETUP_PAGE );
		}
	}

	/**
	 * The setup screen: enroll, regenerate backup codes, turn off.
	 */
	public function render_setup_page() {
		$user    = wp_get_current_user();
		$notice  = '';
		$error   = '';
		$codes   = array();
		$enabled = self::is_enrolled( $user->ID );

		if ( isset( $_POST['anshield_2fa_op'] ) && check_admin_referer( 'anshield_2fa_' . $user->ID ) ) {
			$op   = sanitize_key( $_POST['anshield_2fa_op'] );
			$code = isset( $_POST['anshield_code'] ) ? sanitize_text_field( wp_unslash( $_POST['anshield_code'] ) ) : '';

			if ( 'enroll' === $op && ! $enabled ) {
				$pending = Totp::decrypt( (string) get_user_meta( $user->ID, self::META_PENDING, true ) );
				$step    = $pending ? Totp::verify( $pending, $code ) : false;
				if ( false !== $step ) {
					update_user_meta( $user->ID, self::META_SECRET, Totp::encrypt( $pending ) );
					update_user_meta( $user->ID, self::META_LAST, $step );
					delete_user_meta( $user->ID, self::META_PENDING );
					$codes   = self::new_backup_codes( $user->ID );
					$enabled = true;
					self::mark_current_session( $user->ID );
					wp_destroy_other_sessions();
					$notice  = __( 'Two-factor is on. Save your backup codes below — this is the only time they are shown.', 'anderson-site-shield' );
					Event_Log::log( '2fa.enabled', 'notice', sprintf( /* translators: %s: username */ __( '%s turned on two-factor.', 'anderson-site-shield' ), $user->user_login ), array( 'object_type' => 'user', 'object_id' => $user->ID ) );
				} else {
					$error = __( 'That code did not match. Check that your phone’s clock is set automatically and try the newest code.', 'anderson-site-shield' );
				}
			} elseif ( 'backup' === $op && $enabled ) {
				if ( 'totp' === self::check_code( $user->ID, $code ) ) {
					$codes  = self::new_backup_codes( $user->ID );
					$notice = __( 'New backup codes are below. Your old codes no longer work.', 'anderson-site-shield' );
					Event_Log::log( '2fa.backup_regenerated', 'notice', sprintf( /* translators: %s: username */ __( '%s made new backup codes.', 'anderson-site-shield' ), $user->user_login ) );
				} else {
					$error = __( 'Enter a current code from your authenticator app to make new backup codes.', 'anderson-site-shield' );
				}
			} elseif ( 'disable' === $op && $enabled ) {
				if ( self::is_required( $user ) ) {
					$error = __( 'Your role requires two-factor, so it can’t be turned off. To move to a new phone, ask another administrator to reset it, then set it up again.', 'anderson-site-shield' );
				} elseif ( 'totp' === self::check_code( $user->ID, $code ) ) {
					self::reset( $user->ID, __( 'turned off by the user', 'anderson-site-shield' ) );
					$enabled = false;
					$notice  = __( 'Two-factor is off.', 'anderson-site-shield' );
				} else {
					$error = __( 'Enter a current code from your authenticator app to turn two-factor off.', 'anderson-site-shield' );
				}
			}
		}

		$pending_secret = '';
		if ( ! $enabled ) {
			$pending_secret = Totp::decrypt( (string) get_user_meta( $user->ID, self::META_PENDING, true ) );
			if ( ! $pending_secret ) {
				$pending_secret = Totp::new_secret();
				update_user_meta( $user->ID, self::META_PENDING, Totp::encrypt( $pending_secret ) );
			}
		}

		wp_enqueue_script( 'anshield-qrcode', ANSHIELD_URL . 'assets/vendor/qrcode.js', array(), '1.5.4', true );
		wp_enqueue_style( 'anshield-admin', ANSHIELD_URL . 'assets/admin.css', array(), ANSHIELD_VERSION );
		?>
		<div class="wrap anshield-wrap">
			<h1><?php esc_html_e( 'Two-factor authentication', 'anderson-site-shield' ); ?></h1>

			<?php if ( isset( $_GET['required'] ) && ! $enabled ) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended ?>
				<div class="notice notice-warning"><p><?php esc_html_e( 'Your account needs two-factor authentication before you can use the dashboard. It takes about a minute.', 'anderson-site-shield' ); ?></p></div>
			<?php endif; ?>
			<?php if ( $notice ) : ?>
				<div class="notice notice-success"><p><?php echo esc_html( $notice ); ?></p></div>
			<?php endif; ?>
			<?php if ( $error ) : ?>
				<div class="notice notice-error"><p><?php echo esc_html( $error ); ?></p></div>
			<?php endif; ?>

			<?php if ( $codes ) : ?>
				<div class="anshield-card">
					<h2><?php esc_html_e( 'Backup codes', 'anderson-site-shield' ); ?></h2>
					<p><?php esc_html_e( 'Each code works once. Keep them in your password manager, not on your phone.', 'anderson-site-shield' ); ?></p>
					<ol class="anshield-codes"><?php foreach ( $codes as $c ) : ?><li><code><?php echo esc_html( $c ); ?></code></li><?php endforeach; ?></ol>
					<p><button type="button" class="button" data-anshield-copy="<?php echo esc_attr( implode( "\n", $codes ) ); ?>"><?php esc_html_e( 'Copy codes', 'anderson-site-shield' ); ?></button></p>
				</div>
			<?php endif; ?>

			<?php if ( ! $enabled ) : ?>
				<div class="anshield-card anshield-enroll">
					<h2><?php esc_html_e( '1. Scan this code', 'anderson-site-shield' ); ?></h2>
					<p><?php esc_html_e( 'Use an authenticator app such as 1Password, Google Authenticator, Microsoft Authenticator or Authy.', 'anderson-site-shield' ); ?></p>
					<div id="anshield-qr" class="anshield-qr" data-uri="<?php echo esc_attr( Totp::uri( $pending_secret, $user->user_login ) ); ?>" role="img" aria-label="<?php esc_attr_e( 'QR code for your authenticator app', 'anderson-site-shield' ); ?>"></div>
					<p><?php esc_html_e( 'Can’t scan? Enter this key instead:', 'anderson-site-shield' ); ?><br /><code class="anshield-secret"><?php echo esc_html( trim( chunk_split( $pending_secret, 4, ' ' ) ) ); ?></code></p>

					<h2><?php esc_html_e( '2. Enter the code it shows', 'anderson-site-shield' ); ?></h2>
					<form method="post">
						<?php wp_nonce_field( 'anshield_2fa_' . $user->ID ); ?>
						<input type="hidden" name="anshield_2fa_op" value="enroll" />
						<input type="text" name="anshield_code" class="regular-text anshield-code-input" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]{6,7}" placeholder="123456" required />
						<?php submit_button( __( 'Turn on two-factor', 'anderson-site-shield' ), 'primary', 'submit', false ); ?>
					</form>
				</div>
			<?php else : ?>
				<div class="anshield-card">
					<h2><span class="anshield-pill anshield-pill-ok"><?php esc_html_e( 'On', 'anderson-site-shield' ); ?></span> <?php esc_html_e( 'Two-factor is protecting your account', 'anderson-site-shield' ); ?></h2>
					<p>
						<?php
						printf(
							/* translators: %d: number of codes */
							esc_html( _n( 'You have %d unused backup code.', 'You have %d unused backup codes.', count( (array) get_user_meta( $user->ID, self::META_BACKUP, true ) ), 'anderson-site-shield' ) ),
							(int) count( (array) get_user_meta( $user->ID, self::META_BACKUP, true ) )
						);
						?>
					</p>
					<form method="post" class="anshield-inline-form">
						<?php wp_nonce_field( 'anshield_2fa_' . $user->ID ); ?>
						<label><?php esc_html_e( 'Current app code', 'anderson-site-shield' ); ?>
							<input type="text" name="anshield_code" class="small-text anshield-code-input" inputmode="numeric" autocomplete="one-time-code" required />
						</label>
						<button class="button" name="anshield_2fa_op" value="backup"><?php esc_html_e( 'Make new backup codes', 'anderson-site-shield' ); ?></button>
						<?php if ( ! self::is_required( $user ) ) : ?>
							<button class="button button-link-delete" name="anshield_2fa_op" value="disable"><?php esc_html_e( 'Turn off two-factor', 'anderson-site-shield' ); ?></button>
						<?php endif; ?>
					</form>
				</div>
			<?php endif; ?>
		</div>
		<script>
		document.addEventListener( 'DOMContentLoaded', function () {
			var box = document.getElementById( 'anshield-qr' );
			if ( box && window.qrcode ) {
				var qr = window.qrcode( 0, 'M' );
				qr.addData( box.getAttribute( 'data-uri' ) );
				qr.make();
				box.innerHTML = qr.createSvgTag( { cellSize: 5, margin: 4, scalable: true } );
			}
			document.querySelectorAll( '[data-anshield-copy]' ).forEach( function ( btn ) {
				btn.addEventListener( 'click', function () {
					navigator.clipboard && navigator.clipboard.writeText( btn.getAttribute( 'data-anshield-copy' ) );
					btn.textContent = <?php echo wp_json_encode( __( 'Copied', 'anderson-site-shield' ) ); ?>;
				} );
			} );
		} );
		</script>
		<?php
	}

	/**
	 * Two-factor status on the profile screen.
	 *
	 * @param \WP_User $user Profile being viewed.
	 */
	public function profile_section( $user ) {
		$enrolled = self::is_enrolled( $user->ID );
		$own      = get_current_user_id() === $user->ID;
		?>
		<h2 id="anshield-2fa"><?php esc_html_e( 'Two-factor authentication', 'anderson-site-shield' ); ?></h2>
		<table class="form-table" role="presentation">
			<tr>
				<th><?php esc_html_e( 'Status', 'anderson-site-shield' ); ?></th>
				<td>
					<?php
					echo $enrolled
						? esc_html__( 'On', 'anderson-site-shield' )
						: ( self::is_required( $user ) ? esc_html__( 'Off — required for this role', 'anderson-site-shield' ) : esc_html__( 'Off', 'anderson-site-shield' ) );
					?>
					<?php if ( $own ) : ?>
						&nbsp;<a class="button" href="<?php echo esc_url( admin_url( 'admin.php?page=' . self::SETUP_PAGE ) ); ?>"><?php echo $enrolled ? esc_html__( 'Manage', 'anderson-site-shield' ) : esc_html__( 'Set up', 'anderson-site-shield' ); ?></a>
					<?php elseif ( $enrolled && current_user_can( 'edit_user', $user->ID ) && current_user_can( 'promote_users' ) ) : ?>
						<p><label><input type="checkbox" name="anshield_2fa_reset" value="1" /> <?php esc_html_e( 'Reset two-factor for this user (they will set it up again at next login)', 'anderson-site-shield' ); ?></label></p>
					<?php endif; ?>
				</td>
			</tr>
		</table>
		<?php
	}

	/**
	 * An administrator resets someone else's 2FA from their profile.
	 * Core has already checked the update-user nonce at this point.
	 *
	 * @param int $user_id Profile being saved.
	 */
	public function handle_admin_reset( $user_id ) {
		if ( empty( $_POST['anshield_2fa_reset'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			return;
		}
		if ( ! current_user_can( 'edit_user', $user_id ) || ! current_user_can( 'promote_users' ) || get_current_user_id() === (int) $user_id ) {
			return;
		}
		self::reset( $user_id, sprintf( /* translators: %s: admin username */ __( 'reset by %s', 'anderson-site-shield' ), wp_get_current_user()->user_login ) );
	}
}
