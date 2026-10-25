<?php
/**
 * Plugin bootstrap.
 *
 * @package AndersonSiteShield
 */

namespace AndersonSiteShield;

defined( 'ABSPATH' ) || exit;

/**
 * Wires up the modules.
 */
class Plugin {

	const CRON_DAILY = 'anshield_daily';

	/**
	 * Singleton.
	 *
	 * @var Plugin|null
	 */
	private static $instance = null;

	/**
	 * Loaded modules by key.
	 *
	 * @var array
	 */
	private $modules = array();

	/**
	 * Get the instance.
	 *
	 * @return Plugin
	 */
	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * A loaded module.
	 *
	 * @param string $key Module key.
	 * @return object|null
	 */
	public function module( $key ) {
		return isset( $this->modules[ $key ] ) ? $this->modules[ $key ] : null;
	}

	/**
	 * Start everything. Runs while plugins load, before `plugins_loaded`,
	 * so the custom login URL can catch the request early.
	 */
	public function boot() {
		if ( get_option( 'anshield_db_version' ) !== Event_Log::DB_VERSION ) {
			add_action( 'init', array( Event_Log::class, 'install' ), 1 );
		}

		// Hardening first: DISALLOW_FILE_EDIT must be defined early.
		$this->modules['hardening'] = new Modules\Hardening();
		$this->modules['activity']  = new Modules\Activity_Log();
		$this->modules['login']     = new Modules\Login_Protection();
		$this->modules['login_url'] = new Modules\Login_Url();
		$this->modules['twofa']     = new Modules\Two_Factor();
		$this->modules['fim']       = new Modules\File_Integrity();
		$this->modules['alerts']    = new Alerts();

		foreach ( $this->modules as $module ) {
			$module->register();
		}

		add_action( self::CRON_DAILY, array( $this, 'daily' ) );
		add_action( 'init', array( $this, 'ensure_cron' ) );

		if ( is_admin() ) {
			( new Admin\Admin() )->register();
		}

		( new Updater() )->register();

		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			\WP_CLI::add_command( 'site-shield', CLI::class );
		}
	}

	/**
	 * Daily housekeeping.
	 */
	public function daily() {
		Event_Log::prune();
		if ( Settings::get( 'fim_enabled' ) ) {
			$this->modules['fim']->start_scan( 'schedule' );
		}
	}

	/**
	 * Make sure the daily event is scheduled.
	 */
	public function ensure_cron() {
		if ( ! wp_next_scheduled( self::CRON_DAILY ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', self::CRON_DAILY );
		}
	}

	/**
	 * Activation.
	 */
	public static function activate() {
		Event_Log::install();
		Totp::dedicated_key(); // Create the 2FA key file now, while we know we're an admin request.
		if ( ! get_option( Settings::OPTION ) ) {
			add_option( Settings::OPTION, Settings::defaults(), '', true );
		}
		Settings::flush();
		if ( Settings::get( 'harden_uploads_php' ) ) {
			Modules\Hardening::write_uploads_rules( true );
		}
		if ( ! wp_next_scheduled( self::CRON_DAILY ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', self::CRON_DAILY );
		}
	}

	/**
	 * Deactivation: stop cron and remove server rules, keep data.
	 */
	public static function deactivate() {
		wp_clear_scheduled_hook( self::CRON_DAILY );
		wp_clear_scheduled_hook( Modules\File_Integrity::CRON_TICK );
		Modules\Hardening::write_uploads_rules( false );
	}
}
