<?php
/**
 * Settings store.
 *
 * @package JATSiteShield
 */

namespace JATSiteShield;

defined( 'ABSPATH' ) || exit;

/**
 * Reads, validates and saves the plugin settings (one option).
 */
class Settings {

	const OPTION = 'jatss_settings';

	/**
	 * Cached settings.
	 *
	 * @var array|null
	 */
	private static $cache = null;

	/**
	 * Default values. Every key here is a setting; unknown keys are dropped on save.
	 *
	 * @return array
	 */
	public static function defaults() {
		return array(
			// Login protection.
			'login_protection'      => true,
			'login_max_attempts'    => 5,
			'login_window_minutes'  => 15,
			'login_lockout_minutes' => 30,
			'login_long_lockouts'   => 3,
			'login_long_hours'      => 24,
			'login_generic_errors'  => true,
			'login_allowlist'       => '',
			'custom_login_enabled'  => false,
			'custom_login_slug'     => '',

			// Two-factor.
			'twofa_enabled'         => true,
			'twofa_required_roles'  => array( 'administrator' ),
			'twofa_block_xmlrpc'    => true,

			// Hardening.
			'harden_xmlrpc'         => true,
			'harden_user_enum'      => true,
			'harden_file_edit'      => true,
			'harden_headers'        => true,
			'harden_hsts'           => false,
			'harden_hide_version'   => true,
			'harden_app_passwords'  => false,
			'harden_uploads_php'    => true,

			// Activity log.
			'log_enabled'           => true,
			'log_retention_days'    => 90,
			'alert_emails'          => '',
			'alert_min_severity'    => 'critical',

			// File integrity.
			'fim_enabled'           => true,
			'fim_plugins'           => true,

			// Network.
			'ip_source'             => 'REMOTE_ADDR',
			'trusted_proxies'       => '',
		);
	}

	/**
	 * All settings, merged over defaults.
	 *
	 * @return array
	 */
	public static function all() {
		if ( null === self::$cache ) {
			$stored      = get_option( self::OPTION, array() );
			self::$cache = array_merge( self::defaults(), is_array( $stored ) ? $stored : array() );
		}
		return self::$cache;
	}

	/**
	 * One setting.
	 *
	 * @param string $key Setting key.
	 * @return mixed
	 */
	public static function get( $key ) {
		$all = self::all();
		return array_key_exists( $key, $all ) ? $all[ $key ] : null;
	}

	/**
	 * Validate and store new values. Returns the list of keys that changed.
	 *
	 * @param array $input Raw values (only keys present are changed).
	 * @return array|\WP_Error Changed keys, or an error.
	 */
	public static function update( array $input ) {
		$current = self::all();
		$clean   = self::sanitize( $input, $current );
		if ( is_wp_error( $clean ) ) {
			return $clean;
		}
		$changed = array();
		foreach ( $clean as $key => $value ) {
			if ( $current[ $key ] !== $value ) {
				$changed[] = $key;
			}
		}
		$new = array_merge( $current, $clean );
		update_option( self::OPTION, $new, true );
		self::$cache = $new;
		return $changed;
	}

	/**
	 * Clear the in-memory cache (tests, CLI).
	 */
	public static function flush() {
		self::$cache = null;
	}

	/**
	 * Validate input against the defaults' types.
	 *
	 * @param array $input   Raw values.
	 * @param array $current Current values.
	 * @return array|\WP_Error
	 */
	private static function sanitize( array $input, array $current ) {
		$defaults = self::defaults();
		$out      = array();

		foreach ( $input as $key => $value ) {
			if ( ! array_key_exists( $key, $defaults ) ) {
				continue;
			}
			$type = gettype( $defaults[ $key ] );
			switch ( $type ) {
				case 'boolean':
					$out[ $key ] = (bool) $value && '0' !== $value;
					break;
				case 'integer':
					$out[ $key ] = max( 1, min( 100000, absint( $value ) ) );
					break;
				case 'array':
					$out[ $key ] = array_values( array_filter( array_map( 'sanitize_key', (array) $value ) ) );
					break;
				default:
					$out[ $key ] = is_string( $value ) ? trim( sanitize_textarea_field( $value ) ) : '';
			}
		}

		if ( isset( $out['login_allowlist'] ) ) {
			$ips = array();
			foreach ( preg_split( '/[\s,]+/', $out['login_allowlist'] ) as $entry ) {
				if ( '' !== $entry && Request::is_valid_ip_or_cidr( $entry ) ) {
					$ips[] = $entry;
				}
			}
			$out['login_allowlist'] = implode( "\n", array_unique( $ips ) );
		}

		if ( isset( $out['trusted_proxies'] ) ) {
			$ips = array();
			foreach ( preg_split( '/[\s,]+/', $out['trusted_proxies'] ) as $entry ) {
				if ( '' !== $entry && Request::is_valid_ip_or_cidr( $entry ) ) {
					$ips[] = $entry;
				}
			}
			$out['trusted_proxies'] = implode( "\n", array_unique( $ips ) );
		}

		if ( isset( $out['alert_emails'] ) ) {
			$emails = array();
			foreach ( preg_split( '/[\s,;]+/', $out['alert_emails'] ) as $email ) {
				$email = sanitize_email( $email );
				if ( is_email( $email ) ) {
					$emails[] = $email;
				}
			}
			$out['alert_emails'] = implode( ', ', array_unique( $emails ) );
		}

		if ( isset( $out['alert_min_severity'] ) && ! in_array( $out['alert_min_severity'], array( 'warning', 'critical' ), true ) ) {
			$out['alert_min_severity'] = 'critical';
		}

		if ( isset( $out['ip_source'] ) && ! array_key_exists( $out['ip_source'], Request::ip_sources() ) ) {
			$out['ip_source'] = 'REMOTE_ADDR';
		}

		if ( isset( $out['twofa_required_roles'] ) ) {
			$roles                       = array_keys( wp_roles()->roles );
			$out['twofa_required_roles'] = array_values( array_intersect( $out['twofa_required_roles'], $roles ) );
		}

		if ( isset( $out['custom_login_slug'] ) ) {
			$slug = sanitize_title( $out['custom_login_slug'] );
			if ( '' !== $slug ) {
				$valid = Modules\Login_Url::validate_slug( $slug );
				if ( is_wp_error( $valid ) ) {
					return $valid;
				}
			}
			$out['custom_login_slug'] = $slug;
		}

		$enabled = isset( $out['custom_login_enabled'] ) ? $out['custom_login_enabled'] : $current['custom_login_enabled'];
		$slug    = isset( $out['custom_login_slug'] ) ? $out['custom_login_slug'] : $current['custom_login_slug'];
		if ( $enabled && '' === $slug ) {
			return new \WP_Error( 'jatss_slug', __( 'Choose a login address before turning on the custom login URL.', 'jat-site-shield' ) );
		}

		if ( isset( $out['login_max_attempts'] ) ) {
			$out['login_max_attempts'] = max( 2, min( 50, $out['login_max_attempts'] ) );
		}
		if ( isset( $out['log_retention_days'] ) ) {
			$out['log_retention_days'] = max( 7, min( 3650, $out['log_retention_days'] ) );
		}

		return $out;
	}
}
