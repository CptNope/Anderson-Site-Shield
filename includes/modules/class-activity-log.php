<?php
/**
 * Activity log: records security-relevant changes on the site.
 *
 * @package AndersonSiteShield
 */

namespace AndersonSiteShield\Modules;

use AndersonSiteShield\Event_Log;
use AndersonSiteShield\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Listens to WordPress actions and writes events.
 */
class Activity_Log {

	/**
	 * Options whose change is worth knowing about, with severity.
	 *
	 * @var array
	 */
	const WATCHED_OPTIONS = array(
		'siteurl'            => 'critical',
		'home'               => 'critical',
		'admin_email'        => 'critical',
		'users_can_register' => 'warning',
		'default_role'       => 'warning',
		'blog_public'        => 'notice',
		'permalink_structure' => 'notice',
		'blogname'           => 'info',
	);

	/**
	 * Hook in.
	 */
	public function register() {
		if ( ! Settings::get( 'log_enabled' ) ) {
			return;
		}

		add_action( 'wp_login', array( $this, 'login' ), 10, 2 );
		add_action( 'wp_logout', array( $this, 'logout' ), 10, 1 );
		add_action( 'user_register', array( $this, 'user_created' ), 10, 1 );
		add_action( 'deleted_user', array( $this, 'user_deleted' ), 10, 3 );
		add_action( 'set_user_role', array( $this, 'role_changed' ), 10, 3 );
		add_action( 'add_user_role', array( $this, 'role_added' ), 10, 2 );
		add_action( 'grant_super_admin', array( $this, 'super_admin' ), 10, 1 );
		add_action( 'profile_update', array( $this, 'profile_updated' ), 10, 3 );
		add_action( 'after_password_reset', array( $this, 'password_reset' ), 10, 1 );
		add_action( 'application_password_did_authenticate', array( $this, 'app_password_used' ), 10, 2 );
		add_action( 'wp_create_application_password', array( $this, 'app_password_created' ), 10, 2 );

		add_action( 'activated_plugin', array( $this, 'plugin_activated' ), 10, 2 );
		add_action( 'deactivated_plugin', array( $this, 'plugin_deactivated' ), 10, 2 );
		add_action( 'deleted_plugin', array( $this, 'plugin_deleted' ), 10, 2 );
		add_action( 'upgrader_process_complete', array( $this, 'upgrader_done' ), 10, 2 );
		add_action( 'switch_theme', array( $this, 'theme_switched' ), 10, 3 );
		add_action( 'deleted_theme', array( $this, 'theme_deleted' ), 10, 2 );
		add_action( '_core_updated_successfully', array( $this, 'core_updated' ), 10, 1 );

		add_action( 'updated_option', array( $this, 'option_updated' ), 10, 3 );
		add_action( 'update_option_' . \AndersonSiteShield\Settings::OPTION, array( $this, 'settings_changed' ), 10, 2 );
	}

	/**
	 * Successful login.
	 *
	 * @param string   $login Username.
	 * @param \WP_User $user  User.
	 */
	public function login( $login, $user ) {
		$is_admin = $user instanceof \WP_User && $user->has_cap( 'manage_options' );
		Event_Log::log(
			'auth.login',
			$is_admin ? 'notice' : 'info',
			sprintf( /* translators: %s: username */ __( '%s logged in.', 'anderson-site-shield' ), $login ),
			array( 'user_id' => $user instanceof \WP_User ? $user->ID : 0 )
		);
	}

	/**
	 * Logout.
	 *
	 * @param int $user_id User ID.
	 */
	public function logout( $user_id = 0 ) {
		Event_Log::log( 'auth.logout', 'info', __( 'User logged out.', 'anderson-site-shield' ), array( 'user_id' => (int) $user_id ) );
	}

	/**
	 * Severity for a role.
	 *
	 * @param string $role Role.
	 * @return string
	 */
	private static function role_severity( $role ) {
		if ( 'administrator' === $role ) {
			return 'critical';
		}
		$obj = get_role( $role );
		if ( $obj && ( $obj->has_cap( 'manage_options' ) || $obj->has_cap( 'edit_users' ) || $obj->has_cap( 'install_plugins' ) || $obj->has_cap( 'unfiltered_html' ) ) ) {
			return 'warning';
		}
		return 'info';
	}

	/**
	 * New user.
	 *
	 * @param int $user_id User ID.
	 */
	public function user_created( $user_id ) {
		$user  = get_userdata( $user_id );
		$role  = $user && $user->roles ? reset( $user->roles ) : '';
		$actor = get_current_user_id();
		Event_Log::log(
			'user.created',
			self::role_severity( $role ),
			sprintf(
				/* translators: 1: new username, 2: role, 3: who */
				__( 'New user %1$s created with role %2$s (%3$s).', 'anderson-site-shield' ),
				$user ? $user->user_login : '#' . $user_id,
				$role ? $role : 'none',
				$actor ? sprintf( /* translators: %s: username */ __( 'by %s', 'anderson-site-shield' ), wp_get_current_user()->user_login ) : __( 'self-registration or code', 'anderson-site-shield' )
			),
			array(
				'object_type' => 'user',
				'object_id'   => $user_id,
				'context'     => array(
					'role'  => $role,
					'email' => $user ? $user->user_email : '',
				),
			)
		);
	}

	/**
	 * Deleted user.
	 *
	 * @param int      $id       User ID.
	 * @param int|null $reassign Reassigned to.
	 * @param \WP_User $user     User.
	 */
	public function user_deleted( $id, $reassign = null, $user = null ) {
		Event_Log::log(
			'user.deleted',
			'warning',
			sprintf( /* translators: %s: username */ __( 'User %s was deleted.', 'anderson-site-shield' ), $user instanceof \WP_User ? $user->user_login : '#' . $id ),
			array(
				'object_type' => 'user',
				'object_id'   => $id,
			)
		);
	}

	/**
	 * Role set.
	 *
	 * @param int    $user_id   User ID.
	 * @param string $role      New role.
	 * @param array  $old_roles Old roles.
	 */
	public function role_changed( $user_id, $role, $old_roles = array() ) {
		if ( in_array( $role, (array) $old_roles, true ) ) {
			return;
		}
		$user = get_userdata( $user_id );
		// A brand-new user's first role is reported by user_created().
		if ( empty( $old_roles ) && $user && strtotime( $user->user_registered . ' UTC' ) > time() - MINUTE_IN_SECONDS ) {
			return;
		}
		Event_Log::log(
			'user.role_changed',
			self::role_severity( $role ),
			sprintf(
				/* translators: 1: username, 2: old roles, 3: new role */
				__( 'Role of %1$s changed from %2$s to %3$s.', 'anderson-site-shield' ),
				$user ? $user->user_login : '#' . $user_id,
				$old_roles ? implode( ', ', (array) $old_roles ) : 'none',
				$role ? $role : 'none'
			),
			array(
				'object_type' => 'user',
				'object_id'   => $user_id,
				'context'     => array(
					'from' => array_values( (array) $old_roles ),
					'to'   => $role,
				),
			)
		);
	}

	/**
	 * Extra role added.
	 *
	 * @param int    $user_id User ID.
	 * @param string $role    Role.
	 */
	public function role_added( $user_id, $role ) {
		$user = get_userdata( $user_id );
		Event_Log::log(
			'user.role_added',
			self::role_severity( $role ),
			sprintf( /* translators: 1: role, 2: username */ __( 'Role %1$s added to %2$s.', 'anderson-site-shield' ), $role, $user ? $user->user_login : '#' . $user_id ),
			array(
				'object_type' => 'user',
				'object_id'   => $user_id,
			)
		);
	}

	/**
	 * Super admin granted (multisite).
	 *
	 * @param int $user_id User ID.
	 */
	public function super_admin( $user_id ) {
		$user = get_userdata( $user_id );
		Event_Log::log( 'user.super_admin', 'critical', sprintf( /* translators: %s: username */ __( '%s was made a super admin.', 'anderson-site-shield' ), $user ? $user->user_login : '#' . $user_id ) );
	}

	/**
	 * Email or password change on a profile.
	 *
	 * @param int      $user_id  User ID.
	 * @param \WP_User $old_user Data before.
	 * @param array    $new_data Data saved.
	 */
	public function profile_updated( $user_id, $old_user = null, $new_data = array() ) {
		$user = get_userdata( $user_id );
		if ( ! $user || ! $old_user instanceof \WP_User ) {
			return;
		}
		$privileged = $user->has_cap( 'manage_options' );
		if ( $old_user->user_email !== $user->user_email ) {
			Event_Log::log(
				'user.email_changed',
				$privileged ? 'critical' : 'notice',
				sprintf( /* translators: 1: username, 2: old, 3: new */ __( 'Email of %1$s changed from %2$s to %3$s.', 'anderson-site-shield' ), $user->user_login, $old_user->user_email, $user->user_email ),
				array(
					'object_type' => 'user',
					'object_id'   => $user_id,
				)
			);
		}
		if ( $old_user->user_pass !== $user->user_pass ) {
			Event_Log::log(
				'user.password_changed',
				$privileged ? 'warning' : 'info',
				sprintf( /* translators: %s: username */ __( 'Password of %s was changed.', 'anderson-site-shield' ), $user->user_login ),
				array(
					'object_type' => 'user',
					'object_id'   => $user_id,
				)
			);
		}
	}

	/**
	 * Password reset by email link.
	 *
	 * @param \WP_User $user User.
	 */
	public function password_reset( $user ) {
		Event_Log::log(
			'user.password_reset',
			$user->has_cap( 'manage_options' ) ? 'warning' : 'info',
			sprintf( /* translators: %s: username */ __( '%s reset their password with an email link.', 'anderson-site-shield' ), $user->user_login ),
			array( 'user_id' => $user->ID )
		);
	}

	/**
	 * Application password used (throttled per IP).
	 *
	 * @param \WP_User $user User.
	 * @param array    $item Password item.
	 */
	public function app_password_used( $user, $item ) {
		$key = 'anshield_ap_' . md5( $user->ID . '|' . ( isset( $item['uuid'] ) ? $item['uuid'] : '' ) );
		if ( get_transient( $key ) ) {
			return;
		}
		set_transient( $key, 1, HOUR_IN_SECONDS );
		Event_Log::log(
			'auth.app_password',
			'info',
			sprintf( /* translators: 1: username, 2: app name */ __( '%1$s used application password "%2$s".', 'anderson-site-shield' ), $user->user_login, isset( $item['name'] ) ? $item['name'] : '' ),
			array( 'user_id' => $user->ID )
		);
	}

	/**
	 * Application password created.
	 *
	 * @param int   $user_id User ID.
	 * @param array $item    Password item.
	 */
	public function app_password_created( $user_id, $item ) {
		$user = get_userdata( $user_id );
		Event_Log::log(
			'auth.app_password_created',
			'warning',
			sprintf( /* translators: 1: app name, 2: username */ __( 'Application password "%1$s" created for %2$s.', 'anderson-site-shield' ), isset( $item['name'] ) ? $item['name'] : '', $user ? $user->user_login : '#' . $user_id ),
			array(
				'object_type' => 'user',
				'object_id'   => $user_id,
			)
		);
	}

	/**
	 * Plugin name from its file.
	 *
	 * @param string $plugin Plugin basename.
	 * @return string
	 */
	private static function plugin_name( $plugin ) {
		$path = WP_PLUGIN_DIR . '/' . $plugin;
		if ( file_exists( $path ) ) {
			if ( ! function_exists( 'get_plugin_data' ) ) {
				require_once ABSPATH . 'wp-admin/includes/plugin.php';
			}
			$data = get_plugin_data( $path, false, false );
			if ( ! empty( $data['Name'] ) ) {
				return $data['Name'];
			}
		}
		return $plugin;
	}

	/**
	 * Plugin activated.
	 *
	 * @param string $plugin  Basename.
	 * @param bool   $network Network-wide.
	 */
	public function plugin_activated( $plugin, $network = false ) {
		Event_Log::log(
			'plugin.activated',
			'notice',
			sprintf( /* translators: %s: plugin */ __( 'Plugin activated: %s.', 'anderson-site-shield' ), self::plugin_name( $plugin ) ),
			array(
				'object_type' => 'plugin',
				'object_id'   => $plugin,
			)
		);
	}

	/**
	 * Plugin deactivated. Turning off this plugin is critical.
	 *
	 * @param string $plugin  Basename.
	 * @param bool   $network Network-wide.
	 */
	public function plugin_deactivated( $plugin, $network = false ) {
		$self = ANSHIELD_BASENAME === $plugin;
		Event_Log::log(
			$self ? 'plugin.shield_deactivated' : 'plugin.deactivated',
			$self ? 'critical' : 'notice',
			$self
				? __( 'Anderson Site Shield was deactivated. The site is no longer protected.', 'anderson-site-shield' )
				: sprintf( /* translators: %s: plugin */ __( 'Plugin deactivated: %s.', 'anderson-site-shield' ), self::plugin_name( $plugin ) ),
			array(
				'object_type' => 'plugin',
				'object_id'   => $plugin,
			)
		);
	}

	/**
	 * Plugin deleted.
	 *
	 * @param string $plugin  Basename.
	 * @param bool   $deleted Success.
	 */
	public function plugin_deleted( $plugin, $deleted = true ) {
		if ( ! $deleted ) {
			return;
		}
		Event_Log::log(
			'plugin.deleted',
			'notice',
			sprintf( /* translators: %s: plugin */ __( 'Plugin deleted: %s.', 'anderson-site-shield' ), $plugin ),
			array(
				'object_type' => 'plugin',
				'object_id'   => $plugin,
			)
		);
	}

	/**
	 * Installs and updates of plugins and themes.
	 *
	 * @param \WP_Upgrader $upgrader Upgrader.
	 * @param array        $extra    Details.
	 */
	public function upgrader_done( $upgrader, $extra ) {
		$type   = isset( $extra['type'] ) ? $extra['type'] : '';
		$action = isset( $extra['action'] ) ? $extra['action'] : '';
		if ( ! in_array( $type, array( 'plugin', 'theme' ), true ) || ! in_array( $action, array( 'install', 'update' ), true ) ) {
			return;
		}

		$items = array();
		if ( 'install' === $action ) {
			if ( 'plugin' === $type && method_exists( $upgrader, 'plugin_info' ) && $upgrader->plugin_info() ) {
				$items[] = $upgrader->plugin_info();
			} elseif ( 'theme' === $type && method_exists( $upgrader, 'theme_info' ) && $upgrader->theme_info() ) {
				$items[] = $upgrader->theme_info()->get_stylesheet();
			} elseif ( ! empty( $upgrader->new_plugin_data['Name'] ) ) {
				$items[] = $upgrader->new_plugin_data['Name'];
			}
		} else {
			$key   = 'plugin' === $type ? 'plugins' : 'themes';
			$items = isset( $extra[ $key ] ) ? (array) $extra[ $key ] : ( isset( $extra[ $type ] ) ? array( $extra[ $type ] ) : array() );
		}

		foreach ( $items as $item ) {
			$name = 'plugin' === $type ? self::plugin_name( $item ) : $item;
			Event_Log::log(
				$type . '.' . ( 'install' === $action ? 'installed' : 'updated' ),
				'install' === $action ? 'warning' : 'info',
				'install' === $action
					/* translators: 1: plugin or theme, 2: name */
					? sprintf( __( 'New %1$s installed: %2$s.', 'anderson-site-shield' ), $type, $name )
					/* translators: 1: plugin or theme, 2: name */
					: sprintf( __( '%1$s updated: %2$s.', 'anderson-site-shield' ), ucfirst( $type ), $name ),
				array(
					'object_type' => $type,
					'object_id'   => $item,
				)
			);
		}
	}

	/**
	 * Theme switched.
	 *
	 * @param string    $name      New theme name.
	 * @param \WP_Theme $new_theme New theme.
	 * @param \WP_Theme $old_theme Old theme.
	 */
	public function theme_switched( $name, $new_theme = null, $old_theme = null ) {
		Event_Log::log(
			'theme.switched',
			'notice',
			sprintf( /* translators: 1: old, 2: new */ __( 'Theme changed from %1$s to %2$s.', 'anderson-site-shield' ), $old_theme instanceof \WP_Theme ? $old_theme->get( 'Name' ) : '?', $name ),
			array(
				'object_type' => 'theme',
				'object_id'   => $new_theme instanceof \WP_Theme ? $new_theme->get_stylesheet() : $name,
			)
		);
	}

	/**
	 * Theme deleted.
	 *
	 * @param string $stylesheet Theme.
	 * @param bool   $deleted    Success.
	 */
	public function theme_deleted( $stylesheet, $deleted = true ) {
		if ( $deleted ) {
			Event_Log::log( 'theme.deleted', 'notice', sprintf( /* translators: %s: theme */ __( 'Theme deleted: %s.', 'anderson-site-shield' ), $stylesheet ) );
		}
	}

	/**
	 * Core updated.
	 *
	 * @param string $version New version.
	 */
	public function core_updated( $version ) {
		Event_Log::log( 'core.updated', 'notice', sprintf( /* translators: %s: version */ __( 'WordPress updated to %s.', 'anderson-site-shield' ), $version ) );
	}

	/**
	 * Watched option changed.
	 *
	 * @param string $option Option.
	 * @param mixed  $old    Old value.
	 * @param mixed  $new    New value.
	 */
	public function option_updated( $option, $old, $new ) {
		if ( ! isset( self::WATCHED_OPTIONS[ $option ] ) ) {
			return;
		}
		$severity = self::WATCHED_OPTIONS[ $option ];

		// Open registration as administrator is the classic takeover.
		$open_reg = ( 'users_can_register' === $option && $new ) || ( 'default_role' === $option && get_option( 'users_can_register' ) );
		if ( $open_reg && 'administrator' === get_option( 'default_role' ) ) {
			$severity = 'critical';
		}
		if ( 'default_role' === $option && 'warning' !== self::role_severity( (string) $new ) && 'critical' !== self::role_severity( (string) $new ) ) {
			$severity = 'notice';
		}
		if ( 'default_role' === $option && 'administrator' === $new ) {
			$severity = 'critical';
		}

		Event_Log::log(
			'option.changed',
			$severity,
			sprintf(
				/* translators: 1: option, 2: old, 3: new */
				__( 'Setting %1$s changed from "%2$s" to "%3$s".', 'anderson-site-shield' ),
				$option,
				is_scalar( $old ) ? (string) $old : wp_json_encode( $old ),
				is_scalar( $new ) ? (string) $new : wp_json_encode( $new )
			),
			array(
				'object_type' => 'option',
				'object_id'   => $option,
			)
		);
	}

	/**
	 * This plugin's own settings changed: protections switched off are warnings.
	 *
	 * @param array $old Old settings.
	 * @param array $new New settings.
	 */
	public function settings_changed( $old, $new ) {
		$old = is_array( $old ) ? $old : array();
		$new = is_array( $new ) ? $new : array();
		$off = array();
		$on  = array();
		foreach ( $new as $key => $value ) {
			if ( ! is_bool( $value ) || ! array_key_exists( $key, $old ) || (bool) $old[ $key ] === $value ) {
				continue;
			}
			if ( $value ) {
				$on[] = $key;
			} else {
				$off[] = $key;
			}
		}
		$changed = array_keys( array_diff_assoc( array_map( 'maybe_serialize', $new ), array_map( 'maybe_serialize', $old ) ) );
		if ( ! $changed ) {
			return;
		}
		Event_Log::log(
			'shield.settings_changed',
			$off ? 'warning' : 'notice',
			$off
				/* translators: %s: setting keys */
				? sprintf( __( 'Site Shield settings changed. Turned off: %s.', 'anderson-site-shield' ), implode( ', ', $off ) )
				/* translators: %s: setting keys */
				: sprintf( __( 'Site Shield settings changed: %s.', 'anderson-site-shield' ), implode( ', ', $changed ) ),
			array(
				'context' => array(
					'changed' => $changed,
					'off'     => $off,
					'on'      => $on,
				),
			)
		);
	}
}
