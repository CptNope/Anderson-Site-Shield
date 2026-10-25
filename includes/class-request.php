<?php
/**
 * Request helpers: client IP and user agent.
 *
 * @package AndersonSiteShield
 */

namespace AndersonSiteShield;

defined( 'ABSPATH' ) || exit;

/**
 * Works out who is making the request.
 */
class Request {

	/**
	 * Where the client IP can come from. Only REMOTE_ADDR cannot be forged by
	 * the client; the headers are only safe when a proxy you control sets them.
	 *
	 * @return array Server key => label.
	 */
	public static function ip_sources() {
		return array(
			'REMOTE_ADDR'           => __( 'Direct connection (REMOTE_ADDR) — safest default', 'anderson-site-shield' ),
			'HTTP_CF_CONNECTING_IP' => __( 'Cloudflare (CF-Connecting-IP)', 'anderson-site-shield' ),
			'HTTP_X_REAL_IP'        => __( 'Reverse proxy (X-Real-IP)', 'anderson-site-shield' ),
			'HTTP_X_FORWARDED_FOR'  => __( 'Reverse proxy (X-Forwarded-For, nearest hop)', 'anderson-site-shield' ),
		);
	}

	/**
	 * The client IP for this request, or '0.0.0.0' when unknown.
	 *
	 * @return string
	 */
	public static function ip() {
		static $ip = null;
		if ( null !== $ip ) {
			return $ip;
		}

		$source = Settings::get( 'ip_source' );
		$remote = isset( $_SERVER['REMOTE_ADDR'] ) ? self::clean_ip( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$ip     = $remote;

		if ( 'REMOTE_ADDR' !== $source && isset( $_SERVER[ $source ] ) && self::is_trusted_proxy( $remote, $source ) ) {
			$raw = wp_unslash( $_SERVER[ $source ] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			if ( 'HTTP_X_FORWARDED_FOR' === $source ) {
				// The right-most entry was added by the proxy nearest to us; earlier ones can be forged.
				$parts = array_map( 'trim', explode( ',', (string) $raw ) );
				$raw   = end( $parts );
			}
			$candidate = self::clean_ip( $raw );
			if ( '' !== $candidate ) {
				$ip = $candidate;
			}
		}

		$ip = '' !== $ip ? $ip : '0.0.0.0';
		return $ip;
	}

	/**
	 * Cloudflare's published edge ranges (https://www.cloudflare.com/ips/).
	 *
	 * @var string[]
	 */
	const CLOUDFLARE = array(
		'173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18',
		'108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17',
		'162.158.0.0/15', '104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
		'2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32', '2405:8100::/32',
		'2a06:98c0::/29', '2c0f:f248::/32',
	);

	/**
	 * Only believe a forwarded-IP header when the connection itself comes
	 * from a proxy we trust. Otherwise anyone reaching the server directly
	 * could pick their own IP and dodge (or abuse) lockouts.
	 *
	 * @param string $remote REMOTE_ADDR.
	 * @param string $source Header key.
	 * @return bool
	 */
	public static function is_trusted_proxy( $remote, $source ) {
		if ( '' === $remote ) {
			return false;
		}
		// A proxy on the same machine or private network (nginx in front of Apache, a load balancer).
		// Not for Cloudflare's header: a local proxy passes it through untouched, so it could be forged.
		if ( 'HTTP_CF_CONNECTING_IP' !== $source && ! filter_var( $remote, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
			return true;
		}
		if ( 'HTTP_CF_CONNECTING_IP' === $source ) {
			foreach ( self::CLOUDFLARE as $range ) {
				if ( self::ip_in_range( $remote, $range ) ) {
					return true;
				}
			}
		}
		foreach ( preg_split( '/\s+/', trim( (string) Settings::get( 'trusted_proxies' ) ) ) as $range ) {
			if ( '' !== $range && self::ip_in_range( $remote, $range ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * The unit lockouts count against: the IP, or its /64 for IPv6
	 * (one customer usually controls a whole /64).
	 *
	 * @param string $ip IP.
	 * @return string
	 */
	public static function bucket( $ip ) {
		if ( false === strpos( $ip, ':' ) ) {
			return $ip;
		}
		$bin = @inet_pton( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( false === $bin || 16 !== strlen( $bin ) ) {
			return $ip;
		}
		return inet_ntop( substr( $bin, 0, 8 ) . str_repeat( chr( 0 ), 8 ) ) . '/64';
	}

	/**
	 * Whether the site looks like it's behind Cloudflare while still using REMOTE_ADDR.
	 *
	 * @return bool
	 */
	public static function proxy_misconfigured() {
		return 'REMOTE_ADDR' === Settings::get( 'ip_source' ) && ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] );
	}

	/**
	 * The request's user agent, trimmed.
	 *
	 * @return string
	 */
	public static function user_agent() {
		$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		return substr( $ua, 0, 255 );
	}

	/**
	 * Validate one IP string.
	 *
	 * @param mixed $raw Candidate.
	 * @return string Valid IP or ''.
	 */
	public static function clean_ip( $raw ) {
		$raw = trim( (string) $raw );
		return filter_var( $raw, FILTER_VALIDATE_IP ) ? $raw : '';
	}

	/**
	 * Whether a string is an IP or a CIDR range.
	 *
	 * @param string $entry IP or CIDR.
	 * @return bool
	 */
	public static function is_valid_ip_or_cidr( $entry ) {
		if ( filter_var( $entry, FILTER_VALIDATE_IP ) ) {
			return true;
		}
		if ( false === strpos( $entry, '/' ) ) {
			return false;
		}
		list( $net, $bits ) = explode( '/', $entry, 2 );
		if ( ! ctype_digit( $bits ) || ! filter_var( $net, FILTER_VALIDATE_IP ) ) {
			return false;
		}
		$max = false !== strpos( $net, ':' ) ? 128 : 32;
		return (int) $bits <= $max;
	}

	/**
	 * Whether an IP falls inside an IP or CIDR range.
	 *
	 * @param string $ip    IP to test.
	 * @param string $range IP or CIDR.
	 * @return bool
	 */
	public static function ip_in_range( $ip, $range ) {
		if ( false === strpos( $range, '/' ) ) {
			return inet_pton( $ip ) === @inet_pton( $range ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		}
		list( $net, $bits ) = explode( '/', $range, 2 );
		$ip_bin  = @inet_pton( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		$net_bin = @inet_pton( $net ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( false === $ip_bin || false === $net_bin || strlen( $ip_bin ) !== strlen( $net_bin ) ) {
			return false;
		}
		$bits  = (int) $bits;
		$bytes = intdiv( $bits, 8 );
		if ( substr( $ip_bin, 0, $bytes ) !== substr( $net_bin, 0, $bytes ) ) {
			return false;
		}
		$rem = $bits % 8;
		if ( 0 === $rem ) {
			return true;
		}
		$mask = chr( ( 0xff << ( 8 - $rem ) ) & 0xff );
		return ( $ip_bin[ $bytes ] & $mask ) === ( $net_bin[ $bytes ] & $mask );
	}

	/**
	 * Whether the current client IP is on the login allowlist.
	 *
	 * @return bool
	 */
	public static function is_allowlisted() {
		$list = trim( (string) Settings::get( 'login_allowlist' ) );
		if ( '' === $list ) {
			return false;
		}
		$ip = self::ip();
		foreach ( preg_split( '/\s+/', $list ) as $range ) {
			if ( '' !== $range && self::ip_in_range( $ip, $range ) ) {
				return true;
			}
		}
		return false;
	}
}
