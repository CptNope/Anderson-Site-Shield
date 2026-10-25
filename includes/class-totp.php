<?php
/**
 * TOTP (RFC 6238) and secret encryption.
 *
 * @package AndersonSiteShield
 */

namespace AndersonSiteShield;

defined( 'ABSPATH' ) || exit;

/**
 * Time-based one-time passwords, compatible with Google Authenticator,
 * 1Password, Authy, Microsoft Authenticator and similar apps.
 */
class Totp {

	const PERIOD = 30;
	const DIGITS = 6;
	const WINDOW = 1; // Accept one step either side for clock drift.

	const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	/**
	 * New random secret, base32 (160 bits).
	 *
	 * @return string
	 */
	public static function new_secret() {
		return self::base32_encode( random_bytes( 20 ) );
	}

	/**
	 * Base32 encode (RFC 4648, no padding).
	 *
	 * @param string $bin Binary.
	 * @return string
	 */
	public static function base32_encode( $bin ) {
		$bits = '';
		foreach ( str_split( $bin ) as $char ) {
			$bits .= str_pad( decbin( ord( $char ) ), 8, '0', STR_PAD_LEFT );
		}
		$out = '';
		foreach ( str_split( $bits, 5 ) as $chunk ) {
			$out .= self::B32[ bindec( str_pad( $chunk, 5, '0', STR_PAD_RIGHT ) ) ];
		}
		return $out;
	}

	/**
	 * Base32 decode.
	 *
	 * @param string $b32 Base32 text.
	 * @return string|false Binary, or false if invalid.
	 */
	public static function base32_decode( $b32 ) {
		$b32  = strtoupper( preg_replace( '/[\s=]/', '', $b32 ) );
		$bits = '';
		foreach ( str_split( $b32 ) as $char ) {
			$pos = strpos( self::B32, $char );
			if ( false === $pos ) {
				return false;
			}
			$bits .= str_pad( decbin( $pos ), 5, '0', STR_PAD_LEFT );
		}
		$out = '';
		foreach ( str_split( $bits, 8 ) as $byte ) {
			if ( 8 === strlen( $byte ) ) {
				$out .= chr( bindec( $byte ) );
			}
		}
		return $out;
	}

	/**
	 * Code for a time step.
	 *
	 * @param string $secret Base32 secret.
	 * @param int    $step   Time step.
	 * @return string
	 */
	public static function code( $secret, $step ) {
		$key = self::base32_decode( $secret );
		if ( false === $key || '' === $key ) {
			return '';
		}
		$msg    = pack( 'N*', 0 ) . pack( 'N*', $step );
		$hash   = hash_hmac( 'sha1', $msg, $key, true );
		$offset = ord( $hash[19] ) & 0x0f;
		$num    = ( ( ord( $hash[ $offset ] ) & 0x7f ) << 24 )
			| ( ( ord( $hash[ $offset + 1 ] ) & 0xff ) << 16 )
			| ( ( ord( $hash[ $offset + 2 ] ) & 0xff ) << 8 )
			| ( ord( $hash[ $offset + 3 ] ) & 0xff );
		return str_pad( (string) ( $num % ( 10 ** self::DIGITS ) ), self::DIGITS, '0', STR_PAD_LEFT );
	}

	/**
	 * Current time step.
	 *
	 * @param int|null $time Unix time.
	 * @return int
	 */
	public static function step( $time = null ) {
		return (int) floor( ( null === $time ? time() : $time ) / self::PERIOD );
	}

	/**
	 * Check a code. Steps at or before $last_step are refused so a code
	 * can't be replayed.
	 *
	 * @param string $secret    Base32 secret.
	 * @param string $code      User input.
	 * @param int    $last_step Last accepted step.
	 * @return int|false The matching step, or false.
	 */
	public static function verify( $secret, $code, $last_step = 0 ) {
		$code = preg_replace( '/\D/', '', (string) $code );
		if ( strlen( $code ) !== self::DIGITS ) {
			return false;
		}
		$now = self::step();
		for ( $i = -self::WINDOW; $i <= self::WINDOW; $i++ ) {
			$step = $now + $i;
			if ( $step <= (int) $last_step ) {
				continue;
			}
			if ( hash_equals( self::code( $secret, $step ), $code ) ) {
				return $step;
			}
		}
		return false;
	}

	/**
	 * The otpauth:// URI authenticator apps scan.
	 *
	 * @param string $secret  Base32 secret.
	 * @param string $account Account label.
	 * @return string
	 */
	public static function uri( $secret, $account ) {
		$issuer = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		if ( '' === trim( $issuer ) ) {
			$issuer = (string) wp_parse_url( home_url(), PHP_URL_HOST );
		}
		$label = rawurlencode( $issuer ) . ':' . rawurlencode( $account );
		return 'otpauth://totp/' . $label . '?' . http_build_query(
			array(
				'secret'    => $secret,
				'issuer'    => $issuer,
				'algorithm' => 'SHA1',
				'digits'    => self::DIGITS,
				'period'    => self::PERIOD,
			),
			'',
			'&',
			PHP_QUERY_RFC3986
		);
	}

	/**
	 * Path of the key file kept outside the database.
	 *
	 * @return string
	 */
	public static function key_file() {
		return WP_CONTENT_DIR . '/anshield-key.php';
	}

	/**
	 * The dedicated encryption key: the ANSHIELD_SECRET_KEY constant if set
	 * in wp-config.php, otherwise a random key in wp-content/anshield-key.php.
	 * It is independent of the WordPress salts, so rotating the salts after
	 * an incident does not break two-factor. Neither lives in the database,
	 * so a database leak alone doesn't reveal 2FA secrets.
	 *
	 * @param bool $create Create the key file if missing.
	 * @return string|false 32-byte key.
	 */
	public static function dedicated_key( $create = true ) {
		static $key = null;
		if ( null !== $key ) {
			return $key;
		}
		if ( defined( 'ANSHIELD_SECRET_KEY' ) && strlen( (string) ANSHIELD_SECRET_KEY ) >= 32 ) {
			$key = hash( 'sha256', 'anshield-2fa|' . ANSHIELD_SECRET_KEY, true );
			return $key;
		}
		$file = self::key_file();
		if ( is_readable( $file ) ) {
			$raw = include $file;
			if ( is_string( $raw ) && strlen( $raw ) >= 40 ) {
				$key = hash( 'sha256', 'anshield-2fa|' . $raw, true );
				return $key;
			}
		}
		if ( $create && ! file_exists( $file ) && wp_is_writable( WP_CONTENT_DIR ) ) {
			$raw = bin2hex( random_bytes( 32 ) );
			$php = "<?php\n// Anderson Site Shield two-factor encryption key. Keep it with your backups; without it, two-factor must be reset for every user.\nreturn '" . $raw . "';\n";
			if ( false !== file_put_contents( $file, $php, LOCK_EX ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions
				@chmod( $file, 0640 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions
				$key = hash( 'sha256', 'anshield-2fa|' . $raw, true );
				return $key;
			}
		}
		$key = false;
		return $key;
	}

	/**
	 * Fallback key from the salts (only when no dedicated key can be kept).
	 *
	 * @return string 32 bytes.
	 */
	private static function salt_key() {
		return hash( 'sha256', 'anshield-2fa|' . wp_salt( 'auth' ) . '|' . wp_salt( 'secure_auth' ), true );
	}

	/**
	 * Encrypt a secret for storage.
	 *
	 * @param string $plain Secret.
	 * @return string
	 */
	public static function encrypt( $plain ) {
		$key    = self::dedicated_key();
		$prefix = $key ? 'v2:' : 'v1:';
		$key    = $key ? $key : self::salt_key();
		$nonce  = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
		return $prefix . base64_encode( $nonce . sodium_crypto_secretbox( $plain, $nonce, $key ) ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions
	}

	/**
	 * Decrypt a stored secret.
	 *
	 * @param string $stored Stored value.
	 * @return string|false
	 */
	public static function decrypt( $stored ) {
		if ( ! is_string( $stored ) || strlen( $stored ) < 4 ) {
			return false;
		}
		$prefix = substr( $stored, 0, 3 );
		if ( 'v2:' === $prefix ) {
			$key = self::dedicated_key( false );
		} elseif ( 'v1:' === $prefix ) {
			$key = self::salt_key();
		} else {
			return false;
		}
		if ( ! $key ) {
			return false;
		}
		$raw = base64_decode( substr( $stored, 3 ), true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions
		if ( false === $raw || strlen( $raw ) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ) {
			return false;
		}
		$nonce = substr( $raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
		$box   = substr( $raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
		return sodium_crypto_secretbox_open( $box, $nonce, $key );
	}
}
