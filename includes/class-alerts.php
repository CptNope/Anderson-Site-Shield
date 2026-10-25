<?php
/**
 * Email alerts for serious events.
 *
 * @package AndersonSiteShield
 */

namespace AndersonSiteShield;

defined( 'ABSPATH' ) || exit;

/**
 * Emails serious events to the alert recipients, with a hourly cap so an
 * attack can't flood an inbox.
 */
class Alerts {

	const HOURLY_CAP = 10;

	/**
	 * Hook in.
	 */
	public function register() {
		add_action( 'anshield_event_logged', array( $this, 'maybe_send' ) );
	}

	/**
	 * Recipients: configured addresses, or the site admin email.
	 *
	 * @return array
	 */
	public static function recipients() {
		$list = trim( (string) Settings::get( 'alert_emails' ) );
		if ( '' === $list ) {
			return array( get_option( 'admin_email' ) );
		}
		return array_filter( array_map( 'trim', explode( ',', $list ) ) );
	}

	/**
	 * Send an email for an event when it is severe enough.
	 *
	 * @param array $event Stored event row.
	 */
	public function maybe_send( array $event ) {
		$min   = Settings::get( 'alert_min_severity' );
		$order = array_flip( Event_Log::SEVERITIES );
		if ( $order[ $event['severity'] ] < $order[ $min ] ) {
			return;
		}

		$bucket = 'anshield_alerts_' . gmdate( 'YmdH' );
		$sent   = (int) get_transient( $bucket );
		if ( $sent >= self::HOURLY_CAP ) {
			if ( self::HOURLY_CAP === $sent ) {
				set_transient( $bucket, $sent + 1, HOUR_IN_SECONDS );
				$this->send(
					__( 'Alert limit reached', 'anderson-site-shield' ),
					__( 'More security events happened this hour than the alert limit allows. Further emails are paused until the next hour. Check the activity log on the site for the full list.', 'anderson-site-shield' )
				);
			}
			return;
		}
		set_transient( $bucket, $sent + 1, HOUR_IN_SECONDS );

		$lines = array(
			$event['message'],
			'',
			sprintf( 'Site:     %s', home_url( '/' ) ),
			sprintf( 'Severity: %s', $event['severity'] ),
			sprintf( 'Event:    %s', $event['event_type'] ),
			sprintf( 'Time:     %s UTC', $event['created_at'] ),
			sprintf( 'User:     %s', '' !== $event['username'] ? $event['username'] : '-' ),
			sprintf( 'IP:       %s', $event['ip'] ),
			'',
			sprintf( 'Activity log: %s', admin_url( 'admin.php?page=anderson-site-shield-log' ) ),
		);
		$this->send( $event['message'], implode( "\n", $lines ) );
	}

	/**
	 * Send one email.
	 *
	 * @param string $subject Subject (site name is prefixed).
	 * @param string $body    Plain-text body.
	 */
	private function send( $subject, $body ) {
		$site = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		wp_mail(
			self::recipients(),
			sprintf( '[%s] Site Shield: %s', $site, wp_html_excerpt( $subject, 120, '…' ) ),
			$body
		);
	}
}
