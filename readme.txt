=== JAT Site Shield ===
Contributors: cptnope
Tags: security, two-factor, login security, hardening, activity log
Requires at least: 6.4
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Lock WordPress down: login lockouts, two-factor codes, core hardening, an activity log with email alerts, and file integrity checks.

== Description ==

JAT Site Shield hardens a WordPress site and keeps a record of what happens on it. It's built for agencies and freelancers who look after many sites: one plugin, safe defaults, and no account or outside service to sign up for.

JAT Site Shield is made by [Jeremy Anderson Tech](https://jeremyanderson.tech/), the "JAT" in the name. It pairs with [JAT Shell Scanner](https://wordpress.org/plugins/jat-shell-scanner/): Site Shield keeps attackers out, and the scanner checks whether one already got in.

= Login protection =

* Locks out an IP address after repeated failed logins, with a longer lockout for repeat offenders. IPv6 addresses are grouped by /64 so attackers can't rotate through them.
* Login and password-reset forms give the same answer whether or not an account exists, so they can't be used to find usernames.
* Optional custom login address. `wp-login.php` and `/wp-admin` return "Not Found" to logged-out visitors.
* An allowlist for your office IP, and a warning if the site is behind Cloudflare but every visitor shows Cloudflare's IP.

= Two-factor authentication =

* Six-digit codes from any authenticator app (1Password, Google Authenticator, Microsoft Authenticator, Authy and others), plus 10 single-use backup codes.
* Required by role. Administrators are required by default and must set it up before they can use the dashboard.
* Every login session records that it passed two-factor, so plugins that log people in another way can't skip it.
* Secrets are encrypted with a key kept outside the database.

= Hardening =

* Blocks XML-RPC (left on automatically if Jetpack needs it).
* Blocks username scanning through `?author=`, the REST API users endpoint, oEmbed and the users sitemap.
* Turns off the theme and plugin file editor.
* Blocks PHP in the uploads folder, with a one-click test to confirm it works on your server.
* Sends security headers and hides the WordPress version. HSTS and turning off application passwords are optional.

= Activity log and alerts =

* Records logins, failed logins, lockouts, two-factor events, new users, role changes, email and password changes, plugin and theme installs and updates, core updates, and changes to key settings such as the site address and admin email.
* Filter, search and export the log to CSV.
* Emails critical events, or warnings too, to the addresses you choose. At most 10 emails an hour, so an attack can't flood your inbox.

= File integrity =

* A daily scan compares WordPress core and every plugin from WordPress.org with the official checksums.
* Themes, must-use plugins and plugins from elsewhere are compared with the previous scan instead.
* Flags modified files, unknown PHP files, PHP files in uploads (hidden folders included) and stray PHP files in `wp-content`.
* Runs in small steps in the background, so large sites don't time out.

= Free, open source, no account =

Everything in the plugin is free. There is no paid version, no sign-up and no tracking. Development happens in the open on [GitHub](https://github.com/CptNope/Anderson-Site-Shield).

= Made by Jeremy Anderson Tech =

[Jeremy Anderson Tech](https://jeremyanderson.tech/) builds, secures and looks after WordPress sites. If you'd rather have someone lock down or clean up a site for you, [book a call](https://jeremyanderson.tech/book-a-call/) or see the [services](https://jeremyanderson.tech/services/).

= For developers =

* WP-CLI commands: `wp jat-shield status`, `login-url`, `lockouts`, `unlock`, `reset-2fa`, `scan` and `log`.
* Every event fires the `jatss_event_logged` action, so you can send events to your own monitoring system.

== Installation ==

1. In WordPress, go to **Plugins → Add New**, search for "JAT Site Shield", then install and activate it.
2. You'll be asked to set up two-factor for your administrator account. Scan the QR code with your authenticator app, enter the code, and save your backup codes in a password manager.
3. Open **Site Shield → Overview** and work through anything on the checklist that isn't green.

Recommended next steps:

* **Settings → Login protection:** turn on **Move the login page**, choose an address that isn't easy to guess, and bookmark it.
* **Settings → Hardening:** click **Test it now** under "Block PHP in the uploads folder".
* **Settings → Monitoring and alerts:** add the address that should receive alerts.
* If the site is behind Cloudflare, set **Visitor IP comes from** to Cloudflare.

== Frequently Asked Questions ==

= I'm locked out. How do I get back in? =

Add `define( 'JATSS_SAFE_MODE', true );` to `wp-config.php`. This pauses the custom login address, two-factor and lockouts while logging and hardening stay on. Remove it once you're back in. With WP-CLI you can also run `wp jat-shield login-url`, `wp jat-shield unlock <ip>` or `wp jat-shield reset-2fa <user>`. As a last resort, rename the plugin's folder over SFTP to deactivate it.

= I lost my phone and my backup codes. =

Another administrator can reset your two-factor from your user profile, or run `wp jat-shield reset-2fa <user>`. You'll set it up again at your next login.

= What is wp-content/jatss-key.php? =

It holds the key that encrypts two-factor secrets, created when you activate the plugin. Keep it in your backups and copy it when you move the site. If it's lost, every user's two-factor has to be reset. To manage the key yourself, add `define( 'JATSS_SECRET_KEY', '...at least 32 random characters...' );` to `wp-config.php` before anyone sets up two-factor.

= The PHP-in-uploads test says PHP still runs. =

Your server is probably nginx, which ignores `.htaccess` files. Ask your host to block PHP files in `wp-content/uploads`.

= My site is behind Cloudflare or a proxy. =

Set **Visitor IP comes from** to Cloudflare, or to the header your proxy uses. The header is only trusted when the request really comes from Cloudflare, a private network or an address you list under **Trusted proxies**, so it can't be faked.

= Visitors on my membership site get "Not Found" when they log in. =

With the custom login address on, login links your theme shows to logged-out visitors (such as "Log in to reply") still point to `wp-login.php`. On sites where visitors need to log in, either link to the new address or leave this feature off.

= Does it work with multisite? =

Yes, but the custom login address is turned off on multisite.

= Does it slow my site down? =

No. Nothing heavy runs on page loads. The file integrity scan runs once a day in the background, in small steps.

= Does it send any data to you? =

No. See "External services" below for the only outside requests it makes.

= Where do I report a bug? =

Use the [support forum](https://wordpress.org/support/plugin/jat-site-shield/). Security problems in the plugin itself: please report them privately through [GitHub](https://github.com/CptNope/Anderson-Site-Shield/security/advisories/new).

== External services ==

This plugin connects to WordPress.org for the file integrity scan. No personal data is sent.

* **WordPress.org core checksums API** (`https://api.wordpress.org/core/checksums/1.0/`). Used once a day during the scan, and when you click **Scan now**, to download the official checksums for your WordPress version. It sends your WordPress version and site language. This is the same service WordPress uses for its own `wp core verify-checksums` check.
* **WordPress.org plugin checksums** (`https://downloads.wordpress.org/plugin-checksums/`). Used during the same scan, once per installed plugin, to download that plugin's official checksums. It sends the plugin's slug and version number. You can turn this off with **Include WordPress.org plugins** in the settings.

Both are provided by WordPress.org: [Terms of service](https://wordpress.org/about/domains/), [Privacy policy](https://wordpress.org/about/privacy/).

The "Test it now" button for PHP in uploads sends one request from your site to its own uploads folder. It does not contact any outside service.

== Privacy ==

The activity log stores IP addresses, browser user agents and usernames for security events in your site's database. It is kept for 90 days by default; you can change this under **Settings → Monitoring and alerts**. Nothing is sent outside your site except the alert emails you set up. Suggested text for your privacy policy is added under **Settings → Privacy**.

== Screenshots ==

1. The overview: one verdict for the site, logins, hardening and files at a glance, and the protection checklist.
2. Settings for login protection, two-factor, hardening, alerts and network.
3. File integrity results with severity, the file, what's wrong and when it changed.
4. Two-factor setup with a QR code for any authenticator app.
5. The two-factor step on the login page.
6. The activity log with filters and CSV export.

== Changelog ==

= 1.0.0 =
* First release: login lockouts, generic login errors, custom login address, two-factor authentication with backup codes, hardening, activity log, email alerts, file integrity scanning and WP-CLI commands.

== Upgrade Notice ==

= 1.0.0 =
First release.

== Credits ==

The two-factor QR code is drawn with [qrcode-generator](https://github.com/kazuhikoarase/qrcode-generator) by Kazuhiko Arase, MIT license (bundled in `assets/vendor/`).

Built by [Jeremy Anderson Tech](https://jeremyanderson.tech/).
