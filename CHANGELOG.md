# Changelog

All notable changes to JAT Site Shield. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the plugin uses [semantic versioning](https://semver.org/). The WordPress.org changelog in [readme.txt](readme.txt) is a shorter version of this file.

## [1.0.1]: 2026-10-30

### Fixed
- The QR code on the two-factor setup screen was missing from zips built from the GitHub repository (including the v1.0.0 GitHub release). The bundled QR library in `assets/vendor/` had been excluded by a `.gitignore` rule meant for Composer's `vendor/` folder. The manual setup key always worked.

### Added
- CI builds the plugin zip on every pull request and fails if a required file is missing from it.

## [1.0.0]: 2026-10-30

First release.

### Login protection
- Locks out an IP after repeated failed logins (5 in 15 minutes by default), with a 24-hour lockout after repeated lockouts. IPv6 addresses are grouped by /64.
- While an IP is locked out, password checks are skipped entirely, so attacks cost the server less.
- Login and password-reset forms give the same answer, and redirect the same way, whether or not an account exists.
- Optional custom login address. `wp-login.php`, `wp-signup.php` and logged-out `/wp-admin` return "Not Found", including `//wp-login.php` and other path tricks. Password-protected posts keep working.
- A per-username counter flags distributed attacks that per-IP lockouts can't stop, without locking out the account owner.

### Two-factor authentication
- Six-digit codes (RFC 6238) from any authenticator app, plus 10 single-use backup codes stored as hashes.
- Required by role; administrators by default. Users in required roles can't use the dashboard, AJAX, `admin-post.php` or the REST API until they enroll.
- Every login session records that it passed two-factor. Sessions created without the code step, for example by plugins that call `wp_set_auth_cookie()` directly, are ended and logged as critical. The `jatss_session_requires_2fa` filter allows trusted single sign-on plugins.
- Secrets are encrypted with a dedicated key in `wp-content/jatss-key.php`, or `JATSS_SECRET_KEY` in `wp-config.php`, so rotating the WordPress salts doesn't break them. A missing key refuses the login rather than skipping two-factor.
- Attempts are locked per user, so parallel requests can't reuse a code or get around the attempt limits. Codes can't be replayed.
- Works in the dashboard's session-expired login popup.

### Hardening
- Blocks XML-RPC (kept on when Jetpack needs it), username scanning through `?author=`, REST `/users`, oEmbed and the users sitemap, the theme and plugin editor, and PHP in uploads, with a live test that PHP really is blocked.
- Security headers, and optional HSTS.
- Hides the WordPress version by replacing it with a hash, so browsers and Cloudflare still fetch new files after updates.

### Monitoring
- Activity log for logins, two-factor, users, roles, plugins, themes, core updates and key settings, with filters, search and CSV export (protected against spreadsheet formula injection).
- Email alerts with an hourly cap, and a **Send a test alert** button.
- Daily file integrity scan: WordPress core and WordPress.org plugins against official checksums; themes, must-use plugins and other plugins against the previous scan; PHP files in uploads (hidden folders included) and in `wp-content`. Large folders are scanned in steps.
- Probe events are logged at most once an hour per IP, and low-severity events are capped per hour, so attacks can't fill the database.

### Networking
- Detects Cloudflare automatically. The visitor header is trusted only from Cloudflare's published ranges, private networks or listed trusted proxies. **Settings → Network** shows what each IP source reports.
- Warns when a Cloudflare header arrives through an untrusted proxy, and when Cloudflare connects to the server over plain HTTP.

### Everything else
- Overview with a single verdict, Logins / Hardening / Files tiles and a protection checklist.
- WP-CLI commands: `status`, `login-url`, `lockouts`, `unlock`, `reset-2fa`, `scan` and `log`.
- `JATSS_SAFE_MODE` recovery switch.
- Suggested privacy policy text. Uninstall removes all data, the two-factor key and the uploads rules.
- Passes WordPress's Plugin Check with no errors or warnings, and the WordPress security and PHP 7.4+ compatibility sniffs in CI.

[1.0.1]: https://github.com/CptNope/JAT-Site-Shield/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/CptNope/JAT-Site-Shield/releases/tag/v1.0.0
