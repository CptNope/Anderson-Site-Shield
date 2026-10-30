# Roadmap

Where JAT Site Shield is going, in rough order. Plans change as people use the plugin and as attacks change, so nothing here has a date. If something matters to you, say so in a [feature request](https://github.com/CptNope/JAT-Site-Shield/issues/new?template=feature_request.yml).

**How to read this:** **Now** is being built, **Next** is designed and comes after that, **Later** is planned but not designed yet. Every item has to pass the same bar: it stops a way WordPress sites really get broken into, and it doesn't slow the site down or bury you in false alarms.

## Released

### 1.0: the foundation
- Login lockouts with longer lockouts for repeat offenders, IPv6 grouping, and the same answer whether or not a username exists
- Optional custom login address
- Two-factor codes with backup codes, required by role, encrypted secrets, and checks on every session so other plugins can't skip it
- Hardening: XML-RPC, username scanning, file editor, PHP in uploads (with a live test), security headers, version hiding
- Activity log with CSV export and email alerts
- Daily file integrity scan against WordPress.org checksums, plus change tracking for themes, must-use plugins and custom plugins
- Automatic Cloudflare detection, a protection checklist, WP-CLI commands, and the [free Cloudflare setup guide](docs/cloudflare.md)

## Now

### 1.1: know when a plugin is vulnerable
Vulnerable plugins and themes are the most common way WordPress sites get broken into, and today Site Shield can't see them.
- **Vulnerability alerts:** match the installed versions of core, plugins and themes against a public vulnerability database, and alert when a fix is available. This will be opt-in and disclosed in the readme, because it means sending the list of installed plugins to that service.
- **Security-only automatic updates:** update a plugin automatically only when the new version fixes a known vulnerability.

### 1.1: protect against stolen sessions
- **Re-confirm before dangerous actions:** ask for a fresh two-factor code before installing a plugin or theme, creating or promoting an administrator, or changing an administrator's email. A stolen login cookie then can't take over the site.
- **Session list:** see where you're logged in, and log out everywhere.
- **New-device alerts:** email when an administrator logs in from a new browser or country.

## Next

### 1.2: logins that can't be phished
- **Passkeys** as a two-factor method, and optionally required for administrators.
- **Breached-password check:** refuse passwords that appear in known data breaches, using a privacy-preserving lookup that never sends the password itself (opt-in).
- **Stronger password rules** for administrators and editors.
- **Cloudflare Turnstile and honeypot fields** on login, registration, password reset and comment forms.

### 1.3: clean up, not just detect
- **One-click restore** of modified WordPress core files from the official package.
- **Quarantine with undo** for suspicious files, shared with [JAT Shell Scanner](https://github.com/CptNope/JAT-Shell-Scanner).
- **Database checks:** injected scripts in posts and settings, rogue scheduled tasks, and administrators added straight into the database.
- **Configuration audit:** file permissions on `wp-config.php`, exposed backups, `.git` folders and debug logs, and PHP versions past end of life.

### 1.4: tools for agencies
- **Settings profiles:** export a site's settings and import them on the next client site.
- **Monthly security report** for each client, by email or PDF.
- **Custom login address on multisite.**

## Later

### 2.0: the SOC connection
Connect every site to a central monitoring dashboard you host yourself.
- **Signed event sender:** sites push events and heartbeats to your collector over HTTPS. A stolen site key can send events but can't read or delete them.
- **Silence alerts:** a site that stops checking in is flagged, because a site going quiet is often the first sign of trouble.
- **Fleet dashboard on your phone,** with push alerts for critical events only.
- **Pull-only commands:** sites fetch signed policy and blocklists from the dashboard; the dashboard never needs a way into client sites. Destructive actions need your approval with two-factor.
- **Cross-site correlation:** one IP attacking several sites is blocked on all of them.

### Also being considered
- An early-loading firewall that can ship targeted protection for a newly announced vulnerability before the plugin or PHP is patched
- Translations through translate.wordpress.org
- An accessibility review of every screen

## Not planned

These are deliberate choices, not gaps:

- **A malware signature engine or full-site scan on every request.** It slows sites down and raises false alarms, and [JAT Shell Scanner](https://github.com/CptNope/JAT-Shell-Scanner) already does deep scanning.
- **A paid version, upsells or license keys.** Everything stays free.
- **Sending data anywhere by default.** Anything that contacts an outside service will be opt-in and disclosed.
- **Replacing Cloudflare or your host's firewall.** A plugin runs after the server has already accepted a request; flood protection belongs in front of the server. The [Cloudflare guide](docs/cloudflare.md) shows how.
