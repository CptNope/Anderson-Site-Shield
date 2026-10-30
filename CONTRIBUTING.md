# Contributing to JAT Site Shield

Thanks for helping. Bug reports, ideas, documentation fixes and code are all welcome.

- **Found a security problem?** Don't open an issue. Follow [SECURITY.md](SECURITY.md).
- **Need help using the plugin?** See [SUPPORT.md](SUPPORT.md).
- **Want to suggest a feature?** Check the [roadmap](ROADMAP.md) first, then open a [feature request](https://github.com/CptNope/JAT-Site-Shield/issues/new?template=feature_request.yml).

Everyone taking part follows the [code of conduct](CODE_OF_CONDUCT.md).

## Reporting a bug

Use the [bug report form](https://github.com/CptNope/JAT-Site-Shield/issues/new?template=bug_report.yml). The most useful reports include:

- the plugin, WordPress and PHP versions (`wp jat-shield status` prints most of what's needed)
- whether the site is behind Cloudflare or another proxy, and what **Settings → Network** shows
- the steps to make it happen, and what you expected instead
- matching entries from **Site Shield → Activity log** and from `wp-content/debug.log`

Remove passwords, two-factor secrets, backup codes, the contents of `jatss-key.php`, and anything else private before posting.

## Setting up for development

You need PHP 7.4 or newer, a local WordPress 6.4+ install, and optionally [WP-CLI](https://wp-cli.org/). Any local setup works: [wp-env](https://developer.wordpress.org/block-editor/reference-guides/packages/packages-env/), LocalWP, or plain PHP with the [SQLite database integration](https://github.com/WordPress/sqlite-database-integration).

```bash
git clone https://github.com/CptNope/JAT-Site-Shield.git
ln -s "$PWD/JAT-Site-Shield" /path/to/wordpress/wp-content/plugins/jat-site-shield
wp plugin activate jat-site-shield
```

While you work, add `define( 'JATSS_SAFE_MODE', true );` to `wp-config.php` if you don't want lockouts and two-factor getting in your way. Turn it off before testing those features.

## Checks to run before a pull request

CI runs the first two on every pull request; please run all of them locally.

```bash
# 1. PHP syntax on every supported version you have
find . -name '*.php' -not -path './vendor/*' -print0 | xargs -0 -n1 php -l

# 2. PHP 7.4+ compatibility and WordPress security sniffs (same commands as CI)
composer global require wp-coding-standards/wpcs:^3 phpcompatibility/phpcompatibility-wp:"*"
phpcs --standard=PHPCompatibilityWP --runtime-set testVersion 7.4- \
  --exclude=PHPCompatibility.ParameterValues.NewTrimCharactersDefault \
  --extensions=php --ignore=vendor,assets .
phpcs --standard=WordPress-Extra \
  --sniffs=WordPress.Security.EscapeOutput,WordPress.Security.NonceVerification,WordPress.DB.PreparedSQL,WordPress.Security.ValidatedSanitizedInput \
  --extensions=php --ignore=vendor,assets .

# 3. WordPress's Plugin Check on the built zip (must report no errors or warnings)
bash bin/build-zip.sh
wp plugin install plugin-check --activate
wp plugin check jat-site-shield --include-experimental
```

Then test what you changed by hand, with `WP_DEBUG` and `WP_DEBUG_LOG` on, and confirm `debug.log` stays clean.

## Code guidelines

- **Prefixes:** PHP code lives in the `JATSiteShield` namespace. Options, user meta, transients, hooks, CSS classes and JavaScript globals start with `jatss_` or `jatss-`; constants start with `JATSS_`.
- **Security first:** check the capability and the nonce in every handler, sanitize input where it's read, escape output where it's printed, and use `$wpdb->prepare()` with `%i` for table names. Never trust request headers for an IP address except through `Request::ip()`.
- **No outside calls without disclosure.** Anything that contacts a server other than the site itself must be listed under *External services* in `readme.txt`, and must be opt-in unless it only fetches public data from WordPress.org.
- **Stay compatible:** PHP 7.4 syntax, WordPress 6.4 functions, and no Composer dependencies in the plugin itself.
- **Scripts and styles:** enqueue them; no inline `<script>` tags. Keep bundled libraries unminified and list their licenses.
- **Everything translatable:** wrap user-facing strings with the `jat-site-shield` text domain.
- **Plain language:** messages say what happened and what to do next, in sentence case, without jargon.
- **Fail safe:** if something can't be checked, such as a missing key or an unreachable checksum service, refuse or report it. Never quietly turn protection off.

## Pull requests

1. Fork the repository and create a branch from `main` (`fix/lockout-ipv6`, `feature/passkeys`).
2. Keep each pull request to one change, and update `readme.txt`, `README.md` and `CHANGELOG.md` when behaviour changes.
3. Fill in the pull request template, including how you tested it.
4. `main` is protected: a pull request needs passing CI before it can be merged.

Write commit messages in the imperative ("Block PHP in hidden uploads folders"), with a short body explaining why when it isn't obvious.

## Releasing (maintainers)

1. Bump the version in `jat-site-shield.php` (header and `JATSS_VERSION`) and `Stable tag` in `readme.txt`.
2. Add the release to `CHANGELOG.md` and to the changelog and upgrade notice in `readme.txt`.
3. Merge to `main`, then publish a GitHub release with a new tag such as `v1.0.3` (or push the tag). The release workflow checks that the three versions match, builds `jat-site-shield.zip`, attaches it to a GitHub release and, once the `SVN_USERNAME` and `SVN_PASSWORD` repository secrets are set, deploys it with the assets in `.wordpress-org/` to WordPress.org.

## License

By contributing, you agree that your contribution is licensed under the [GPL v2 or later](LICENSE), like the rest of the plugin.
