## What this changes

<!-- One or two sentences. Link the issue it fixes, e.g. "Fixes #12". -->

## Why

<!-- The attack it stops, the bug it fixes, or the problem it solves. -->

## How I tested it

<!-- WordPress and PHP versions, single site or multisite, behind Cloudflare or not, and the steps you followed. -->

## Checklist

- [ ] `php -l` passes and CI is green
- [ ] Plugin Check reports no errors or warnings on the built zip
- [ ] Capabilities, nonces, sanitizing and escaping are in place for anything new
- [ ] No new outside requests, or they're listed under *External services* in `readme.txt` and are opt-in
- [ ] New strings use the `jat-site-shield` text domain
- [ ] `readme.txt`, `README.md` and `CHANGELOG.md` are updated if behaviour changed
- [ ] Tested with `WP_DEBUG` on, and `debug.log` stays clean
