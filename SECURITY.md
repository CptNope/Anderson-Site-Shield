# Security policy

JAT Site Shield is a security plugin, so problems in it matter. Thank you for reporting them responsibly.

## Reporting a vulnerability

**Please don't open a public issue, discussion or support-forum post for a security problem.**

Report it privately through GitHub: on this repository, go to **Security → Report a vulnerability**, or use [this link](https://github.com/CptNope/JAT-Site-Shield/security/advisories/new). If you can't use GitHub, email **info@jeremyanderson.tech** with "JAT Site Shield security" in the subject.

Please include:

- the plugin version, and the WordPress and PHP versions
- what an attacker can do, and what they need first (a logged-out visitor, a subscriber account, an administrator, access to the server)
- step-by-step instructions or a proof of concept, against a test site only
- any suggested fix

## What happens next

- You'll get a reply acknowledging the report, normally within a few business days.
- The problem is confirmed and fixed in a private fork, and the fix is released to WordPress.org and GitHub.
- A GitHub security advisory is published after the fix is out, crediting you unless you'd rather stay anonymous. A CVE is requested where appropriate.
- Please keep the details private until the fixed version is released.

There is no paid bug bounty.

## Supported versions

| Version | Security fixes |
|---|---|
| 1.0.x (latest) | Yes |
| Older | Update to the latest version |

## In scope

Anything that weakens the protection the plugin promises, for example:

- getting around two-factor, lockouts or the custom login address
- faking a visitor IP to dodge or abuse lockouts
- revealing the hidden login address or two-factor secrets
- cross-site scripting, request forgery, SQL injection or missing permission checks in the plugin's screens and actions
- tampering with or hiding activity log entries

## Out of scope

- Weaknesses in WordPress itself, other plugins or the server. Report those to their maintainers.
- Attacks that need administrator access or file access to the site, unless the plugin claims to defend against them.
- Missing hardening that the plugin doesn't claim to provide. Suggest those as a [feature request](https://github.com/CptNope/JAT-Site-Shield/issues/new?template=feature_request.yml).
- Denial of service through sheer request volume. That belongs in front of the server (see the [Cloudflare guide](docs/cloudflare.md)).

## Safe harbor

Good-faith research on your own sites or test installs, following this policy, won't lead to any complaint or legal action from Jeremy Anderson Tech. Don't access other people's data or sites, and don't degrade services for others.
