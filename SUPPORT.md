# Getting help

| You want to… | Go here |
|---|---|
| Ask how something works, or get help with a problem on your site | The [WordPress.org support forum](https://wordpress.org/support/plugin/jat-site-shield/), once the plugin is live in the directory. Until then, open a [bug report](https://github.com/CptNope/JAT-Site-Shield/issues/new?template=bug_report.yml) and describe your question. |
| Report a bug in the plugin | A [bug report](https://github.com/CptNope/JAT-Site-Shield/issues/new?template=bug_report.yml) on GitHub |
| Suggest a feature | A [feature request](https://github.com/CptNope/JAT-Site-Shield/issues/new?template=feature_request.yml), after checking the [roadmap](ROADMAP.md) |
| Report a security problem | Privately, following [SECURITY.md](SECURITY.md). Never in public. |
| Get hands-on help locking down or cleaning up a site | [Jeremy Anderson Tech](https://jeremyanderson.tech/services/): [book a call](https://jeremyanderson.tech/book-a-call/) |

## Before you ask

Most questions are answered in one of these:

- **Locked out?** The [lockout table in the README](README.md#if-you-get-locked-out), or add `define( 'JATSS_SAFE_MODE', true );` to `wp-config.php`.
- **Behind Cloudflare?** The [free Cloudflare setup guide](docs/cloudflare.md) and **Site Shield → Settings → Network**.
- **Something else?** The FAQ in [readme.txt](readme.txt) and the [known limits](README.md#known-limits).

When you ask, include the output of `wp jat-shield status` if you can, or a screenshot of **Site Shield → Overview**. Never post passwords, backup codes, your custom login address or the contents of `wp-content/jatss-key.php`.

The plugin is free and support is given in spare time, so replies on the forum and GitHub may take a few days.
