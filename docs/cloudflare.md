# Protect a WordPress site with Cloudflare's free plan

Cloudflare sits in front of your site and filters traffic before it reaches your server. JAT Site Shield protects WordPress itself. Together they cover each other's gaps:

| Layer | Stops |
|---|---|
| **Cloudflare** (in front of the server) | Floods of requests, bursts of login attempts, scans for `.env` and backup files, PHP requests in uploads, XML-RPC abuse, known exploit patterns, and hides your server's real IP address |
| **JAT Site Shield** (inside WordPress) | Slow password guessing, logins without two-factor, username discovery, dangerous settings, and changed or planted files |

Setup takes 30 to 45 minutes. Everything below works on Cloudflare's **free** plan, and the free-plan limits are listed at the end.

> Menu names are from Cloudflare's dashboard in late 2026. If a name differs, search the dashboard for it.

## Before you start

- You need to be able to change the **nameservers** at your domain registrar (GoDaddy, Namecheap, IONOS and so on).
- Have your host's control panel open (on Cloudways: **Applications → your app**).
- Take a backup of the site, and make a note of your current DNS records, including email records.
- Install and activate JAT Site Shield first. It recognizes Cloudflare by itself.

## 1. Add the site to Cloudflare

1. Create a free account at [dash.cloudflare.com](https://dash.cloudflare.com), choose **Add a domain**, enter your domain and pick the **Free** plan.
2. Cloudflare imports your DNS records. Check them carefully against the copy you made:
   - **Proxied (orange cloud):** the records for the website itself, usually the root domain (`@`) and `www`.
   - **DNS only (grey cloud):** email (`MX` records, `mail.`, `autodiscover.`), FTP or SFTP, `cpanel.`, and anything that isn't a web page. Proxying these breaks email or file access.
3. At your registrar, replace the nameservers with the two Cloudflare gives you. The domain shows **Active** once the change has spread, usually within an hour but sometimes up to 24.

**Edge case: your server's IP may already be public.** Cloudflare only hides the server if attackers don't already know its address. Old DNS history sites, emails sent from the server and grey-cloud subdomains on the same server can all reveal it. Step 4 makes the server refuse visitors who don't come through Cloudflare, which closes that gap.

## 2. Encrypt the whole connection

Open **SSL/TLS** for the domain.

1. **Give the server a certificate Cloudflare trusts.** Choose one:
   - Keep your host's free Let's Encrypt certificate. This is the easiest, and it works with step 2.
   - Or create a free **Origin Certificate** under **SSL/TLS → Origin Server → Create Certificate**, valid for up to 15 years, and install it on the server. On Cloudways: **SSL Certificate → I have my own certificate**. See [Cloudways' guide](https://support.cloudways.com/en/articles/5130554-how-to-configure-cloudflare-origin-certificate).
2. Set the encryption mode to **Full (strict)**.
   - **Never use "Flexible".** In Flexible mode, Cloudflare talks to your server over plain HTTP. WordPress then sees every page as insecure, which causes redirect loops and drops the secure flag from login cookies. JAT Site Shield's checklist warns you if this happens ("HTTPS all the way to the server").
3. Under **SSL/TLS → Edge Certificates**, turn on:
   - **Always Use HTTPS**
   - **Minimum TLS Version: 1.2**
   - **TLS 1.3**
   - **Automatic HTTPS Rewrites**
4. Wait for HSTS until the whole site has worked over HTTPS for a few days. Then turn it on in one place only: either Cloudflare's **HSTS** setting, or **Send HSTS** in Site Shield → Settings → Hardening.

**Edge case: redirect loops.** If you get a loop after this step, two things are probably both forcing HTTPS: a host setting or plugin that redirects to HTTPS while Cloudflare is still in Flexible mode. Switch Cloudflare to Full (strict) and keep only one redirect.

## 3. Make sure WordPress sees real visitor IPs

Behind Cloudflare, every visit reaches your server from a Cloudflare address. JAT Site Shield detects this automatically and reads the real visitor IP from Cloudflare's `CF-Connecting-IP` header. It only trusts that header when the connection really comes from Cloudflare's published IP ranges, so it can't be faked.

To check it:

1. Open **Site Shield → Settings → Network**.
2. The **This request** table shows what each source reports. The last row, **Site Shield uses**, should be **your own public IP** (search "what is my IP" to compare) with "(through Cloudflare)" after it.
3. If the last row shows a private address such as `127.0.0.1` or `10.x.x.x`, a web server on the same machine sits between Cloudflare and WordPress. This is common on stacks that run nginx in front of Apache. Add that address under **Trusted proxies** and save.

Without this, every visitor would share one address, and a handful of wrong passwords from anyone would lock out everyone. Site Shield shows a warning at the top of the dashboard if it spots this.

## 4. Lock the server to Cloudflare

This is the step most guides skip. Without it, anyone who finds your server's IP can go around Cloudflare. Pick whichever your host supports:

- **Authenticated Origin Pulls (free).** Cloudflare presents a client certificate on every request, and your server refuses requests without it.
  - Turn it on under **SSL/TLS → Origin Server → Authenticated Origin Pulls**. Your server then has to check the certificate: on Cloudways, enabling it alongside a Cloudflare Origin Certificate is covered in the guide above, and on your own server see [Cloudflare's setup steps](https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/set-up).
  - The default (global) certificate only proves a request came through *some* Cloudflare account. To prove it came through yours, use the **zone-level** option with your own certificate.
- **Firewall allowlist.** If your host lets you edit the server firewall, allow ports 80 and 443 only from [Cloudflare's IP ranges](https://www.cloudflare.com/ips/), and recheck the list every few months.
- **Cloudflare Tunnel (free, for VPS owners).** The server makes an outbound connection to Cloudflare and needs no open web ports at all.

**Check it:** from your own computer, run `curl -sk -o /dev/null -w "%{http_code}\n" --resolve yourdomain.com:443:YOUR.SERVER.IP https://yourdomain.com/`. A refused connection or an error means the server is locked. A `200` means it still answers directly.

## 5. Add five firewall rules

The free plan includes **5 custom rules**. Go to **Security → Security rules → Create rule → Custom rules**, and for each rule choose **Edit expression** and paste the expression.

Replace `example.com` with your domain and `/your-login-address/` with the login address set in Site Shield. Run `wp jat-shield login-url` to see it, and keep the trailing slash if your permalinks use one. If you haven't moved the login page, use `/wp-login.php` instead.

**Rule 1: Block XML-RPC.** Action: **Block**.
```
(http.request.uri.path eq "/xmlrpc.php")
```
Skip this rule if the site uses Jetpack or the WordPress mobile app with a password. Site Shield already blocks XML-RPC inside WordPress, but this rule stops the traffic before it costs your server anything.

**Rule 2: Block requests for secret and backup files.** Action: **Block**.
```
(http.request.uri.path contains "/.env") or (http.request.uri.path contains "/.git") or (http.request.uri.path contains "wp-config") or (http.request.uri.path eq "/wp-content/debug.log") or (ends_with(lower(http.request.uri.path), ".sql")) or (ends_with(lower(http.request.uri.path), ".bak")) or (ends_with(lower(http.request.uri.path), ".zip") and starts_with(http.request.uri.path, "/wp-content/") and not starts_with(http.request.uri.path, "/wp-content/uploads/"))
```

**Rule 3: Block PHP in uploads.** Action: **Block**.
```
(starts_with(http.request.uri.path, "/wp-content/uploads/") and (ends_with(lower(http.request.uri.path), ".php") or ends_with(lower(http.request.uri.path), ".phtml") or ends_with(lower(http.request.uri.path), ".phar")))
```
Site Shield writes the same rule for Apache and LiteSpeed. This one also covers nginx servers, which ignore that file.

**Rule 4: Challenge the login page and dashboard for everyone but you.** Action: **Managed Challenge**.
```
((http.request.uri.path eq "/your-login-address/") or (http.request.uri.path eq "/wp-login.php") or (starts_with(http.request.uri.path, "/wp-admin/") and http.request.uri.path ne "/wp-admin/admin-ajax.php" and http.request.uri.path ne "/wp-admin/admin-post.php")) and not ip.src in {203.0.113.10}
```
- Replace `203.0.113.10` with your office or home IP. Separate several with spaces, and use `{}` brackets even for one address.
- Real people pass the challenge once per browser session, usually with no puzzle to solve. Bots don't get through.
- If your IP changes often, drop the `and not ip.src in {...}` part.

**Rule 5: Challenge logins using a leaked password.** Action: **Managed Challenge**.
```
(http.request.method eq "POST" and cf.waf.credential_check.password_leaked)
```
Cloudflare's leaked credentials check is on by default on the free plan. This rule turns its result into a challenge, so attackers replaying passwords from data breaches are stopped. People with weak reused passwords get a challenge too, and should change those passwords.

> **Order matters.** Rules run top to bottom. If you add an allow rule later (for example **Skip** for an uptime monitor's IP), put it first.

## 6. Add one rate limiting rule

The free plan includes **1 rate limiting rule**. It counts per IP over a fixed 10-second window and blocks for 10 seconds. That's short, but it stops the bursts that brute-force tools send. Site Shield's lockouts handle the slow, patient attacks.

Go to **Security → Security rules → Create rule → Rate limiting rules**:

- **Name:** Login bursts
- **Expression:**
  ```
  (http.request.method eq "POST" and (http.request.uri.path eq "/your-login-address/" or http.request.uri.path eq "/wp-login.php"))
  ```
- **When rate exceeds:** 5 requests per 10 seconds
- **Action:** Block
- **Duration:** 10 seconds

## 7. Bots

- **Bot Fight Mode** (**Security → Settings**, then filter for bot traffic) challenges known bad bots across the whole site.
  - On the free plan it **can't have exceptions**, and custom rules can't skip it.
  - Turn it on for brochure and blog sites.
  - Leave it **off** for sites that receive automated traffic you need: WooCommerce stores (payment notifications from Stripe or PayPal), sites with Zapier or other integrations, headless sites and APIs, and sites watched by uptime monitors.
  - If something stops working after you turn it on, check **Security → Events**, then turn it off.
- **Block AI bots** is optional. Turn it on if your dashboard offers it and you don't want AI crawlers copying your content.
- **Turnstile** is Cloudflare's free, privacy-friendly CAPTCHA. Rule 4 already protects the login page. For comment and contact forms, add it with a Turnstile plugin from the WordPress directory.

## 8. Caching without breaking logins

Out of the box, Cloudflare caches images, CSS and JavaScript, but not pages. That's safe, so leave it alone if you can.

If you add a **Cache Rule** that caches whole pages ("Cache everything"), or use Automatic Platform Optimization, make sure these are **never cached**:

- `/wp-admin/`, `/wp-login.php`, your login address, `/wp-json/` and `/xmlrpc.php`
- any request with a cookie containing `wordpress_logged_in`, `wp-postpass` or `comment_author`
- cart, checkout and account pages if you run a store

A cached login page or two-factor step can show one visitor's page to another, or simply stop logins from working.

Also turn **Rocket Loader off** (**Speed → Optimization**). It rewrites how JavaScript loads and can break the dashboard, the two-factor QR code and page builders.

When you update WordPress, purge Cloudflare's cache if anything looks stale. Site Shield's "Hide the WordPress version" option keeps a version-specific code on CSS and JavaScript files, so browsers still fetch the new files after an update.

## 9. Check that it all works

1. The site loads over `https://` with no browser warnings.
2. **Site Shield → Overview:** "Cloudflare in front of the site" is green, and there's no "HTTPS all the way to the server" warning.
3. **Site Shield → Settings → Network:** the last row shows your own IP.
4. `https://yourdomain.com/xmlrpc.php` shows a Cloudflare block page (if you used rule 1).
5. `https://yourdomain.com/.env` shows a Cloudflare block page.
6. Logging in from a phone on mobile data (a different IP) shows a brief Cloudflare check before the login page (rule 4).
7. The `curl --resolve` test in step 4 can't reach the server directly.
8. **Security → Events** in Cloudflare lists the blocked and challenged requests.

## If something goes wrong

| Problem | Likely cause | Fix |
|---|---|---|
| "Too many redirects" | Flexible SSL, or two HTTPS redirects | Set SSL/TLS to **Full (strict)**, and keep one redirect (Cloudflare's **Always Use HTTPS**) |
| Email stopped arriving | Mail records were proxied | Set `MX`, `mail` and `autodiscover` records to **DNS only** |
| Everyone gets locked out at once | Site Shield sees one shared IP | Follow step 3. Unlock with `wp jat-shield unlock all` |
| You're stuck on a challenge | Rule 4, and your IP changed | Add your new IP to rule 4, or pause the rule. In an emergency, **Overview → Pause Cloudflare on Site** |
| Payments or webhooks stopped | Bot Fight Mode or rule 4 | Turn off Bot Fight Mode; find the blocked requests in **Security → Events** |
| Dashboard buttons or QR code don't work | Rocket Loader | Turn Rocket Loader off |
| A plugin or app can't log in | Rule 1 blocks XML-RPC | Use an application password over the REST API, or remove rule 1 |
| Site Shield shows Cloudflare IPs in the log | Rare server setups | Step 3, and add the address shown to **Trusted proxies** |

**Under attack right now?** Turn on **I'm Under Attack mode** (**Overview** or **Security → Settings**). Every visitor gets a short check before the site loads. Turn it off once the attack stops, because it also slows real visitors.

## Free-plan limits worth knowing

| Feature | Free plan |
|---|---|
| Custom firewall rules | 5, all actions except Log; no regular expressions |
| Rate limiting rules | 1, counted per IP over 10 seconds; Block for 10 seconds |
| Managed WAF rules | The Free Managed Ruleset, on by default |
| Leaked credentials detection | On by default (password-only check) |
| Bot protection | Bot Fight Mode on/off, no exceptions |
| Turnstile, Origin Certificates, Authenticated Origin Pulls, Tunnel | Free |

If you outgrow these, Cloudflare Pro adds the full managed WordPress rules, longer rate-limit windows and bot exceptions. On Cloudways, its Cloudflare Enterprise add-on is another option.

## Sources

- [Cloudflare: custom rules](https://developers.cloudflare.com/waf/custom-rules/) (5 rules on Free, all actions except Log, no regex)
- [Cloudflare: stop account takeover attacks](https://developers.cloudflare.com/use-cases/solutions/stop-account-takeover-attacks/) (free rate limiting, leaked credentials)
- [Cloudflare: stop malicious bots](https://developers.cloudflare.com/use-cases/solutions/stop-malicious-bots/) (Bot Fight Mode behaviour)
- [Cloudflare: Authenticated Origin Pulls](https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/)
- [Cloudflare: restoring original visitor IPs](https://developers.cloudflare.com/support/troubleshooting/restoring-visitor-ips/restoring-original-visitor-ips/)
- [Cloudflare: IP ranges](https://www.cloudflare.com/ips/)
- [Cloudways: Cloudflare Origin Certificate](https://support.cloudways.com/en/articles/5130554-how-to-configure-cloudflare-origin-certificate)

---

Part of [JAT Site Shield](https://github.com/CptNope/JAT-Site-Shield) by [Jeremy Anderson Tech](https://jeremyanderson.tech/).
