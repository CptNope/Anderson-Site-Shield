# Security Assurance Roadmap — October 2026 Review

> **Proposal for maintainers, not a release commitment or a vulnerability advisory.**
>
> Scope: static review of public `main`-branch source and documentation of **JAT Site Shield 1.0.2** and selected related JAT Shell Scanner 1.6.0 files, performed 2026-10-31. No staging installation, exploit validation, external pentest, or verification of GitHub Actions run outcomes was conducted. Severity estimates below are **triage priorities**, not confirmed exploitability or CVSS ratings. Keep reproducible exploitation details in private security advisories per [SECURITY.md](../SECURITY.md).

This document adds a **security-assurance workstream** alongside the feature milestones in [ROADMAP.md](../ROADMAP.md). Its purpose is to make the protections testable and the evidence credible for users, agencies, enterprise buyers, and potential government customers. It **does not** assert government approval, FedRAMP/FIPS certification, NIST compliance, or suitability for sensitive federal operations.

## Executive summary

**Preserve and build upon:** modular WordPress architecture; capability and nonce checks on administrative actions; encrypted TOTP secrets and hashed backup codes; session-level second-factor marking; guarded, user-initiated remediation in the companion scanner; private vulnerability reporting; reproducible packaging; and existing lint/compatibility checks.

**Next priority:** verify proxy trust and IP attribution, add WordPress-level security integration tests, expand file-integrity coverage, and make CI/release evidence independently inspectable. These are more important than new features in a security-sensitive initial release.

### Finding register

| ID | Priority | Observation / evidence | Proposed outcome |
|---|---|---|---|
| SS-01 | High — verify first | [`Request::is_trusted_proxy()`](../includes/class-request.php) treats some private/reserved immediate peer IPs as trusted for selected forwarding headers. This assumes the upstream proxy strips hostile client headers; a misconfigured upstream can invalidate that assumption. | Restrict forwarded-header trust to explicitly configured trusted peers or verified Cloudflare edges; regression tests for proxy topologies. |
| SS-02 | High | [Site Shield CI](../.github/workflows/ci.yml) checks syntax, packaging, and PHP coding standards, but currently contains no WordPress integration suite exercising login, 2FA and access-control flows. | Add integration and adversarial-regression tests before claiming production authentication coverage. |
| SS-03 | Medium | [`File_Integrity::scan_baseline()`](../includes/modules/class-file-integrity.php) checks new/changed PHP files against a previous baseline but iterates current files only; deleted baseline entries do not appear to be reported. | Detect deleted files and report them distinctly, while suppressing expected update/removal noise. |
| SS-04 | Medium | [Event logs](../includes/class-event-log.php) and [file baselines](../includes/modules/class-file-integrity.php) are stored locally in WordPress tables/options. This is useful operationally but is not tamper-evident against a sufficiently privileged database attacker. | Define an optional, privacy-conscious off-site evidence sink with authenticated delivery, retention, and integrity validation. |
| SS-05 | Medium | [README](../README.md) displays a “Plugin Check: passing” badge, but [CI](../.github/workflows/ci.yml) does not currently run WordPress Plugin Check. A local pass may exist, but is not demonstrated in CI. | Add a reproducible Plugin Check job, report actual results, and make badges correspond to verified automation. |
| SS-06 | Medium | [CI](../.github/workflows/ci.yml) and [release workflow](../.github/workflows/release.yml) use mutable action refs (e.g. version tags/`stable`). | Pin third-party actions to reviewed full commit SHAs and use minimal job permissions and update automation. |
| SS-07 | Medium — validate | [TOTP](../includes/class-totp.php) depends on libsodium, stores a dedicated key in `wp-content` when possible, and has a salt fallback; [2FA](../includes/modules/class-two-factor.php) handles enrollment, recovery and application passwords. Complex dependencies deserve failure-mode testing, especially on multi-server/read-only deployments. | Check extension requirements, document key custody, and test fail-closed recovery/migration scenarios. |
| SS-08 | Cross-repository | Companion [JAT Shell Scanner fleet code](https://github.com/CptNope/JAT-Shell-Scanner/blob/main/includes/class-fleet.php) accepts `http://` hub URLs. HMAC signatures authenticate messages but do not encrypt report contents in transit. | Track **in the Shell Scanner repository**: require HTTPS for production remote hubs; gate any HTTP loopback test exception. |
| SS-09 | Assurance | No automated SBOM, release provenance, or independently verified security review was established during this source inspection. | Produce release attestations, maintain a threat model, and arrange independent testing; distinguish “documented” from “independently tested.” |

## Milestone A — Pre-release / next maintenance release

These are recommendations to evaluate before increasing public adoption. Coordinate with WordPress.org reviewers; **do not alter submitted plugin artifacts silently while review is pending**.

### A1. Proxy trust and identity correctness (SS-01)

- [ ] Document supported proxy topologies: direct hosting, Cloudflare direct, Cloudflare → trusted load balancer → origin, nginx → Apache, and multiple forwarded hops.
- [ ] Replace implicit blanket trust of private/reserved peer addresses with an explicit trusted-proxy allowlist. Default to the direct connection where no verified proxy is configured.
- [ ] Evaluate `X-Forwarded-For` **right-to-left through known trusted hops**; reject malformed addresses and never trust a client-supplied prefix by position alone.
- [ ] Verify `CF-Connecting-IP` only after confirming the immediate ingress path and header provenance; do not assume `CF-Connecting-IP === REMOTE_ADDR` proves Cloudflare involvement for feature decisions.
- [ ] Add integration cases for spoofed forwarded headers, unexpected CDN-to-origin routing, IPv4/IPv6, shared hosting, and proxy misconfiguration.
- [ ] Check lockout keys, exemptions, activity logs, and threat attribution use the *same* validated client-IP logic.
- [ ] Include a visible diagnostic warning when identity attribution cannot be trusted.

**Acceptance:** Unauthorized clients cannot choose arbitrary IP buckets via request headers in the tested supported topologies. Valid CDN/proxy deployments neither misattribute visitors nor trigger site-wide lockouts. Preserve rollback guidance.

### A2. Authentication and 2FA integration tests (SS-02, SS-07)

Build a disposable WordPress+PHP+database test matrix (supported PHP versions and at least the oldest/newest supported WordPress versions) that verifies:

- [ ] Failed-password thresholds, expiry, escalations, and successful-login reset.
- [ ] Username and password-reset enumeration protection.
- [ ] Enrolled administrators cannot obtain normal dashboard, cookie-authenticated REST, or AJAX access without completed 2FA.
- [ ] Direct `wp_set_auth_cookie()`, third-party login hooks and REST/application-password paths are handled intentionally.
- [ ] TOTP time-window validity, reuse rejection, backup-code single use, throttling, simultaneous requests and pending-token expiry.
- [ ] Mandatory enrollment; safe-mode recovery; admin-initiated reset with proper capability and CSRF checks.
- [ ] Missing/rotated key, read-only filesystem, missing libsodium, mismatched node keys and backup/restore behavior.
- [ ] wp-login/custom slug, registration, lost password, logout, multisite and caching/proxy compatibility.
- [ ] Admin POST and export actions reject users without the requisite capability or nonce.

**Acceptance:** CI runs the security test matrix and fails on regressions; test fixtures use no real credentials or customer data. A build with missing required crypto functionality must show a clear error and not silently weaken authentication.

### A3. File-integrity correctness (SS-03)

- [ ] Compare both directions of baseline vs. current PHP file lists; flag removals with a distinct code and severity.
- [ ] Add regression fixtures for created, modified, deleted, renamed, inaccessible, and symlinked PHP paths.
- [ ] Avoid false alarms for expected core/plugin/theme update and reinstall events.
- [ ] Explicitly document that this is **change detection**, not proof that baseline code is benign, and that some trees or types may not be included.
- [ ] Consider adding a scan summary of errors, permission failures and incomplete coverage.

**Acceptance:** Tests detect an unexpected removed baseline file; planned updates and inaccessible files produce accurate, separate statuses.

## Milestone B — CI, software supply chain and release evidence

### B1. Reproducible checks (SS-05, SS-06)

- [ ] Add official WordPress Plugin Check to CI against the **packaged zip**, not merely the checkout.
- [ ] Record exact WordPress/PHP versions and the tested artifact's SHA-256; fix or document warnings.
- [ ] Pin GitHub Actions to immutable reviewed commit SHAs; declare minimal workflow `permissions` and escalate permissions only where necessary for releases.
- [ ] Add static security analysis (e.g. CodeQL where compatible) and lint on changed and full PHP source.
- [ ] Add release consistency checks across plugin header, constant, `readme.txt` stable tag, changelog, and packaged contents.
- [ ] Make badges link to workflows or reports; remove unsupported “passing” claims.

**Acceptance:** A public CI run proves what was tested for a specific commit and release zip. Avoid expanding expensive matrix jobs unnecessarily; reserve deeper suites for scheduled or release gates where appropriate.

### B2. Release assurance artifacts (SS-09)

- [ ] Generate a CycloneDX or SPDX SBOM for first-party and bundled third-party components.
- [ ] Record dependency licenses, source, and versions; alert on new risky dependencies.
- [ ] Generate build provenance and checksums for each distributed zip; consider attestations/signatures supported by the release platform.
- [ ] Publish a brief, versioned threat model for authentication, file integrity, admin actions, and external integrations.
- [ ] Add a documented vulnerability triage/patch workflow, with clear supported versions and notification approach.
- [ ] Commission independent security testing of the 2FA/login and remote reporting paths; publish a sanitized summary of resolved findings.

**Acceptance:** A third party can trace a release artifact to a source commit, review its component inventory, and see which security claims were actually tested.

## Milestone C — Operational evidence and agency adoption

### C1. Trustworthy event telemetry (SS-04)

- [ ] Specify a minimal event schema (UTC timestamp, site ID, event type/severity, policy version, correlation ID).
- [ ] Make optional external transport HTTPS-only, authenticated, rate-limited and retry-safe. Ensure failures do not block WordPress requests.
- [ ] Prefer append-only server-side storage and integrity verification; define retention, access controls, and customer consent.
- [ ] Minimize PII; offer documented redaction of IPs, usernames, URLs and finding details. Do **not** enable external data transfer without explicit user configuration and disclosure.
- [ ] Test replay resistance, rotation/revocation, delivery outage recovery, clock skew and compromised-member containment.
- [ ] Produce sanitized sample incident timelines and monthly reports.

**Acceptance:** A compromised client cannot silently rewrite previously received events; administrators can account for delivery gaps and explain what information leaves each site.

### C2. Defensible field validation

- [ ] Run controlled pilot deployments on permissioned client/test environments across Apache/nginx, Cloudflare, Redis, multisite, and high-volume sites.
- [ ] Measure scanner runtime, CPU/memory impact, true-positive/false-positive rates with documented fixtures, lockout false positives and recovery time.
- [ ] Document tested hardening controls and explicit limits (e.g. nginx `.htaccess` cannot enforce PHP execution rules).
- [ ] Create redacted case studies that distinguish confirmed malicious indicators from hypotheses and alerts.
- [ ] Offer a coordinated disclosure/security contact for both plugins, and a standard incident response playbook.

**Acceptance:** An evaluator can reproduce key detection outcomes and inspect a known-limitations list without relying solely on feature descriptions.

## Cross-product follow-up: JAT Shell Scanner

This PR intentionally **does not modify** [JAT Shell Scanner](https://github.com/CptNope/JAT-Shell-Scanner). Open a separate ticket/PR there to:

1. Make `https://` mandatory for externally hosted fleet hubs (any local HTTP exception explicitly limited to trusted testing). HMAC signing **does not provide confidentiality**.
2. Validate member identity, key rotation, replay/window handling, oversized payloads, misconfigured reverse proxies, and compromised-member isolation with integration tests.
3. Reuse the existing strong CI pattern (syntax + WordPress integration + popular-plugin false-positive corpus) as a model for Site Shield. Keep test runtime and GitHub Actions consumption under control.
4. Extend its concise [SECURITY.md](https://github.com/CptNope/JAT-Shell-Scanner/blob/main/SECURITY.md) with supported versions, scope, and disclosure expectations.

## Optional enterprise / government buyer evidence (not certification)

Map security-engineering practices to **NIST SP 800-218 (SSDF)** as a *self-assessed evidence index*, not as a claim of government endorsement. Suggested evidence folders:

- **Prepare the organization:** named code/release owners, secure development policy, threat model and threat intake.
- **Protect software:** branch protections, reviewed PRs, minimal CI token privileges, release checksums/provenance, SBOM.
- **Produce well-secured software:** architecture decisions, authentication/proxy test matrix, least privilege, misuse-case tests.
- **Respond to vulnerabilities:** private intake, triage deadlines, advisories, emergency patch procedure, regression tests.

For procurement or partnership materials, report **measurable evidence**, e.g. completed independent assessment, tests by version, validated deployment counts, mean alert/response time and false-positive benchmarks. Do not infer federal contracting eligibility or investigative authority from a WordPress.org listing.

## Proposed implementation order

1. **Security test harness + proxy trust validation:** prioritize SS-01 and SS-02, ideally without changing behavior until the supported topology is proven.
2. **Small correctness release:** fix validated proxy defects and baseline deletion reporting; add missing-crypto fail-closed handling if testing confirms a gap.
3. **CI/release evidence:** run Plugin Check, pin actions, add reproducible packaged-artifact checks and SBOM.
4. **Operational assurance:** optional off-site evidence, pilot deployment, independent security review, then update external claims to match demonstrated results.
5. **Companion scanner:** track HTTPS-only hub transport and fleet tests separately in its own repository.

## Maintainer decisions

- Which supported hosting/proxy configurations should be guaranteed in v1.x?
- Should the security-assurance gates be completed before directory approval, immediately after approval, or as a dedicated 1.0.x hardening milestone?
- What is the supported behavior when libsodium or the dedicated secret key is unavailable?
- What telemetry may leave a site, if any, and who is the data controller?
- Should the companion scanner share a *schema* for monitoring events without coupling plugin release cycles?

---

### Source pointers

- Site Shield: [README](../README.md) · [roadmap](../ROADMAP.md) · [CI](../.github/workflows/ci.yml) · [release](../.github/workflows/release.yml) · [request/IP](../includes/class-request.php) · [TOTP](../includes/class-totp.php) · [2FA](../includes/modules/class-two-factor.php) · [file integrity](../includes/modules/class-file-integrity.php) · [event log](../includes/class-event-log.php) · [admin actions](../includes/admin/class-admin.php)
- Companion: [Shell Scanner fleet transport](https://github.com/CptNope/JAT-Shell-Scanner/blob/main/includes/class-fleet.php) · [scanner CI](https://github.com/CptNope/JAT-Shell-Scanner/blob/main/.github/workflows/ci.yml)
- Guidance (context, not a compliance attestation): [NIST SP 800-218 Secure Software Development Framework](https://csrc.nist.gov/pubs/sp/800/218/final) · [WordPress Plugin Check](https://wordpress.org/plugins/plugin-check/)

*Document status: proposed roadmap based on source review. Implementation, exploit confirmation, CI outcomes and review-team feedback remain to be verified.*
