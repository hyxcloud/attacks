# Threat Disclosure — Multi-Vector WordPress Backdoor & SEO-Cloaking Persistence Framework

**Publisher:** Hyx Security Research (CDN / WAF)
**Document type:** Customer research advisory
**Reference ID:** HYX-TR-2026-0803
**TLP:** CLEAR (may be redistributed freely; adjust to your programme's needs)
**Date:** 2026-08-03
**Analysis baseline:** WordPress 7.0.2 core, **no plugins and no themes installed**
**Audience:** Site operators and hosting teams — particularly those **not** protected by Hyx edge/WAF who need to block this threat on their own infrastructure

---

## 1. Purpose and scope

Hyx has developed and deployed server-side and edge block patterns that neutralise this threat for customers behind our WAF/CDN. This document is published so that operators **who do not use Hyx protection** can understand the threat and implement equivalent controls on their own stack.

This is a **defensive advisory**. It documents identification, classification, behaviour, indicators of compromise (IOCs), detection, blocking, and remediation. It intentionally contains **no offensive detail** — no payload source, no deobfuscation routines, and nothing that would help reproduce or operate the malware.

The analysis environment was a **clean WordPress 7.0.2 core install with no third-party plugins or themes**. This is significant: every artefact described below is **attacker-introduced**, not a modification of any legitimate extension. The framework is fully self-contained post-compromise persistence — it does not depend on, or exploit, any installed plugin or theme to operate once present on disk.

---

## 2. Executive summary

The threat is a **modular, self-healing WordPress compromise framework** combining two operational payloads that were observed deployed together:

1. **A remote-controlled SEO-cloaking / redirect backdoor** — a thin loader that proxies content live from attacker command-and-control (C2) on every request, serving spam pages to search crawlers and redirecting real visitors.
2. **A full remote-access backdoor** — disguised as a plugin, it beacons to C2, **creates a hidden administrator account**, **forges valid WordPress authentication sessions and exfiltrates them** (allowing credential-less admin login from anywhere), removes competing malware, hides itself from the WordPress UI, injects remote scripts into pages, and persists through numerous independent footholds.

The framework's defining characteristic is **redundant, self-healing persistence**: it stages multiple copies of itself and multiple auto-execution hooks (must-use plugin, `wp-config` include, `auto_prepend_file` directives, database options, shared memory, ZIP archives, and an object-cache drop-in). Removing any single component causes the others to regenerate it on the next request. **Partial cleanup fails.**

This activity aligns with a well-documented, actively-tracked family of WordPress backdoors reported through 2025 (see §12).

---

## 3. Attack classification

This is not a single technique but a stack of them. The framework exhibits the following attack classes simultaneously:

| Class | Present as |
|---|---|
| **Backdoor / Remote Access** | C2-driven command execution; credential-less admin access via forged sessions |
| **Persistence (redundant/self-healing)** | Multiple auto-run hooks and staged copies that regenerate each other |
| **Privilege persistence** | Hidden administrator account creation; auth-cookie forgery |
| **SEO spam / cloaking** | Crawler-versus-visitor content differentiation served from C2 |
| **Malicious redirection** | Attacker-controlled 301 redirects of real visitors |
| **Client-side injection** | Off-domain `<script>` injected into rendered pages |
| **Defense evasion / anti-forensics** | UI self-hiding, code obfuscation, competitor-malware removal, magic-parameter gating |
| **Data exfiltration** | Session cookies and environment data transmitted to C2 |

MITRE ATT&CK mapping (indicative): T1505.003 (Server Software Component: Web Shell), T1136.001 (Create Account: Local), T1556 (Modify Authentication Process), T1554 (Compromise Host Software Binaries / drop-ins), T1027 (Obfuscated Files or Information), T1620 (Reflective/loader execution), T1071.001 (Application Layer Protocol: Web), T1070 (Indicator Removal).

---

## 4. Components observed

Five distinct artefacts were recovered. Each is attacker-introduced; none is part of WordPress core or any legitimate plugin/theme.

| # | Role | Description |
|---|---|---|
| 1 | **Cloaking loader** | Self-contained script that, on every request, packages request metadata and fetches live content from C2, then serves crawler spam / visitor redirects based on C2 instructions. |
| 2 | **`phar://` loader** | One-line stub that executes PHP hidden inside a ZIP archive in the uploads directory via the `phar://` stream wrapper — evades scanners that only inspect `.php` files. |
| 3 | **Injected include stub** | A single line (typically inserted into `wp-config.php`, `index.php`, or a core file) that conditionally includes a hidden dot-prefixed PHP file from `wp-content`. |
| 4 | **Self-healing reinstaller** | Obfuscated routine that rebuilds the primary backdoor as a **must-use plugin** whenever it is missing or truncated, drawing from several redundant local source copies and invalidating the PHP opcode cache so the rebuilt copy runs immediately. |
| 5 | **Primary backdoor "plugin"** | The main payload, carrying a fake plugin header. Implements C2 beaconing, hidden-admin creation, session forgery/exfiltration, self-hiding, competitor removal, script injection, and the full redundant persistence surface. |

---

## 5. Method of attack (kill chain)

**Initial access (inferred).** Because the analysis baseline had **no plugins or themes**, the usual vulnerable-extension vector was not available in this environment. For a clean-core system, the realistic entry vectors are: **compromised credentials** (FTP/SFTP/SSH, hosting panel, or `wp-admin`), a **compromised hosting account** on shared infrastructure, or **direct file write** through a server-level weakness. Operators should treat the entry vector as unknown-but-open until proven otherwise.

**Execution.** The framework relies on WordPress and PHP auto-execution mechanisms so that no attacker request is needed to run it:
- **Must-use plugins** (`wp-content/mu-plugins/`) load automatically on every request and cannot be deactivated from the dashboard.
- **`auto_prepend_file`** (via `.htaccess`, `.user.ini`, or `php.ini`) executes a chosen PHP file before *every* request, independent of WordPress.
- A **`wp-config` / core include** line pulls in a hidden payload file on load.
- An **`object-cache.php` drop-in** in `wp-content` is auto-loaded by WordPress ahead of the built-in cache. (Legitimately this file bridges WordPress to Redis/Memcached; here the mechanism is abused for execution.)

**Payload A — cloaking/redirect.** On each request the loader fingerprints the visitor's User-Agent to decide crawler-versus-human, packages host/URI/referrer/protocol, and retrieves live content from C2 over an outbound HTTP call. A control keyword in the C2 response selects the response mode: serve injected spam HTML, serve a fake sitemap or `robots.txt`, issue an attacker-controlled 301 redirect, or spoof a 404/500. Because payloads are fetched live, the operator changes them without touching the site again. The loader also overwrites `robots.txt` to maximise crawl of the spam, and honours a magic URL string used as a preview/liveness check.

**Payload B — full backdoor.** The primary "plugin" beacons to C2, retrieves a command-server list and a symmetric key, and acts on returned commands. It creates a hidden administrator, **forges cryptographically valid authentication cookies** using WordPress's own session APIs and exfiltrates them (yielding credential-less admin login for the cookie lifetime), deletes competing malware, hides itself across the admin UI, injects a remote `<script>` into rendered pages, and serves attacker content when a per-site magic GET parameter is present.

**Persistence & self-healing.** Both payloads are staged redundantly (see §6). The reinstaller and the primary backdoor continuously re-create missing components and re-apply auto-run hooks, so any incomplete removal is reversed on the next request.

---

## 6. Persistence surface (the critical defensive detail)

This is the reason partial cleanup fails. The framework maintains **independent, mutually-regenerating footholds**. Treat this as the checklist of places to inspect and remove **simultaneously**.

| Foothold | Location / form |
|---|---|
| Must-use plugin | `wp-content/mu-plugins/` (auto-loaded, not dashboard-deactivatable) |
| Redundant plugin source | `wp-content/plugins/<name>/` used only as a rebuild source |
| Injected include line | `wp-config.php`, `index.php`, or a core/theme file |
| Hidden dot-file payload | `wp-content/.<hex>.php` (dot-prefixed to evade listing) |
| Cache-dir copy | `wp-content/cache/<hex>.php` |
| ZIP archive copies | `wp-content/<hex>.zip`, `wp-content/uploads/<hex>.zip` |
| `phar://` loader | Stub executing PHP inside an uploads ZIP |
| `auto_prepend_file` directive | `.htaccess`, `.user.ini`, or `php.ini` |
| Object-cache drop-in | `wp-content/object-cache.php` |
| Database options | Encrypted/obfuscated payload + config stored in `wp_options` |
| Shared memory | A resident copy held in SysV/`shmop` shared memory that can rewrite deleted files |
| Rogue admin + forged sessions | `wp_users` / `wp_usermeta` and valid session cookies already issued |

---

## 7. Capabilities summary

- **Credential-less admin access** via forged, cryptographically valid session cookies (no new login required for the cookie lifetime).
- **Hidden administrator account**, filtered out of the users list and user-count so it is invisible in the dashboard.
- **Self-concealment**: hides its own plugin from the plugins list, suppresses its update checks, and removes itself from user enumeration.
- **Competitor eviction**: detects and deletes other malware/backdoors to monopolise the host.
- **SEO cloaking + redirection**: crawler spam and attacker-controlled visitor redirects driven live from C2.
- **Client-side script injection**: off-domain `<script>` inserted into page output.
- **Magic-parameter content delivery**: serves attacker content when a per-site-derived GET parameter is present.
- **Anti-removal / self-healing** across the full persistence surface above.

---

## 8. Evasion & obfuscation techniques (described, not reproduced)

Understanding the *techniques* helps tune detection without needing the code:

- **Function-name obfuscation** — sensitive PHP function names are assembled at runtime (character-by-character and via a custom substitution map) so static signature/`grep` scanning for calls like the file/exec primitives misses them.
- **ROT13 + URL-encoding** of C2 hostnames to defeat casual inspection and simple scanners.
- **Layered encoding** of stored payloads (base64 over gzip/deflate, plus XOR with a per-site key) held in the database and archives.
- **Non-`.php` execution** via `phar://` streams inside ZIP archives and via the object-cache drop-in, bypassing scanners that only read `.php` files.
- **Dot-prefixed filenames** and cache/uploads placement to avoid directory listings and casual review.
- **UI self-hiding** so dashboard audits (plugins, users, updates) do not reveal it.
- **Magic-string / magic-parameter gating** so functionality only triggers for the operator, reducing incidental discovery.

None of these is novel individually; the risk is their **combination** with redundant persistence.

---

## 9. Indicators of Compromise (IOCs)

> **Caveat:** Hostnames, filenames, and the magic parameter **rotate between deployments**. The **structural and behavioural** indicators (§6, §7, §10) are more durable than the literal strings below. Use both.

### 9.1 Network — C2 (as observed)

Command-and-control endpoint path:
```
/super6.php        (queried with request metadata as URL parameters)
```

C2 hostnames observed (all share the sub-label `3061-link211`):
```
3061-link211.skyhooks.top
3061-link211.vivyne.xyz
3061-link211.ecovisios.xyz
3061-link211.ineffably.xyz
```

### 9.2 On-request string markers
```
3061-link211        magic liveness/preview string in path or query
nobotuseragent      sentinel returned when all C2 hosts are unreachable
```

### 9.3 File / path indicators (as observed)
```
wp-content/mu-plugins/bold-conductor-snap.php     rebuilt backdoor (mu-plugin)
wp-content/plugins/bold-conductor-snap/           redundant rebuild source
wp-content/.50a9c554.php                           hidden dot-file payload
wp-content/cache/c7bad850.php                      cache-dir copy
wp-content/1be2cc8d.zip                            archive source copy
wp-content/uploads/fcefabhjea.zip                  archive source (phar target)
wp-content/object-cache.php                        drop-in (if not installed by you)
```

### 9.4 Fake plugin identifiers (primary backdoor header)
```
Plugin Name: Apex Collector Cue
Author:      Charlotte Walker
Plugin URI:  walker.dev/plugins/apex-collector-cue
```
(These are fabricated. Any plugin bearing this identity on a site that never installed it is an indicator.)

### 9.5 Database / account indicators
```
Hidden admin whose email matches the pattern:  login@<your-domain>
Obfuscated payload/config values stored in wp_options
An administrator account NOT present in your known-good admin list
```

### 9.6 Robots.txt tampering
```
robots.txt overwritten to "User-agent: * / Allow: /" plus an injected sitemap line
```

### 9.7 Behavioural indicators
- Different HTML served to a Googlebot User-Agent versus a normal browser for the same URL (cloaking).
- Outbound HTTP from the PHP tier to unknown hosts, especially to `/super6.php`.
- Admin sessions valid but originating from ASNs/geographies never associated with your administrators (forged-cookie use).
- Unexpected rewrites of `robots.txt`, new top-level `.php`/`.zip` under `wp-content/uploads` or `wp-content/cache`, or new `auto_prepend_file` directives.

---

## 10. Detection guidance (server-side)

For operators inspecting their own hosts:

**File system**
- Enumerate `wp-content/mu-plugins/` — on a clean-baseline site this directory should be empty or absent. Any PHP here is suspect.
- Check for `object-cache.php` in `wp-content/` if you have **not** deliberately installed a persistent object cache (Redis/Memcached drop-in). An unexplained drop-in is a strong indicator.
- Search for dot-prefixed PHP files (`.<name>.php`) and for standalone `.php`/`.zip` in `wp-content/uploads/` and `wp-content/cache/` (neither directory should contain executable PHP).
- Grep configuration for `auto_prepend_file` across `.htaccess`, `.user.ini`, `php.ini`, and vhost config.
- Inspect `wp-config.php`, `index.php`, and any core files for injected `include`/`require` lines referencing hidden or hex-named files.
- File-integrity-monitor `robots.txt` for unexpected rewrites.

**Database (query directly — the UI is unreliable here)**
- The backdoor hides its admin from `WP_User_Query` and adjusts the user count, so **do not** trust the dashboard user list. Query the database directly for accounts with administrator capability and reconcile against your known-good list.
- Look for an account whose email matches `login@<your-domain>`.
- Review `wp_options` for large opaque/obfuscated values with unfamiliar option names.

**Process / runtime**
- A copy may reside in shared memory (`shmop`/SysV). If files reappear after deletion without an inbound request, suspect a memory-resident instance and plan a PHP worker restart (see §11).

**Cloaking probe**
- Request a sample of URLs with a Googlebot User-Agent and compare to the normal-browser response. Divergence indicates active cloaking. (This is the one signal that still fires even after C2 domains rotate.)

---

## 11. Remediation (order matters — self-healing framework)

Because the framework regenerates from redundant local copies and a shared-memory resident, cleanup must be **complete and correctly sequenced**. Piecemeal removal will be reversed.

1. **Rotate the WordPress auth keys and salts** in `wp-config.php` (`AUTH_KEY`, `SECURE_AUTH_KEY`, `LOGGED_IN_KEY`, `NONCE_KEY`, and the corresponding salts). This **invalidates every session, including the forged cookies already issued.** Do this first.
2. **Isolate the site** (maintenance mode / take offline) if feasible, to stop re-triggering during cleanup.
3. **Remove the entire persistence surface in one pass** (§6): the mu-plugin, the redundant plugin source directory, the hidden dot-file, the cache-dir copy, both ZIP archives, the `phar` loader stub, the injected `wp-config`/core include line, every `auto_prepend_file` directive, and the malicious `object-cache.php` drop-in.
4. **Remove the hidden administrator(s) via direct database action**, not the dashboard (the UI hides them). Verify against your known-good admin list.
5. **Restart PHP-FPM / Apache** to clear any shared-memory-resident copy. Without a worker restart, a memory-resident instance can rewrite the files you just deleted.
6. **Flush the PHP opcode cache** (OPcache) so no stale malicious bytecode remains loaded.
7. **Rotate all credentials** — admin passwords, database credentials, and any FTP/SFTP/SSH/hosting-panel credentials that could have been the entry vector.
8. **Identify and close the entry vector.** On a clean-core baseline, prioritise credential compromise and server-level file-write. Review access logs and hosting-account activity.
9. **Re-scan and assume co-infection.** This framework evicts competitors, but that behaviour is not a guarantee of a single infection. Confirm the persistence surface is fully clear and monitor for regeneration.

---

## 12. Related campaigns & attribution context

This activity is consistent with a family of WordPress backdoors publicly tracked through 2025. Independent vendor reporting describes the same building blocks:

- Security researchers documented backdoors abusing the **must-use plugins directory** as an automatically-loaded, non-deactivatable foothold, using a **ROT13-obfuscated loader** to fetch a remote payload and stash it in the database. <cite index="10-1">The must-use plugins directory auto-loads plugins without dashboard activation, making it an effective hiding place, and the loader silently fetches a ROT13-obfuscated remote payload and stores it in the database.</cite>
- The same reporting describes **hidden administrator creation** and **password resets of common admin usernames** to lock out legitimate operators. <cite index="9-1">The malware creates a hidden administrator account and can change the passwords of common admin usernames such as "admin," "root," and "wpsupport" to an attacker-set default, locking out other administrators.</cite>
- A closely-related variant relies on **forging valid authentication cookies rather than creating accounts**, so the operator returns as an administrator without re-authenticating and without leaving a new user in the database. <cite index="7-1">The backdoor creates valid authentication cookies that let attackers return as administrators for the cookie lifetime without re-authenticating, leaving no new user account and appearing as normal admin activity in logs.</cite> That variant was found **disguised as a JavaScript asset that was actually PHP**, loading the full WordPress environment to reuse its internal session APIs. <cite index="7-1">The file was disguised as a JavaScript asset in the wp-admin/js directory but was actually PHP, and it loads WordPress to reuse internal APIs such as cookie creation and user enumeration.</cite>
- Earlier waves in the same family used the mu-plugins directory for **SEO redirection and spam**, with execution branching on whether the visitor is a **bot, an administrator, or a regular visitor** — the same cloaking logic seen in the loader component here. <cite index="13-1">Earlier mu-plugins malware redirected traffic to malicious sites, maintained backdoor access, and injected SEO spam, with a script that executed conditionally based on whether the visitor was a bot, an administrator, or a regular visitor.</cite>
- Reinstallation-on-removal via a **secondary force-installed component** and payload storage under a dedicated `wp_options` key are also documented family traits. <cite index="8-1">The malware stores a base64 payload in a wp_options key, includes a hidden file manager, creates an admin user, and force-installs a malicious plugin to restore the backdoor if removed.</cite>

**Attribution note.** These are **post-compromise persistence toolkits**, not the product of a single exploit. Vendor reporting notes that entry frequently occurs through **compromised FTP/SFTP credentials or the wp-admin panel** rather than one specific vulnerability. <cite index="14-1">Because the malware arrived inside a plugin, the attackers likely compromised an FTP/SFTP account or uploaded it via the wp-admin panel.</cite>

---

## 13. CVE context

There is **no single CVE** for this framework. It is delivery-agnostic persistence that runs on any WordPress version once written to disk — confirmed here against a **clean WordPress 7.0.2 core with no plugins or themes**, where no extension vulnerability was available to exploit. CVE relevance is therefore in the **entry vector**, not the payload:

- On sites **with** third-party plugins/themes, unpatched extension vulnerabilities (arbitrary file upload/write, unauthenticated RCE, privilege escalation) are the most common doorway. Keep all extensions patched and remove unused ones.
- On **clean-core** sites (this baseline), prioritise **credential and server-level** vectors: reused/leaked admin, FTP/SFTP/SSH, or hosting-panel credentials; shared-hosting neighbour compromise; and any server misconfiguration permitting file write.

Track the vendor advisories in §14 for evolving IOCs; the family rotates infrastructure frequently.

---

## 14. References

- Sucuri — *Uncovering a Stealthy WordPress Backdoor in mu-plugins* (Jul 2025): `https://blog.sucuri.net/2025/07/uncovering-a-stealthy-wordpress-backdoor-in-mu-plugins.html`
- Sucuri — *WordPress Auto-Login Backdoor Disguised as JavaScript Data File* (Dec 2025): `https://blog.sucuri.net/2025/12/wordpress-auto-login-backdoor-disguised-as-javascript-data-file.html`
- Sucuri — *Hidden Malware Strikes Again: MU-Plugins Under Attack* (Mar 2025): `https://blog.sucuri.net/2025/03/hidden-malware-strikes-again-mu-plugins-under-attack.html`
- Sucuri — *Malicious WordPress Plugin Creates Hidden Admin User Backdoor* (Jun 2025): `https://blog.sucuri.net/2025/06/malicious-wordpress-plugin-creates-hidden-admin-user-backdoor.html`
- The Hacker News — *Hackers Deploy Stealth Backdoor in WordPress Mu-Plugins* (Jul 2025): `https://thehackernews.com/2025/07/hackers-deploy-stealth-backdoor-in.html`
- Security Affairs — *Stealth backdoor found in WordPress mu-Plugins folder* (Jul 2025): `https://securityaffairs.com/180311/malware/stealth-backdoor-found-in-wordpress-mu-plugins-folder.html`
- WordPress Developer Resources — *WP_Object_Cache / object-cache.php drop-in* (mechanism reference): `https://developer.wordpress.org/reference/classes/wp_object_cache/`

---

## Appendix A — IOC quick-reference

| Type | Indicator |
|---|---|
| C2 path | `/super6.php` |
| C2 host | `3061-link211.skyhooks.top` |
| C2 host | `3061-link211.vivyne.xyz` |
| C2 host | `3061-link211.ecovisios.xyz` |
| C2 host | `3061-link211.ineffably.xyz` |
| String marker | `3061-link211` (path/query) |
| Sentinel | `nobotuseragent` |
| File | `wp-content/mu-plugins/bold-conductor-snap.php` |
| Dir | `wp-content/plugins/bold-conductor-snap/` |
| File | `wp-content/.50a9c554.php` |
| File | `wp-content/cache/c7bad850.php` |
| File | `wp-content/1be2cc8d.zip` |
| File | `wp-content/uploads/fcefabhjea.zip` |
| Drop-in | `wp-content/object-cache.php` (if not self-installed) |
| Fake plugin | "Apex Collector Cue" / author "Charlotte Walker" |
| Hidden admin | email pattern `login@<domain>` |
| Config | unexpected `auto_prepend_file` in `.htaccess` / `.user.ini` / `php.ini` |
| Tamper | `robots.txt` reset to `Allow: /` + injected sitemap |

*Rotating values — pair with the structural/behavioural indicators in §6–§10.*

---

## Appendix B — Self-service blocking checklist (for operators not behind Hyx)

> Hyx customers are already covered by our deployed edge and server patterns. The controls below let other operators approximate that protection. The single highest-leverage control is **egress filtering on the PHP tier**: both payloads are inert without outbound HTTP to C2.

**Server / origin (highest impact first)**
- [ ] **Egress allowlist from PHP workers.** Deny arbitrary outbound HTTP; permit only known-good destinations. This alone neutralises C2 beaconing and the live-fetch cloaker.
- [ ] **Sinkhole** the four C2 hostnames and `/super6.php` at your resolver/firewall.
- [ ] **Disable dangerous PHP where feasible** (`disable_functions`) and constrain file access with `open_basedir`.
- [ ] **Deny PHP execution** under `wp-content/uploads/` and `wp-content/cache/` at the web-server level.
- [ ] **Remove and block `auto_prepend_file`** directives you did not set; monitor `.htaccess`/`.user.ini`/`php.ini` for reintroduction.
- [ ] **File-integrity monitoring** on `robots.txt`, `wp-config.php`, `wp-content/mu-plugins/`, and `wp-content/object-cache.php`; alert on new top-level `.php`/`.zip` in uploads/cache.
- [ ] **Restart PHP workers on a schedule** during and after incident response to defeat shared-memory residency.

**Edge / WAF / CDN (if you run your own)**
- [ ] Block requests where path or query contains `3061-link211`.
- [ ] Deny direct access to `.php` and `.zip` under `/wp-content/uploads/` and `/wp-content/cache/`.
- [ ] Deny direct access to dot-prefixed PHP (`/\.[^/]+\.php$`).
- [ ] **Block or strip off-domain `Location:` headers** on 3xx responses (allowlist your own hosts) — defeats the redirect payload regardless of C2 state.
- [ ] **Serve a canonical `robots.txt` from the edge** so origin tampering is invisible to crawlers.
- [ ] **Content-Security-Policy `script-src` allowlist** (deploy report-only first, then enforce) — the browser refuses the injected off-domain script no matter how the tag entered the HTML.
- [ ] **Restrict `/wp-admin` and `/wp-login.php`** by IP allowlist or geofence — blocks interactive use of the rogue admin / forged cookies even while files remain.
- [ ] **Flag admin sessions from unfamiliar ASNs/geos** (step-up auth) — forged cookies are cryptographically valid, so behavioural anomaly detection is the only edge angle.
- [ ] **Response-body scanning** for off-domain `<script src>` injection and crawler-facing spam markers.

**Do NOT rely on**
- UA-agnostic aggressive caching as a "cloak breaker" — it can cache and serve the spam variant to real users.
- Dashboard audits of users/plugins/updates — the backdoor hides itself from all three.
- Blocklisting the magic GET parameter — it is derived per-site and has no static signature.

---

*Prepared by Hyx Security Research for customer distribution. Indicators rotate; revalidate against the linked vendor advisories periodically. Questions or additional samples: contact your Hyx security representative.*
