# Threat Disclosure — Multi-Vector WordPress Compromise Framework

**Publisher:** Hyx Security Research (CDN / WAF)
**Document type:** Customer research advisory
**Reference ID:** HYX-TR-2026-0803
**Version:** 2.0 (supersedes 1.0)
**TLP:** CLEAR (may be redistributed freely; adjust to your programme's needs)
**Date:** 2026-08-03
**WP Version:** 7.0.2
**Audience:** Site operators and hosting teams — particularly those **not** protected by Hyx edge/WAF who need to detect and block this threat on their own infrastructure

---

## 0. Change log

| Version | Date | Summary |
|---|---|---|
| 1.0 | 2026-08-03 | Initial advisory from artefact analysis against a clean WordPress 7.0.2 baseline: documented the "SC" self-healing backdoor suite and the SEO-cloaking loader. |
| **2.0** | **2026-08-03** | **Rewritten after a full production-site forensic image.** Confirms the v1 families in situ and adds: a **second cloaking campaign**, a **magic-auth "SSO" backdoor**, a **JS-overlay cloaking gate ("Speed Optimizer", ×5)**, **SEO-spam injection plugins ("Link Factory", "SEO Flex Block")**, a **signed self-updating link-injection backdoor ("Easypost")**, a **password-gated webshell**, malicious **db.php / advanced-cache.php drop-ins**, empty **registered plugin shells**, a **fake theme**, and file hashes for all artefacts. Corrects one cloaker C2 domain decode (`ecoisios.xyz`, previously mis-decoded as `ecovisios.xyz`). |

---

## 1. Purpose and scope

Hyx has developed and deployed server-side and edge block patterns that neutralise this threat for customers behind our WAF/CDN. This document is published so that operators **who do not use Hyx protection** can understand the threat and implement equivalent controls on their own stack.

This is a **defensive advisory**. It documents identification, classification, behaviour, indicators of compromise (IOCs), detection, blocking, and remediation. It intentionally contains **no offensive detail** — no payload source, no deobfuscation routines, and nothing that would help reproduce or operate the malware.

**Two analysis inputs underpin this advisory.** The v1 artefact analysis was performed against a **clean WordPress 7.0.2 core install with no plugins or themes**, which proved the primary backdoor is fully self-contained post-compromise persistence that does not depend on any extension. This v2 update incorporates a **complete production-site forensic image** of a live compromised host, confirming the same families in place and revealing several additional components layered on top by what appears to be **more than one operator**.

---

## 2. Executive summary

The forensic image shows a WordPress site compromised by **at least ten distinct malicious components**, spanning **remote access, magic authentication, SEO cloaking, spam injection, and a raw webshell**. They fall into several families that were installed and maintained independently — this is a **multi-actor, stacked compromise**, not a single implant.

The load-bearing component is a **modular, self-healing backdoor suite** (internally named **"SC"**, versioned 4.0.x) that beacons to command-and-control (C2), **creates a hidden administrator**, **forges and exfiltrates valid WordPress sessions**, deletes competing malware, hides itself from the admin UI, and re-creates itself from numerous redundant footholds. Removing any single piece causes the others to regenerate it. Alongside it run **two SEO-cloaking campaigns**, a **magic-authentication backdoor**, a **JS-overlay cloaking gate deployed five times under different names**, **two SEO-spam link-injection plugins**, a **signed self-updating link-injection endpoint**, and a **password-protected webshell**.

The defining operational property remains **redundant, self-healing persistence across many independent hooks** — a must-use plugin, a `.user.ini` `auto_prepend_file` directive, two WordPress drop-ins (`db.php`, `advanced-cache.php`), an active-theme `functions.php` injection, database options, ZIP archives, and shared memory. **Partial cleanup fails.**

This activity aligns with a well-documented, actively-tracked family of WordPress backdoors reported through 2025 (see §13).

---

## 3. Affected environment & incident context

- **Reference forensic image:** a full `public_html` capture of a live compromised production site.
- **Compromised domain (from on-host artefacts):** `rejouva-tech.co.uk`.
- **Hosting path fingerprint:** document root under `/var/www/145e9e79-5b51-46c2-9be7-19754fde7d14/public_html/` (this UUID appears hard-coded in the `auto_prepend_file` stub — a per-host artefact).
- **Scale:** ~6,200 files, ~1,700 PHP files; ~20 plugin directories and multiple themes present, most of the suspicious ones attacker-introduced.
- **v1 baseline:** clean WordPress 7.0.2 core with **no plugins or themes**, used to isolate the primary backdoor and confirm it is extension-independent.

The malware operates independently of any legitimate plugin or theme. On this host it also **injected the active theme's `functions.php`** and **cloned/spoofed plugins and a theme** for camouflage, but none of those legitimate extensions is required for the malware to run.

---

## 4. Threat classification

The compromise exhibits the following attack classes simultaneously:

| Class | Present as |
|---|---|
| **Backdoor / Remote Access** | "SC" suite C2 command execution; forged-session admin access; raw webshell |
| **Authentication bypass (magic auth)** | "SSO" mu-plugin unauthenticated AJAX → `wp_set_auth_cookie()` for admin |
| **Persistence (redundant/self-healing)** | mu-plugins, `.user.ini` prepend, `db.php`/`advanced-cache.php` drop-ins, theme `functions.php`, DB options, ZIPs, shared memory |
| **Privilege persistence** | Hidden administrator creation; auth-cookie forgery; session exfiltration |
| **SEO spam / cloaking** | Two server-side cloaking campaigns; a JS-overlay cloaking gate; hidden-link and spam-post injection |
| **Malicious redirection** | Attacker-controlled 301 redirects (server-side) and JS-driven redirects (client-side) |
| **Client-side injection** | Off-domain `<script>` and hidden-link injection into rendered pages |
| **Defense evasion / anti-forensics** | UI self-hiding, code obfuscation, competitor-malware removal, magic-parameter gating, editor-padding, non-`.php` execution |
| **Data exfiltration** | Session cookies and environment data transmitted to C2 |
| **Anti-availability** | Future-dated `.maintenance` lock |

MITRE ATT&CK (indicative): T1505.003 (Web Shell), T1136.001 (Create Account: Local), T1556 (Modify Authentication Process), T1554 (Compromise Host Software Binaries / drop-ins), T1027 (Obfuscated Files/Information), T1620 (reflective/loader execution), T1071.001 (Application-Layer C2), T1070 (Indicator Removal), T1505.004-style REST endpoint abuse.

---

## 5. Full component inventory

Every item below is attacker-introduced. Sizes and hashes are from the forensic image (see Appendix A for SHA-256).

| # | Component | On-host location(s) | Role |
|---|---|---|---|
| F1 | **"SC" backdoor suite** | `mu-plugins/bold-conductor-snap.php`, `.50a9c554.php`, `50a9c554.php`, `db.php`, `advanced-cache.php`, `cache/c7bad850.php`, `1be2cc8d.zip` (×3), `uploads/fcefabhjea.zip`, `themes/twentytwentyfive/functions.php`, `plugins/hybrid-security/*.rdt` | Primary RAT + self-healing persistence |
| F2 | **Cloaker — campaign `3061-link211`** | `shop.php` | SEO cloaking / visitor redirect via C2 |
| F3 | **Cloaker — campaign `3121-bright152`** | `wp-slgnup.gz` | Second SEO-cloaking campaign (staged) |
| F4 | **"SSO" magic-auth backdoor** | `mu-plugins/sso-loader.php` | Unauthenticated admin login via secret token |
| F5 | **"Speed Optimizer" cloaking gate** | `plugins/speed-optimizer/`, `speed-optimizer-1/`, `defender-database-wordpress/`, `visual-user/`, `wp-shipping-aggregator-for/` (all `speed-optimizer.php`) | JS full-page overlay + XOR-decoded client redirect (×5 copies) |
| F6 | **"Link Factory" spam injector** | `plugins/link-factory/` | Signed REST endpoints: footer-sentence injection + auto-post publishing |
| F7 | **"SEO Flex Block" hidden-link spam** | `plugins/seo-flex-block/`, `uploads/2026/07/seo-flex-block-2.zip` | Hidden/offset SEO link block |
| F8 | **"Easypost" signed link-injection backdoor** | `plugins/easypost/easypost.php` → drops `wp-content/easypost/easypost.php` + `mu-plugins/easypost-runtime.php` | HMAC-signed REST: hidden homepage links, arbitrary post creation, **OTA self-update** |
| F9 | **Password-gated webshell** | `index.zip` (`index.php`, 37 KB) | `goto`-obfuscated shell gated by `sha1(sha1($_REQUEST['a']))` |
| F10 | **Empty registered plugin shells** | `plugins/solid-scanner-run/`, `wp-security-helper/`, `xadvanced-link-keeper-tgzns/`, `xelite-pixel-stream-vlsid/`, `xsilent-data-flow-kccma/` | Slot reservation / removal remnants (registered in `active_plugins`) |
| — | **Fake theme** | `themes/skyxoyj/` (header-only) | Slot reservation / staging |
| — | **Camouflage** | `plugins/apzvd/`, `ggurr/`, `uytxo/` (all "Protect Uploads") | Benign plugin cloned ×3 under random names as filler |
| — | **Anti-availability / artefacts** | `.maintenance`, `.tmb/` (file-manager thumbnail cache), tampered `.htaccess` | Maintenance lock; evidence of an active file manager |

**Provenance note.** The "SC" suite (F1), "SSO" (F4), cloakers (F2/F3), overlay gate (F5), spam injectors (F6/F7), the signed injector (F8), and the webshell (F9) use different authors, naming schemes, and techniques. Treat this as several overlapping intrusions sharing one over-exposed host, not one toolkit.

---

## 6. Component detail

### F1 — "SC" self-healing backdoor suite (primary)

Internally named **SC**, versioned (drop-in headers read `SC_DB_BEGIN:4.0.2` and `SC_ADV_BEGIN:4.0.3`). Obfuscated with a custom per-file substitution cipher over ordinary PHP function names; payloads layered as base64-over-gzip plus XOR with a per-site key.

**Execution / persistence on this host (confirmed in situ):**
- **`.user.ini`** sets `auto_prepend_file = "…/wp-content/50a9c554.php"` — runs on **every** PHP request.
- **`wp-content/50a9c554.php`** (203 B) — include stub → includes the hidden reinstaller.
- **`wp-content/.50a9c554.php`** (6 KB) — self-healing reinstaller: rebuilds the mu-plugin whenever it is missing/truncated, from redundant local sources, then invalidates OPcache.
- **`wp-content/mu-plugins/bold-conductor-snap.php`** (~185 KB) — the rebuilt primary backdoor.
- **`wp-content/db.php`** (~79 KB) — malicious **database drop-in**, loaded extremely early (before most of core), on every request.
- **`wp-content/advanced-cache.php`** (~11 KB) — malicious **cache drop-in** (loads when `WP_CACHE` is set); front-padded with ~80 blank lines to hide the payload in editors.
- **`wp-content/cache/c7bad850.php`** — reinstaller copy.
- **`wp-content/1be2cc8d.zip`**, **`themes/twentytwentyfour/1be2cc8d.zip`**, **`uploads/2026/08/1be2cc8d.zip`** — three redundant archive sources.
- **`wp-content/uploads/fcefabhjea.zip`** — `phar://` payload archive.
- **`themes/twentytwentyfive/functions.php`** — SC injected into the **active theme**.
- **`plugins/hybrid-security/1.rdt … 10.rdt`** — ten encoded payload/config blobs (5–14 KB each) in a fake "security" plugin dir.

**Capabilities (from v1 deep analysis):** C2 beacon → command-server list + symmetric key → commands; hidden-admin creation; **forged, cryptographically valid auth cookies exfiltrated** to C2 (credential-less admin login); competitor-malware deletion; self-hiding from plugins list, updates and user enumeration; off-domain `<script>` injection; per-site magic GET-parameter content delivery; redundant self-healing across all footholds; a shared-memory (`shmop`) resident that can rewrite deleted files.

### F2 / F3 — SEO cloaking campaigns

Both are the same cloaker lineage: fingerprint the visitor (User-Agent; the second variant also reads `Accept-Language`), fetch live content from C2 at **`/super6.php`**, and serve crawler spam / visitor redirects / fake `sitemap`/`robots` per a control keyword; overwrite `robots.txt`; honour a magic liveness string; fail silent on the sentinel `nobotuseragent`.

- **F2 `shop.php`** — campaign **`3061-link211`** (present, executable in webroot).
- **F3 `wp-slgnup.gz`** — campaign **`3121-bright152`** (gzip-stored to evade `.php` scanners; staged for a loader to decompress/write).

Domains are ROT13 + URL-encoded; decoded values are in §11.1. **Correction from v1:** the third `3061-link211` domain is **`ecoisios.xyz`** (v1 mis-printed `ecovisios.xyz`).

### F4 — "SSO" magic-authentication backdoor

`wp-content/mu-plugins/sso-loader.php` — fake **"SSO"** plugin (spoofed authors "Garth Mortensen, Mike Hansen"). Registers **`wp_ajax_nopriv_sso-check`** and `wp_ajax_sso-check` — an **unauthenticated** AJAX action. On request it computes `base64(sha256(nonce . salt))[:64]` and compares to the stored option **`sso_token`**; on match (nonce not expired) it calls **`wp_set_auth_cookie()`** for the supplied user or the **first administrator**, then redirects into `wp-admin`. Nonce expiry uses a `-e<epoch>` suffix (300 s); brute-force throttling (5 attempts/IP via a transient) makes it look legitimate. Anyone who learns `sso_token` gets instant admin.

### F5 — "Speed Optimizer" JS-overlay cloaking gate (×5)

Five identical drops named `speed-optimizer.php` under masquerade directories (`speed-optimizer`, `speed-optimizer-1`, `defender-database-wordpress`, `visual-user`, `wp-shipping-aggregator-for`); fake author "Performance Team", "HTML optimization" cover story. Injects a **full-page white overlay + spinner** (`<div id="R2FvKSeqkPMZAnMV" style="position:fixed;…z-index:9999">`) and a **JS decoder** (`decode(token, key="3UYf-$iW$_oQHP^Eb$;L{U]G$01Wjh>_")` — XOR-with-key over base64) that reveals a payload/redirect client-side, evading server-side response scanning.

### F6 — "Link Factory" SEO-spam injector

`plugins/link-factory/link-factory.php` — fake "Link Factory", version `977adfa` (a git hash used as a version — an attacker tell). Exposes **signed REST endpoints** that store HTML "sentences" rendered in `wp_footer` (homepage-only or sitewide) and **publish standard posts via `wp_insert_post()`** — footer link-spam plus automated spam-post publication.

### F7 — "SEO Flex Block" hidden-link spam

`plugins/seo-flex-block/seo-flex-block.php` — fake "SEO Flex Block" (author `@Berezovskyi_F`, v1.0.4): a "flexible text block with links for SEO" using **offset-based hiding** — i.e., hidden-link injection. Staged copy at `uploads/2026/07/seo-flex-block-2.zip`.

### F8 — "Easypost" signed link-injection + self-update backdoor

`plugins/easypost/easypost.php` (fake "Easypost", v2026.06.10). On activation it writes a standalone endpoint at **`wp-content/easypost/easypost.php`** and a runtime mu-plugin **`mu-plugins/easypost-runtime.php`** (both re-created on demand — empty in the snapshot). The endpoint bootstraps WordPress via `wp-load.php` discovery and processes **HMAC-SHA256-signed** POSTs authenticated by headers `x-easypost-token-id`, `x-easypost-timestamp`, `x-easypost-request-id`, `x-easypost-body-sha256`, `x-easypost-signature`, keyed to token id **`ep_99cec15bfac444bf8d0c938ec6954937`**. Actions:
- `create_post` — publishes arbitrary posts (`wp_insert_post`).
- `place_homepage_link` / `remove_homepage_link` — injects/removes **hidden** homepage links (Elementor-aware) with placement styles `WHITE_LINK`, `CLASS_HIDE`, `NO_WIDTH`, `INVISIBLE_ZONE`, `NO_VISIBILITY`, `NO_OPACITY` — a catalogue of cloaked-link techniques; stored in option `easypost_homepage_placements` and post-meta `_easypost_homepage_placement_*`.
- `update_endpoint` — **OTA self-update**: verifies an attacker RSA signature (embedded public key) then overwrites itself with attacker-supplied base64 PHP. This makes the backdoor self-updating and version-controlled.

### F9 — Password-gated webshell

`index.zip` contains `index.php` (~37 KB), a **`goto`-obfuscated** shell that authenticates the operator via **`sha1(sha1($_REQUEST['a']))`** against an embedded hash before executing commands. Staged as a ZIP to avoid `.php` scanners.

### F10 / camouflage / artefacts

- **Empty registered shells** (`solid-scanner-run`, `wp-security-helper`, `xadvanced-link-keeper-tgzns`, `xelite-pixel-stream-vlsid`, `xsilent-data-flow-kccma`): empty directories, likely registered in `active_plugins` to trigger loaders or reserve slots, or remnants of removed payloads. Naming pattern `x<word>-<word>-<5char>`.
- **Fake theme `skyxoyj`**: header-only (style.css/readme/screenshot, no PHP); referenced by the file-manager thumbnail cache.
- **Camouflage clones**: the legitimate "Protect Uploads" plugin cloned into `apzvd/`, `ggurr/`, `uytxo/` — benign code, anomalous placement, used as filler so malicious plugins blend into a long list.
- **`.maintenance`** = `<?php $upgrading = 2101150065; ?>` — a **future-dated** timestamp keeps WordPress hard-locked in maintenance mode (anti-availability / captured mid-operation).
- **`.tmb/`** — elFinder/file-manager thumbnail cache (base64-encoded paths of `wp-admin/images/*` and the `skyxoyj` theme) — evidence an attacker file manager was actively used. `wp-file-manager/` and `fileorganizer/` are present and **require verification** (legitimate file managers, but commonly attacker-dropped/abused). `wp-cli-login-server` (a real plugin) enables passwordless magic-login links and is attacker-leverageable.
- **`.htaccess`** carries duplicated rewrite blocks outside the WordPress markers — minor tampering.
- **`wp-config.php`** sets `DISABLE_WP_CRON` (the malware uses `init`/admin/shutdown hooks and its own scheduling rather than `wp-cron.php`).

---

## 7. Consolidated persistence surface

Inspect and remove **simultaneously** — each foothold can regenerate the others.

| Foothold | On this host |
|---|---|
| PHP prepend | `.user.ini` → `wp-content/50a9c554.php` → `wp-content/.50a9c554.php` |
| Must-use plugins | `mu-plugins/bold-conductor-snap.php` (SC), `mu-plugins/sso-loader.php` (magic auth), `mu-plugins/easypost-runtime.php` (re-created) |
| DB drop-in | `wp-content/db.php` (SC_DB 4.0.2) |
| Cache drop-in | `wp-content/advanced-cache.php` (SC_ADV 4.0.3) |
| Active-theme injection | `themes/twentytwentyfive/functions.php` |
| Reinstaller copy | `wp-content/cache/c7bad850.php` |
| Archive sources | `wp-content/1be2cc8d.zip`, `themes/twentytwentyfour/1be2cc8d.zip`, `uploads/2026/08/1be2cc8d.zip` |
| `phar://` payload | `wp-content/uploads/fcefabhjea.zip` |
| Payload blobs | `plugins/hybrid-security/{1..10}.rdt` |
| Signed injector drops | `wp-content/easypost/easypost.php` (+ its OTA self-update) |
| Registered plugins | Multiple malicious plugins in `active_plugins` |
| Database | SC options, `sso_token`, `easypost_homepage_placements`, obfuscated option blobs |
| Shared memory | SC `shmop` resident (survives file deletion until PHP workers restart) |
| Rogue access | Hidden admin in `wp_users`/`wp_usermeta`; forged sessions already issued |
| Anti-availability | `.maintenance` future-dated lock |

---

## 8. Kill chain

**Initial access (inferred).** The v1 clean-core baseline had no extensions to exploit, so for that environment the vector is **credential compromise** (FTP/SFTP/SSH, hosting panel, or `wp-admin`), a **compromised shared-hosting account**, or **direct file write**. On the populated production host, an **unpatched vulnerable plugin/theme** is an additional realistic doorway. Given the presence of file managers and multiple unrelated malware families, treat the host as **broadly exposed** with the entry vector open until proven closed.

**Execution.** Malware runs via auto-execution hooks that need no attacker request: `mu-plugins`, `.user.ini` `auto_prepend_file`, the `db.php` and `advanced-cache.php` drop-ins, and the active theme's `functions.php`. The signed injector (F8) additionally bootstraps WordPress from its own standalone endpoint.

**Monetisation / objectives.** (1) Persistent remote control and credential-less admin (F1, F4, F9); (2) SEO spam and traffic hijack via server-side cloaking (F2/F3), a client-side overlay gate (F5), and hidden-link/spam-post injection (F6/F7/F8).

**Persistence & self-healing.** All components are staged redundantly (§7) and continuously re-create each other; incomplete removal is reversed on the next request.

---

## 9. Evasion & obfuscation (described, not reproduced)

- **Function-name obfuscation** — sensitive calls assembled at runtime via per-file substitution maps, defeating signature/`grep` scanning.
- **ROT13 + URL-encoding** of C2 hostnames (both cloaker campaigns).
- **Layered encoding** — base64-over-gzip plus XOR with per-site keys, in the DB, drop-ins, and `.rdt` blobs.
- **Non-`.php` execution** — `phar://` inside ZIPs, `.gz`-stored cloaker, and WordPress drop-ins, bypassing `.php`-only scanners.
- **Editor-padding** — ~80 leading blank lines in `advanced-cache.php` push the payload out of view.
- **Client-side cloaking** — the "Speed Optimizer" overlay decodes its payload/redirect in the browser, so server-side response inspection sees only benign markup.
- **UI self-hiding** — the SC backdoor removes itself from the plugins list, update checks, and user enumeration; `.rtd` blobs and dot-files and cache/uploads placement avoid casual review.
- **Magic-string / magic-parameter gating** — cloaker liveness string, SC magic GET parameter, SSO `sso_token`, Easypost signed headers, webshell `$_REQUEST['a']`.
- **Camouflage** — cloned benign plugins and a header-only theme pad the extension list.
- **Signed self-update (F8)** — RSA-verified OTA replacement keeps the backdoor current and resistant to static signatures.

---

## 10. Indicators of Compromise (IOCs)

> **Caveat:** hostnames, filenames, tokens, and magic parameters **rotate between deployments**. The **structural and behavioural** indicators (§6–§9) are more durable than the literal strings. Use both.

### 10.1 Network — C2 (as observed)

Endpoint path (both cloaker campaigns):
```
/super6.php
```
Campaign **`3061-link211`** (F2 `shop.php`):
```
3061-link211.skyhooks.top
3061-link211.vivyne.xyz
3061-link211.ecoisios.xyz        (corrected from v1)
3061-link211.ineffably.xyz
```
Campaign **`3121-bright152`** (F3 `wp-slgnup.gz`):
```
3121-bright152.elareap.top
3121-bright152.zenithin.top
3121-bright152.clarip.xyz
3121-bright152.zenvie.xyz
```

### 10.2 On-request string / parameter markers
```
3061-link211 , 3121-bright152     cloaker campaign IDs / liveness strings
nobotuseragent                    cloaker all-C2-unreachable sentinel
action=sso-check + sso_token      SSO magic-auth (params: salt, nonce, user, bounce)
R2FvKSeqkPMZAnMV                  Speed Optimizer overlay div id
3UYf-$iW$_oQHP^Eb$;L{U]G$01Wjh>_  Speed Optimizer JS XOR key
x-easypost-token-id / -signature  Easypost signed-request headers
ep_99cec15bfac444bf8d0c938ec6954937   Easypost token id
$_REQUEST['a']                    webshell operator auth parameter
```

### 10.3 File / path indicators (this host)
```
# SC suite
wp-content/mu-plugins/bold-conductor-snap.php
wp-content/.50a9c554.php   wp-content/50a9c554.php   wp-content/cache/c7bad850.php
wp-content/db.php          wp-content/advanced-cache.php
wp-content/1be2cc8d.zip    wp-content/themes/twentytwentyfour/1be2cc8d.zip
wp-content/uploads/2026/08/1be2cc8d.zip   wp-content/uploads/fcefabhjea.zip
wp-content/themes/twentytwentyfive/functions.php   (injected)
wp-content/plugins/hybrid-security/{1..10}.rdt
.user.ini  (auto_prepend_file directive)   .maintenance  (future-dated)

# Other families
shop.php                                   (cloaker 3061-link211)
wp-slgnup.gz                               (cloaker 3121-bright152)
index.zip -> index.php                     (webshell)
wp-content/mu-plugins/sso-loader.php       (magic auth)
wp-content/plugins/speed-optimizer/speed-optimizer.php  (+4 clones, see §5)
wp-content/plugins/link-factory/           (spam injector)
wp-content/plugins/seo-flex-block/  + wp-content/uploads/2026/07/seo-flex-block-2.zip
wp-content/plugins/easypost/easypost.php   -> wp-content/easypost/easypost.php
                                           -> wp-content/mu-plugins/easypost-runtime.php

# Shells / camouflage
wp-content/plugins/{solid-scanner-run,wp-security-helper,xadvanced-link-keeper-tgzns,
                    xelite-pixel-stream-vlsid,xsilent-data-flow-kccma}/   (empty shells)
wp-content/themes/skyxoyj/                 (header-only fake theme)
wp-content/plugins/{apzvd,ggurr,uytxo}/    (cloned "Protect Uploads" filler)
```

### 10.4 Fake extension identities
```
Plugin "Apex Collector Cue"  / author "Charlotte Walker"   (SC backdoor header, seen elsewhere)
Plugin "SSO"                 / author "Garth Mortensen, Mike Hansen"
Plugin "Speed Optimizer"     / author "Performance Team"    (×5 dirs)
Plugin "Link Factory"        / author "Link Factory" / version 977adfa
Plugin "SEO Flex Block"      / author @Berezovskyi_F
Plugin "Easypost"            / version 2026.06.10
Drop-in headers: SC_DB_BEGIN:4.0.2 / SC_ADV_BEGIN:4.0.3
```

### 10.5 Database / account indicators
```
Hidden admin whose email matches pattern:  login@<domain>
Administrator account NOT in your known-good admin list
Options:  sso_token , easypost_homepage_placements , obfuscated SC option blobs
Post meta: _easypost_homepage_placement_*
robots.txt overwritten to "User-agent: * / Allow: /" + injected sitemap
```

### 10.6 Behavioural indicators
- Different HTML to a Googlebot UA vs a normal browser for the same URL (server-side cloaking).
- A brief full-page white overlay/spinner then a client-side redirect (Speed Optimizer gate).
- Outbound HTTP from the PHP tier to unknown hosts, especially `/super6.php`.
- Admin sessions valid but from ASNs/geographies never used by your admins (forged cookies).
- Unexpected `robots.txt` rewrites; new `.php`/`.zip`/`.rdt`/`.gz` under `uploads`, `cache`, or plugin dirs; new `auto_prepend_file`.
- Hidden links or unfamiliar published posts appearing on the homepage/footer.

### 10.7 SHA-256 (this image)
See **Appendix A**.

---

## 11. Detection guidance (server-side)

**File system**
- Enumerate `wp-content/mu-plugins/` — expect only known-good files. Anything else (SC, SSO, Easypost runtime) is suspect.
- Check `wp-content/` for drop-ins you did not install: **`db.php`**, **`advanced-cache.php`**, `object-cache.php`. Any unexplained drop-in is a strong indicator (an unexplained ~79 KB `db.php` especially).
- Search for dot-prefixed PHP (`.<name>.php`), and for `.php`/`.zip`/`.rdt`/`.gz` under `uploads/`, `cache/`, and plugin directories (none should hold executable payloads).
- Grep config for `auto_prepend_file` across `.user.ini`, `.htaccess`, `php.ini`, vhosts.
- Diff the **active theme's `functions.php`** and core entry files (`index.php`, `wp-blog-header.php`, `wp-config.php`) against known-good copies.
- Flag plugin directories with **zero PHP files** (empty registered shells) and **duplicate plugins** installed under different random directory names.
- File-integrity-monitor `robots.txt`.
- Check for a future-dated `.maintenance` file.

**Database (query directly — the UI hides the rogue admin and adjusts the user count)**
- Enumerate administrator-capability accounts directly and reconcile against your known-good list; look for an email matching `login@<domain>`.
- Review `wp_options` for `sso_token`, `easypost_homepage_placements`, and large opaque blobs.
- Review recent posts and homepage/footer content for injected links / spam posts.

**Process / runtime**
- The SC suite holds a `shmop` shared-memory copy; if files reappear after deletion without an inbound request, plan a PHP worker restart (§12).

**Cloaking probes**
- Fetch sample URLs with a Googlebot UA and compare to a normal-UA response (server-side cloaking).
- Load the homepage with JS disabled/enabled and watch for the overlay/redirect (Speed Optimizer gate).

---

## 12. Remediation (order matters — self-healing, multi-family)

Piecemeal removal will be reversed. Remove **completely** and in this order.

1. **Rotate the WordPress auth keys and salts** in `wp-config.php` (`AUTH_KEY`, `SECURE_AUTH_KEY`, `LOGGED_IN_KEY`, `NONCE_KEY` + salts). This invalidates **all** sessions, including forged cookies already issued. Do this first.
2. **Isolate the site** (maintenance/offline) during cleanup.
3. **Remove the entire persistence surface in one pass** (§7): the two/three malicious mu-plugins; the `.user.ini` directive and its stub + reinstaller; `db.php` and `advanced-cache.php`; the active-theme `functions.php` injection; the cache reinstaller copy; all `1be2cc8d.zip` copies; `fcefabhjea.zip`; the `hybrid-security/*.rdt` blobs; the Easypost plugin **and** its dropped `wp-content/easypost/` endpoint and runtime mu-plugin; the cloakers (`shop.php`, `wp-slgnup.gz`); the webshell (`index.zip`); the spam plugins (`link-factory`, `seo-flex-block` + staged zip); the five "Speed Optimizer" copies; the empty shell dirs; the fake theme; and the cloned-filler plugins.
4. **Remove the hidden administrator(s) via direct database action**, not the dashboard; delete malicious options (`sso_token`, `easypost_homepage_placements`, SC blobs) and any injected posts/homepage links.
5. **Restart PHP-FPM / Apache** to clear the SC `shmop` resident. Without a worker restart, a memory-resident instance rewrites deleted files.
6. **Flush OPcache.**
7. **Rotate all credentials** — admin passwords, DB credentials, and every FTP/SFTP/SSH/hosting-panel credential that could be the entry vector.
8. **Remove the `.maintenance` lock** and clean the tampered `.htaccess` back to a known-good template.
9. **Close the entry vector** — patch/replace any vulnerable plugin/theme; audit file-manager plugins (`wp-file-manager`, `fileorganizer`, `wp-cli-login-server`) and remove if unauthorised; review access logs and hosting-account activity.
10. **Re-scan and assume multi-family co-infection.** Confirm the surface is clear and monitor for regeneration before restoring access. Given the breadth here, a **rebuild from known-good source + a vetted content export** is often faster and safer than in-place cleaning.

---

## 13. Related campaigns & attribution context

This activity is consistent with a family of WordPress backdoors tracked publicly through 2025. Independent vendor reporting describes the same building blocks — abuse of the **must-use plugins** directory as an auto-loaded, non-deactivatable foothold; **ROT13-obfuscated loaders** fetching remote payloads into the database; **hidden-administrator creation** and password resets of common admin usernames; and a variant that **forges valid authentication cookies** rather than creating accounts, disguised as a JavaScript asset that is really PHP and loading WordPress to reuse its session APIs. Earlier waves used the same directory for **SEO redirection/spam** with execution branching on bot vs administrator vs visitor — the logic seen in the cloakers here — and reinstalled themselves from a **secondary force-installed component** with payloads stored under a dedicated `wp_options` key. The **magic-auth "SSO"** endpoint (F4) matches the forged-cookie/auto-login lineage; the **cloakers** (F2/F3) match the SEO-redirect lineage; and the **self-updating signed injector** (F8) reflects the trend toward signed, version-controlled implants.

**Attribution note.** These are **post-compromise persistence toolkits**, not the product of a single exploit; reporting attributes entry most often to **compromised FTP/SFTP credentials or the wp-admin panel**. The presence of several unrelated families on one host indicates the site was **broadly exposed** (likely credential or file-manager exposure) and colonised by multiple operators.

---

## 14. CVE context

There is **no single CVE** for this framework. It is delivery-agnostic persistence that runs on any WordPress version once written to disk — confirmed in v1 against clean WordPress 7.0.2 core with no extensions. CVE relevance is in the **entry vector**:
- On sites **with** third-party plugins/themes (this host), unpatched extension vulnerabilities (arbitrary file upload/write, unauthenticated RCE, privilege escalation) are the most common doorway; abusable file-manager plugins are a frequent culprit. Keep everything patched; remove unused and unauthorised extensions.
- On **clean-core** sites, prioritise **credential and server-level** vectors: reused/leaked admin, FTP/SFTP/SSH, or hosting-panel credentials; shared-hosting neighbour compromise; server misconfiguration permitting file write.

Track the vendor advisories in §15 for evolving IOCs; these families rotate infrastructure frequently.

---

## 15. References

- Sucuri — *Uncovering a Stealthy WordPress Backdoor in mu-plugins* (Jul 2025): `https://blog.sucuri.net/2025/07/uncovering-a-stealthy-wordpress-backdoor-in-mu-plugins.html`
- Sucuri — *WordPress Auto-Login Backdoor Disguised as JavaScript Data File* (Dec 2025): `https://blog.sucuri.net/2025/12/wordpress-auto-login-backdoor-disguised-as-javascript-data-file.html`
- Sucuri — *Hidden Malware Strikes Again: MU-Plugins Under Attack* (Mar 2025): `https://blog.sucuri.net/2025/03/hidden-malware-strikes-again-mu-plugins-under-attack.html`
- Sucuri — *Malicious WordPress Plugin Creates Hidden Admin User Backdoor* (Jun 2025): `https://blog.sucuri.net/2025/06/malicious-wordpress-plugin-creates-hidden-admin-user-backdoor.html`
- The Hacker News — *Hackers Deploy Stealth Backdoor in WordPress Mu-Plugins* (Jul 2025): `https://thehackernews.com/2025/07/hackers-deploy-stealth-backdoor-in.html`
- Security Affairs — *Stealth backdoor found in WordPress mu-Plugins folder* (Jul 2025): `https://securityaffairs.com/180311/malware/stealth-backdoor-found-in-wordpress-mu-plugins-folder.html`
- WordPress Developer Resources — *WP_Object_Cache / drop-ins* (drop-in mechanism reference): `https://developer.wordpress.org/reference/classes/wp_object_cache/`

---

## Appendix A — IOC quick-reference & SHA-256

### A.1 Quick-reference

| Type | Indicator |
|---|---|
| C2 path | `/super6.php` |
| C2 hosts (3061-link211) | `skyhooks.top`, `vivyne.xyz`, `ecoisios.xyz`, `ineffably.xyz` (all `3061-link211.*`) |
| C2 hosts (3121-bright152) | `elareap.top`, `zenithin.top`, `clarip.xyz`, `zenvie.xyz` (all `3121-bright152.*`) |
| Cloaker sentinel | `nobotuseragent` |
| Magic-auth | action `sso-check`, option `sso_token`, params `salt/nonce/user/bounce` |
| Overlay gate | div id `R2FvKSeqkPMZAnMV`; XOR key `3UYf-$iW$_oQHP^Eb$;L{U]G$01Wjh>_` |
| Easypost | token id `ep_99cec15bfac444bf8d0c938ec6954937`; headers `x-easypost-*`; option `easypost_homepage_placements`; drops `wp-content/easypost/easypost.php` + `mu-plugins/easypost-runtime.php` |
| Webshell | `index.zip` → `index.php`; auth param `$_REQUEST['a']` |
| Drop-in headers | `SC_DB_BEGIN:4.0.2`, `SC_ADV_BEGIN:4.0.3` |
| Hidden admin | email pattern `login@<domain>` |
| robots.txt | reset to `Allow: /` + injected sitemap |
| Maintenance lock | `.maintenance` = `<?php $upgrading = 2101150065; ?>` |

### A.2 SHA-256 (this forensic image)

```
084bdc75772b7a32aecc2ea2c4bf1563a38f77957e145714d4c9ebb9292b0739  shop.php
21ddc5d17df2988716155809b7b0d4e6031921598a4d1c05cad9f837549b029c  wp-slgnup.gz
26d1140a544d33e9a56cc9ed9e93532958c91077b5f8a103f621ca3d8a824e38  index.zip
014c15ba4ddd43bf795e199caa5b0ee0a4f4be4c555ebb2cb98dc4109de3d4a2  wp-content/50a9c554.php
7c1a18ccd1d13f29c386369b9d5fec8180c8e6ef8183ede57655ce8cf1e2a789  wp-content/.50a9c554.php
0d7b4d3100cb08ed70c7c039315b897968e601b2562e3695f6306a20c35c1a05  wp-content/cache/c7bad850.php
e8b0b552ff3d12a541520f4eadeacf4fed09b1a2b2916fe9d8c0a94b9b36ddf4  wp-content/mu-plugins/bold-conductor-snap.php
337fee21376d07b27f6bcf7ef7c85e74c3273aadff491137f524ab1cb1aa111d  wp-content/mu-plugins/sso-loader.php
a332193fd1fd87568ad9b9cc7d14186a674337d37370ef4cb1f19f2de6f0e491  wp-content/db.php
17cf74a755ef42b38690a43bbb47a62580e0476acb3e3f930051fca5137e6998  wp-content/advanced-cache.php
fe2d471a5e6f004466c156098fa3d1e6fa2b9d9cf89047ee4c1b9e18f1e68624  wp-content/1be2cc8d.zip
f05a161e538a0a690c80f997b05d2e09819f6a9f2e90452c49e6166471578cbb  wp-content/uploads/fcefabhjea.zip
044b70faaa555af0926eb892d0f88cf7d7021b17f506566f8a54d166854c88aa  wp-content/plugins/speed-optimizer/speed-optimizer.php
94b1542d6cc5fc1b2c7f19180b5905e1d5b0f59ae006216e6598623c38abedcf  wp-content/plugins/link-factory/link-factory.php
36a25e26d91a17fdbe8b251947e0c524213b3d478dbbbcc5e24c4865cdb4c9d0  wp-content/plugins/seo-flex-block/seo-flex-block.php
4cff9167fb2ffd939a14434e41519b08e1e0caefe93022500183fe3f97fca2ae  wp-content/plugins/easypost/easypost.php
d33a652e369e05c6853e46455648572c85e46f563bdfef3f38a81c7772542ac2  wp-content/themes/twentytwentyfive/functions.php
```
*The four other "Speed Optimizer" copies are byte-identical or near-identical drops of the same file under different directories (see §5).*

---

## Appendix B — Self-service blocking checklist (for operators not behind Hyx)

> Hyx customers are already covered by our deployed edge and server patterns. The single highest-leverage control is **egress filtering on the PHP tier**: the SC beacon and both cloakers are inert without outbound HTTP to C2.

**Server / origin (highest impact first)**
- [ ] **Egress allowlist from PHP workers.** Deny arbitrary outbound HTTP; permit only known-good destinations. Neutralises C2 beaconing and live-fetch cloaking.
- [ ] **Sinkhole** all eight C2 hostnames and `/super6.php` at your resolver/firewall.
- [ ] **Disable dangerous PHP** where feasible (`disable_functions`) and constrain file access with `open_basedir`; consider disabling `shmop` if unused.
- [ ] **Deny PHP execution** under `wp-content/uploads/` and `wp-content/cache/`.
- [ ] **Remove/block `auto_prepend_file`** you did not set; monitor `.user.ini`/`.htaccess`/`php.ini` for reintroduction.
- [ ] **File-integrity monitoring** on `robots.txt`, `wp-config.php`, active-theme `functions.php`, `wp-content/mu-plugins/`, and the drop-ins `db.php`/`advanced-cache.php`/`object-cache.php`; alert on new `.php`/`.zip`/`.rdt`/`.gz` in `uploads`/`cache`/plugin dirs.
- [ ] **Restart PHP workers** during and after IR to defeat shared-memory residency; watch for a future-dated `.maintenance`.

**Edge / WAF / CDN (if you run your own)**
- [ ] Block requests whose path/query contains `3061-link211` or `3121-bright152`.
- [ ] Block the magic-auth endpoint pattern: `admin-ajax.php?action=sso-check` (and any `sso_token` usage).
- [ ] Deny direct access to `.php`/`.zip` under `/wp-content/uploads/` and `/wp-content/cache/`, and to dot-prefixed PHP (`/\.[^/]+\.php$`).
- [ ] Block requests to `/wp-content/easypost/easypost.php` and any request bearing `x-easypost-*` headers.
- [ ] **Block/strip off-domain `Location:`** on 3xx responses (allowlist your own hosts) — defeats the redirect payloads.
- [ ] **Serve a canonical `robots.txt` from the edge** so origin tampering is invisible to crawlers.
- [ ] **Content-Security-Policy `script-src` allowlist** (report-only first, then enforce) — blocks the SC off-domain `<script>` and the Speed Optimizer overlay/redirect regardless of how injected.
- [ ] **Restrict `/wp-admin` and `/wp-login.php`** by IP allowlist or geofence — blocks interactive use of the rogue admin, forged cookies, and the SSO endpoint.
- [ ] **Flag admin sessions from unfamiliar ASNs/geos** (step-up auth) — forged cookies are cryptographically valid, so behaviour is the only edge angle.
- [ ] **Response-body scanning** for off-domain `<script src>`, hidden-link markers (`data-placement`, offset/opacity/visibility-hidden wrappers), and spam link patterns.

**Do NOT rely on**
- UA-agnostic aggressive caching as a "cloak breaker" — it can cache and serve the spam variant to real users.
- Dashboard audits of users/plugins/updates — the SC backdoor hides itself from all three.
- Blocklisting the SC magic GET parameter or the webshell param alone — they are per-site/rotating and have weak static signatures.

---

## Appendix C — Removal manifest (file/dir level, this host)

Delete together, then complete the database and process steps in §12. Verify byte-for-byte against a known-good WordPress before restoring.

```
# PHP prepend chain + SC drop-ins
.user.ini                                   (remove auto_prepend_file directive)
wp-content/50a9c554.php
wp-content/.50a9c554.php
wp-content/cache/c7bad850.php
wp-content/db.php
wp-content/advanced-cache.php
wp-content/mu-plugins/bold-conductor-snap.php

# SC archives + payload blobs + theme injection
wp-content/1be2cc8d.zip
wp-content/themes/twentytwentyfour/1be2cc8d.zip
wp-content/uploads/2026/08/1be2cc8d.zip
wp-content/uploads/fcefabhjea.zip
wp-content/plugins/hybrid-security/            (whole dir; 1.rdt..10.rdt)
wp-content/themes/twentytwentyfive/functions.php   (restore clean copy)

# Magic auth + cloakers + webshell
wp-content/mu-plugins/sso-loader.php
shop.php
wp-slgnup.gz
index.zip

# Signed injector (plugin + its drops)
wp-content/plugins/easypost/
wp-content/easypost/                            (if present / re-created)
wp-content/mu-plugins/easypost-runtime.php      (if present / re-created)

# Spam injectors
wp-content/plugins/link-factory/
wp-content/plugins/seo-flex-block/
wp-content/uploads/2026/07/seo-flex-block-2.zip

# Overlay cloaking gate (all five)
wp-content/plugins/speed-optimizer/
wp-content/plugins/speed-optimizer-1/
wp-content/plugins/defender-database-wordpress/
wp-content/plugins/visual-user/
wp-content/plugins/wp-shipping-aggregator-for/

# Empty registered shells + fake theme + filler clones
wp-content/plugins/solid-scanner-run/
wp-content/plugins/wp-security-helper/
wp-content/plugins/xadvanced-link-keeper-tgzns/
wp-content/plugins/xelite-pixel-stream-vlsid/
wp-content/plugins/xsilent-data-flow-kccma/
wp-content/themes/skyxoyj/
wp-content/plugins/apzvd/  wp-content/plugins/ggurr/  wp-content/plugins/uytxo/

# Anti-availability + verify
.maintenance                                   (remove future-dated lock)
.htaccess                                       (restore known-good template)

# Verify (legitimate but abusable — confirm authorised, else remove)
wp-content/plugins/wp-file-manager/
wp-content/plugins/fileorganizer/
wp-content/plugins/wp-cli-login-server/
```

Then (see §12): rotate keys/salts → remove hidden admin + malicious options/posts via DB → restart PHP workers → flush OPcache → rotate all credentials → close entry vector → re-scan. Given the breadth, prefer **rebuild from known-good source + vetted content export** over in-place cleaning where practical.

---

*Prepared by Hyx Security Research for customer distribution. Indicators rotate; revalidate against the linked vendor advisories periodically. Questions or additional samples: contact your Hyx security representative.*
