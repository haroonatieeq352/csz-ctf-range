# CSZone Offensive Security Range — Internal Solutions Guide

**Confidential — do not distribute to participants.** This document exists
for QA and difficulty calibration only.

**Revision note (2026-07-24):** full QA pass against the shipped code.
Fixed: E1 flag was missing from the app entirely; E2 and E3 walkthroughs
were out of date with the actual (more chained/encoded) mechanisms in the
code; a previously undocumented header-based flag was added as E4; the
directory wordlist and a new password-cracking wordlist were split and
moved to a sibling `participant-tools/` folder so they can't be
accidentally deployed with the app; a ticket-number typo, a palette
violation in CSS, and a `bruteforce.py` default-target inconsistency were
also fixed. See each section's "QA fix" notes for specifics. Total scored
flags: **10** (was effectively 8 working out of 9 documented before this
pass).

---

## E1 — Comments Don't Lie
- **Category:** Recon | **Difficulty:** Easy
- **Story given to participants:** "Start at the homepage. Not everything
  meant for developers gets removed before launch."
- **Where hidden:** HTML comment in `index.html`, directly below the
  staging TODO comment, above the `<header>` tag.
- **Flag:** `CTF{h1dd3n_1n_pl41n_s1ght}`
- **Walkthrough:** Open the homepage → right-click → "View Page Source"
  (or `Ctrl+U`) → read the comment block near the top of the file. Two
  comments sit together here — a staging TODO and the flag note right
  after it — so participants should read past the first comment, not
  stop at it.
- **Tools:** Browser view-source only.
- **QA fix (2026-07-24):** this flag was previously documented but not
  actually present anywhere in the shipped files — the challenge was
  unsolvable. Now fixed in `index.html`.

---

## E2 — Robots Talk Too Much
- **Category:** Recon | **Difficulty:** Easy
- **Story:** "Search engines aren't the only ones who read `robots.txt`."
- **Where hidden:** `/robots.txt` discloses `/recon-notes/`. That page is
  a deprecation notice — it doesn't hold the flag directly, but its body
  text and an HTML comment both point to an unpurged sub-directory,
  `/recon-notes/ops-archive/`. That directory returns a 403 index page,
  but it also contains an HTML comment naming a specific file,
  `session-dump.log`, which is directly fetchable and contains a
  Base64-encoded `session.integrity_token`.
- **Flag:** `CTF{r0b0ts_d1scl0s3_p4ths}`
- **Walkthrough:**
  1. Visit `/robots.txt` → note the `Disallow` entries, including
     `/recon-notes/`.
  2. Visit `/recon-notes/` → read the deprecation notice, which mentions
     an unpurged sub-directory and view-source to find the HTML comment
     confirming the sub-directory name: `ops-archive/`.
  3. Visit `/recon-notes/ops-archive/` → directory listing is blocked
     (403), but view-source on that 403 page reveals an HTML comment
     naming `session-dump.log`.
  4. Fetch `/recon-notes/ops-archive/session-dump.log` directly → find
     the `session.integrity_token` value → decode via Base64.
- **Tools:** Browser (view-source at each hop). No brute-forcing needed —
  every hop is disclosed via a comment or body text at the previous step.
- **QA fix (2026-07-24):** original doc described this as a single hop
  with the flag directly in the page body. The shipped implementation is
  a three-hop chain (robots.txt → recon-notes comment → ops-archive
  comment → session-dump.log). This is arguably better recon practice
  than the original design, so the code was kept and the doc updated
  to match instead of simplifying the challenge.

---

## E3 — Inspect Me
- **Category:** Recon + light Crypto | **Difficulty:** Easy
- **Story:** "The homepage loads a script. Not every variable in that
  script gets used — and one of them didn't want to be read directly."
- **Where hidden:** `main.js`, in the `window.__c` property. The value is
  Base64-encoded, then single-byte XOR'd with a key. The key itself
  (`85`) is disclosed separately in `js-config.json` as the `dbg_key`
  field, and the code comment above `__c` explicitly points there.
- **Flag:** `CTF{unus3d_v4r14bl3_l34k}`
- **Walkthrough:**
  1. View page source → follow `<script src="main.js">` → read the file
     → find `window.__c = 'FgETLiA7ICZmMQojYSdkYTc5Zgo5ZmE+KA=='` and the
     comment pointing to `/js-config.json -> dbg_key`.
  2. Fetch `/js-config.json` → note `"dbg_key": 85`.
  3. Base64-decode the `__c` value, then XOR every byte against `85`
     (single repeating byte key, not a string). In CyberChef: recipe
     "From Base64" → "XOR" (key `85`, as a decimal/number, not text).
- **Tools:** Browser DevTools (Sources/Network tab) or `curl`, plus
  CyberChef (or a short script) for the Base64 + XOR step.
- **QA fix (2026-07-24):** original doc described this as a plain unused
  variable with no decode step, but the shipped code requires a real
  Base64+XOR decode using a key sourced from a second file. The real
  mechanism is more interesting than the original description, so the
  doc was corrected to match the code rather than simplifying the
  challenge. Note this makes E3 marginally harder than a typical "Easy"
  — flag it during difficulty calibration if running with a very junior
  cohort.

---

## E4 — Header Hunter
- **Category:** Recon / HTTP Fundamentals | **Difficulty:** Easy
- **Story given to participants:** "The page content isn't the only thing
  the server sends you. Look at what comes before the HTML."
- **Where hidden:** every HTTP response on this range carries an
  `X-Debug-Info` response header containing the flag directly (no
  encoding). Injected via `server.py` (`end_headers`), and duplicated in
  `_headers` (Netlify) / `.htaccess` (Apache) / `vercel.json` (Vercel) so
  it survives regardless of hosting platform.
- **Flag:** `CTF{h34d3r_hunt3r_pr0}`
- **Walkthrough:** `curl -I https://<host>/` (or check the Network tab
  in DevTools on any request) → read the `X-Debug-Info` response header.
- **Tools:** `curl -I`, or Burp/DevTools Network tab.
- **QA fix (2026-07-24):** this flag existed in the code since the first
  build (`server.py` even labels it "Scenario 1" in a comment) but was
  never added to this document. It is being formally documented now.
  **Hosting caveat:** this challenge only works if the host actually
  serves custom response headers. Netlify (`_headers`) and Vercel
  (`vercel.json`, added in this fix) both work; Apache with `.htaccess`
  enabled works. **GitHub Pages does not support custom response headers
  at all** — if you deploy there, this flag silently disappears with no
  error. Don't offer GitHub Pages as a hosting option while this
  challenge is in scope.

---

## M1 — The Admin's Shortcut
- **Category:** Web / Broken Access Control | **Difficulty:** Medium
- **Story:** "An admin panel exists somewhere on this range. It has no
  login page. Find out where it moved."
- **Where hidden:** `main.js` logs a Base64 string to the browser console
  on every page load, decoding to the panel path `/panel-7c4f2a/`. The
  panel itself has no auth and displays the flag directly.
- **Flag:** `CTF{4dm1n_p4n3l_3xp0s3d}`
- **Walkthrough:**
  1. Open DevTools Console on the homepage.
  2. Observe the logged Base64 string: `QWRtaW4gcGFuZWwgcmVsb2NhdGVkIHRvIC9wYW5lbC03YzRmMmEv`
  3. Decode via CyberChef or `echo <string> | base64 -d` → reveals
     `Admin panel relocated to /panel-7c4f2a/`
  4. Navigate to `/panel-7c4f2a/` → read the flag.
- **Tools:** Browser DevTools Console, CyberChef or `base64` CLI.

---

## M2 — IDOR Invoice
- **Category:** Web / IDOR | **Difficulty:** Medium
- **Story:** "You've been given access to your own invoice. Everyone's
  invoice lives in the same place."
- **Where hidden:** `/invoices/invoice.html?id=1001` fetches
  `/invoices/invoices.json` at runtime and renders the record matching the
  `id` query parameter. Record `id: 1007` (Finance Department) contains
  the flag Base64-encoded in `internal_notes`.
- **Flag:** `CTF{1d0r_1nv01c3_l34k}`
- **Walkthrough:**
  1. Load `/invoices/invoice.html` (defaults to id 1001, "Guest Account").
  2. Notice the `id` parameter controls which record is shown, with no
     ownership check.
  3. Try adjacent/plausible IDs — `1004`, `1007`, `1009` — either by
     manual guessing or by inspecting `invoices.json` directly via
     Network tab / direct fetch.
  4. On `id=1007`, the `internal_notes` field contains
     `Q1RGezFkMHJfMW52MDFjM19sMzRrfQ==` — decode via Base64.
- **Tools:** Browser address bar / Burp Repeater for parameter tampering,
  Base64 decode (CyberChef).

---

## M3 — Base64 Breadcrumb
- **Category:** Cryptography | **Difficulty:** Medium
- **Story:** "A partner promo page leaked into the public web root.
  'Encoded for transport' is not the same thing as 'protected.'"
- **Where hidden:** `robots.txt` discloses `/promo-page/`, which displays
  a Base64 blob.
- **Flag:** `CTF{b4s364_1s_n0t_3ncrypt10n}`
- **Walkthrough:** Visit `/robots.txt` → visit `/promo-page/` → copy the
  code block → decode via CyberChef or `base64 -d`.
- **Tools:** Browser, CyberChef or `base64` CLI.

---

## H1 — Burp the Bypass
- **Category:** Web / Client-Side Access Control | **Difficulty:** Hard
- **Story:** "This section rejects you by default. It trusts something
  about your session that you control more than it thinks."
- **Where hidden:** `/robots.txt` discloses `/secure/`. The page source
  contains an HTML comment with a Base64-encoded cookie requirement
  (`access_level=admin-9f3a`). Once that cookie is set in the browser, a
  hidden `<div>` is revealed containing a second Base64-encoded flag.
- **Flag:** `CTF{h34d3r_c00k13_byp4ss}`
- **Walkthrough:**
  1. Visit `/robots.txt` → find `/secure/`.
  2. View page source of `/secure/index.html` → find the HTML comment:
     `YWNjZXNzX2xldmVsPWFkbWluLTlmM2E=`
  3. Decode → `access_level=admin-9f3a`.
  4. Set this cookie on the domain — via Burp (Proxy intercept → add
     `Cookie: access_level=admin-9f3a` header on the request, or use
     Burp's browser and the "Add cookie" option), or via DevTools
     Application tab / `document.cookie = "access_level=admin-9f3a"` in
     console.
  5. Reload the page → hidden payload `Q1RGe2gzNGQzcl9jMDBrMTNfYnlwNHNzfQ==`
     appears → decode via Base64.
- **Tools:** Burp Suite (Proxy/Repeater, or its embedded browser) or
  DevTools Application tab, plus Base64 decode.
- **Design note:** because this range is fully static (no server-side
  logic), the "access control" is enforced client-side via a cookie check
  in JavaScript rather than a true server-side header/session check. This
  still requires the same practical skill — inspecting source, decoding a
  hint, and manipulating a request/session artifact via Burp or DevTools
  — but is not equivalent to bypassing a real server-side auth control.
  Flag it to participants as a simulated control if asked.

---

## H2 — Hash and Seek (Scenario 7: Backup Service Authentication)
- **Category:** Web / Burp Suite Authentication Brute-Force & Crypto | **Difficulty:** Hard
- **Story:** "There's a quarantined backup directory that never made it into the
  public sitemap or robots.txt. Find it, extract the leaked service metadata, and authenticate."
- **Where hidden:** `/backup/index.html` returns 403 with HTML comments pointing to `/backup/users.json`.
  `/backup/users.json` leaks the service username `svc_backup`, salt (`9c1f7a`), and SHA-256 target hash (`5269a48d5eb030eee36c71eaa9edbfec94b52cb042ad98cad03bf8e7be20f723`),
  along with links to the scenario PDF briefing and candidate password list.
  Authenticating at `/backup/login.html` reveals the flag.
- **Flag:** `CTF{h4sh_cr4ck3d_4cc3ss}` (Base64: `Q1RGe2g0c2hfY3I0Y2szZF80Y2Mzc3N9`)
- **Credentials for QA:** username `svc_backup`, salt `9c1f7a`, password `Summer2024!`
- **Burp Suite Community Edition Walkthrough:**
  1. **Recon & Discovery:** Discover `/backup/` via wordlist directory search (e.g. `gobuster`, `dirb`, or Burp Intruder).
  2. **Information Leakage Analysis:** Visit `/backup/` → Inspect response in Burp Proxy / HTTP History to find HTML comments pointing to `/backup/users.json`.
  3. **Metadata & Credential Schema Extraction:** Fetch `http://<host>/backup/users.json` → Observe `svc_backup`, salt `9c1f7a`, `hash_algo: sha256(salt+password)`, and the cloud/local wordlist link.
  4. **Burp Decoder / Hash Analysis (Optional):** Inspect and decode any Base64 comments or verify hashes in Burp Decoder.
  5. **Burp Intruder Brute-Force Attack:**
     - Open `/backup/login.html` in browser through Burp Proxy.
     - Send the request to **Burp Intruder** (`Ctrl+I`).
     - Configure attack position on password: `GET /backup/login.html?username=svc_backup&password=§candidate§`.
     - Load/paste the 20 password candidates from the provided cloud list (or `participant-tools/password-wordlist.txt`).
     - Run the attack and sort results by Response Length / look for "Authentication Successful!".
     - Identify valid password: `Summer2024!`.
  6. **Authentication & Flag Capture:** Submit `svc_backup` and `Summer2024!` on `/backup/login.html` → Flag `CTF{h4sh_cr4ck3d_4cc3ss}` is displayed.
- **Tools:** Burp Suite Community Edition (Proxy, HTTP History, Decoder, Intruder Sniper), or Gobuster + Hashcat (offline mode 1420 `sha256($salt.$pass)`).
- **QA note:** Password `Summer2024!` is required for the final checkpoint (Scenario 8 / H3), preserving 100% full-chain continuity.

---

## H3 — Full Chain Finale (Scenario 8: Central Security Vault)
- **Category:** Combined Chained Exploitation & Multi-byte XOR Cryptography | **Difficulty:** Hard
- **Story:** "This final checkpoint doesn't accept fresh logins. It wants proof
  you've already been here before — twice: an admin session marker and a recovered service credential."
- **Where hidden:** `/finale/index.html` requires **both**:
  (a) `Cookie: access_level=admin-9f3a` (recovered from Scenario 6), and
  (b) `?key=Summer2024!` (recovered password from Scenario 7).
  When both conditions are met, the vault unlocks and reveals the encrypted vault ciphertext: `ECErFgNDXARea0I7QVwDOhECXUJYEidGEA==`.
- **Flag:** `CTF{f1n4l_ch41n_c0mpl3t3}`
- **Burp Repeater & Chained Exploitation Walkthrough:**
  1. **Ensure Artifacts are in hand:**
     - Scenario 6 Cookie: `access_level=admin-9f3a`
     - Scenario 7 Credential: `Summer2024!`
  2. **Burp Repeater Request Crafting:**
     - In Burp Suite Proxy, capture any request to `/finale/index.html`.
     - Send the request to **Burp Repeater (`Ctrl + R`)**.
     - Edit the request line to:
       `GET /finale/index.html?key=Summer2024! HTTP/1.1`
     - Add the Cookie header:
       `Cookie: access_level=admin-9f3a`
     - Send the request (`Ctrl + Space` or Send button).
     - Response status returns `X-Vault-Status: VAULT_UNLOCKED` and renders the Vault Unlocked section with encrypted token `ECErFgNDXARea0I7QVwDOhECXUJYEidGEA==` and the final flag.
  3. **Multi-byte XOR Decryption (CyberChef):**
     - Input: `ECErFgNDXARea0I7QVwDOhECXUJYEidGEA==`
     - Recipe: `From Base64` ➔ `XOR` (Key: `Summer2024!`, Type: `UTF-8` / `Standard`)
     - Output: `CTF{f1n4l_ch41n_c0mpl3t3}`
- **Tools:** Burp Suite Repeater / Browser with DevTools Application Tab + CyberChef.

---

## Deployment Checklist
1. Host the `ctf-platform/` folder as a static site. **E4 (Header
   Hunter) depends on the host actually serving custom response
   headers** — this is not universal across the platforms below:
   - **Netlify** — works, via `_headers`.
   - **Vercel** — works, via `vercel.json` (added 2026-07-24; the
     `_headers` file alone does *not* work on Vercel).
   - **Apache / S3+Nginx with Apache in front** — works, via
     `.htaccess`, but only if `AllowOverride` permits it and
     `mod_headers` is enabled. Plain Nginx does not read `.htaccess` —
     needs its own `add_header` directives in the server block instead.
   - **GitHub Pages — does NOT support custom response headers.** If
     you deploy here, E4 silently breaks with no error. Do not offer
     GitHub Pages while E4 is in scope, or drop E4 for that deployment.
2. Do **not** publish anything in `participant-tools/` or
   `SOLUTIONS-INTERNAL.md` inside the hosted app. `participant-tools/`
   (containing `dir-wordlist.txt` and `password-wordlist.txt`) sits as a
   sibling folder to `ctf-platform/` specifically so it's never
   accidentally deployed alongside it — distribute its contents to
   participants separately as the "tools provided" pack, and keep this
   solutions file entirely internal.
3. If using `server.py` directly instead of a static host, its
   `BLOCKED_FILES` list is defense-in-depth for admin/config files —
   but it only helps if those files are actually present in
   `ctf-platform/`. Since `participant-tools/` is now a sibling folder,
   this is redundant in the recommended layout, but keep it as a
   safeguard in case files get copied in manually.
4. Confirm HTTPS is enabled on the host — `crypto.subtle` (used in H2/H3)
   requires a secure context and will silently fail over plain HTTP.
5. Test the full chain end-to-end in an incognito/private window before
   go-live, to confirm no cached cookies or state carry over between
   test runs.
6. Consider rate-limiting or monitoring if hosting somewhere with request
   logs, purely to catch accidental scanner misuse — not required for
   the challenges themselves.
