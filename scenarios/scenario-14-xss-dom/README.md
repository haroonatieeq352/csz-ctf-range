# Scenario 14: DOM-based XSS (Client-Side Source & Sink)

- **Port:** `8014`
- **Vulnerability:** DOM-based Cross-Site Scripting
- **Flag:** `CTF{d0m_xss_s1nk_m4st3r}`

## Exploitation Walkthrough
1. Access `http://<host>:8014/analytics`.
2. Inspect page source / Developer Tools to analyze client-side script execution.
3. Identify the **Source** (`window.location.search` via `URLSearchParams`) and the **Sink** (`document.getElementById("telemetry-content").innerHTML`).
4. Identify that internal telemetry keys are stored in `window.__TELEMETRY_KEY`.
5. Craft a DOM XSS payload in the `tab` parameter:
   ```text
   http://<host>:8014/analytics?tab=<img src=1 onerror="document.getElementById('extracted-vault').innerText=window.__TELEMETRY_KEY">
   ```
6. The payload executes client-side during DOM parsing and discloses the flag.
