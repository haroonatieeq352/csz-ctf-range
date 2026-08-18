# Scenario 06 — Partner Promo & Client Cookie Gateway Guard

- **Port:** `8006`
- **Category:** Access Control / Cookie Manipulation
- **Difficulty:** Medium
- **Flag:** `CTF{h34d3r_c00k13_byp4ss}`

## Walkthrough
1. **Reconnaissance:** Inspect `http://<host>:8006/robots.txt` to discover `/promo-page/` and `/secure/`.
2. **Credential Discovery:** Navigate to `http://<host>:8006/promo-page/` and extract the partner encoded credential:
   `YWNjZXNzX2xldmVsPWFkbWluLTlmM2E=`
3. **Base64 Decoding:** Decode the token:
   `echo "YWNjZXNzX2xldmVsPWFkbWluLTlmM2E=" | base64 -d`
   Result: `access_level=admin-9f3a`
4. **Gateway Bypass:**
   - Navigate to `http://<host>:8006/secure/` (observing initial `403 Access Denied`).
   - Open Developer Tools (`F12`) &rarr; **Application** tab &rarr; **Cookies**.
   - Add a new cookie:
     - **Name:** `access_level`
     - **Value:** `admin-9f3a`
   - Refresh the page (`F5`).
5. **Flag Capture:** Access is granted and the Base64 flag token `Q1RGe2gzNGQzcl9jMDBrMTNfYnlwNHNzfQ==` is decrypted to `CTF{h34d3r_c00k13_byp4ss}`.
