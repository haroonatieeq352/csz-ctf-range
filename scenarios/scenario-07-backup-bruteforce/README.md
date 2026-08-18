# Scenario 07 — Backup Service Authentication & Burp Suite Intruder

- **Port:** `8007`
- **Category:** Web / Burp Suite Authentication Brute-Force & Crypto
- **Difficulty:** Hard
- **Flag:** `CTF{h4sh_cr4ck3d_4cc3ss}`
- **Credentials:** Username `svc_backup`, Salt `9c1f7a`, Password `Summer2024!`

## Walkthrough
1. Discover the hidden `/backup/` directory via wordlist/directory search.
2. View `/backup/` source comments -> points to `/backup/users.json`.
3. Fetch `http://<host>:8007/backup/users.json` -> observe username `svc_backup`, salt `9c1f7a`, target hash `5269a48d5eb030eee36c71eaa9edbfec94b52cb042ad98cad03bf8e7be20f723`, and wordlist link.
4. Send `GET /backup/login.html?username=svc_backup&password=test` to **Burp Suite Intruder** (`Ctrl+I`).
5. Attack password parameter with the 20-candidate wordlist (`participant-tools/password-wordlist.txt`).
6. Identify valid password: `Summer2024!`.
7. Authenticate on `http://<host>:8007/backup/login.html` -> reveals Base64 flag token `Q1RGe2g0c2hfY3I0Y2szZF80Y2Mzc3N9` -> decode to `CTF{h4sh_cr4ck3d_4cc3ss}`.
