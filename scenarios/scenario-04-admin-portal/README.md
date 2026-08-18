# Scenario 04 — Broken Access Control & Admin Relocation

- **Port:** `8004`
- **Category:** Web / Broken Access Control
- **Difficulty:** Medium
- **Flag:** `CTF{4dm1n_p4n3l_3xp0s3d}`

## Walkthrough
1. Open `http://<host>:8004/` in your browser and check the DevTools Console.
2. Observe the logged Base64 string `QWRtaW4gcGFuZWwgcmVsb2NhdGVkIHRvIC9wYW5lbC03YzRmMmEv`.
3. Decode with Base64: reveals `Admin panel relocated to /panel-7c4f2a/`.
4. Navigate to `http://<host>:8004/panel-7c4f2a/` and read the flag: `CTF{4dm1n_p4n3l_3xp0s3d}`.
