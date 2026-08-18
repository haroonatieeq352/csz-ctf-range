# Scenario 02 — Robots.txt & Ops Archive Recon

- **Port:** `8002`
- **Category:** Recon / Directory Traversal
- **Difficulty:** Easy
- **Flag:** `CTF{r0b0ts_d1scl0s3_p4ths}`

## Walkthrough
1. Fetch `http://<host>:8002/robots.txt` and note the disallowed `/recon-notes/` path.
2. Visit `http://<host>:8002/recon-notes/` and view source to find the comment mentioning `ops-archive/`.
3. Visit `http://<host>:8002/recon-notes/ops-archive/` -> 403 Forbidden page reveals comment pointing to `session-dump.log`.
4. Fetch `http://<host>:8002/recon-notes/ops-archive/session-dump.log`.
5. Extract Base64 string `Q1RGe3IwYjB0c19kMXNjbDAzM19wNHRoc30=` and decode to get `CTF{r0b0ts_d1scl0s3_p4ths}`.
