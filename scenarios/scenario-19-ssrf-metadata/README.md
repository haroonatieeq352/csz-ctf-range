# Scenario 15 — Server-Side Request Forgery (SSRF)

- **Port:** `8015`
- **Category:** SSRF
- **Difficulty:** Medium
- **Flag:** `CTF{ssrf_1nt3rn4l_m3t4d4t4}`

## Walkthrough
1. Log in or register an account at `http://<host>:8015/login`.
2. Navigate to `http://<host>:8015/avatar-import`.
3. Test direct access to `http://<host>:8015/internal/metadata` — observe that external access is restricted by IP address guard.
4. Input the loopback metadata URL into the avatar import form:
   `http://127.0.0.1:8015/internal/metadata`
5. The server fetches the internal endpoint locally and renders the JSON metadata response containing `CTF{ssrf_1nt3rn4l_m3t4d4t4}`.
