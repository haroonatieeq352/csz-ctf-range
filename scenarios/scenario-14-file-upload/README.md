# Scenario 14 — Unrestricted File Upload & Stored XSS

- **Port:** `8014`
- **Category:** File Upload / Stored XSS
- **Difficulty:** Medium

## Walkthrough
1. Log in or register an account at `http://<host>:8014/login`.
2. Navigate to `http://<host>:8014/upload`.
3. Attempt to upload server-side scripts like `.php` or `.py` — observe that they are blocked by the extension blocklist.
4. Upload an HTML file containing JavaScript (e.g. `pwn.html` with `<script>alert(document.domain)</script>`).
5. The file is successfully stored in `/static/uploads/pwn.html`.
6. Accessing `http://<host>:8014/static/uploads/pwn.html` executes JavaScript directly in the origin context.
