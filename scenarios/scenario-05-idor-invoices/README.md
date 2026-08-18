# Scenario 05 — Insecure Direct Object Reference (IDOR)

- **Port:** `8005`
- **Category:** Web / IDOR
- **Difficulty:** Medium
- **Flag:** `CTF{1d0r_1nv01c3_l34k}`

## Walkthrough
1. Access `http://<host>:8005/invoices/invoice.html?id=1001`.
2. Notice the `id` query parameter is directly rendered from the client-side JSON endpoint.
3. Test IDs (e.g. `1004`, `1007`, `1009`) or inspect `http://<host>:8005/invoices/invoices.json`.
4. Invoice `1007` contains internal notes with Base64 payload `Q1RGezFkMHJfMW52MDFjM19sMzRrfQ==`.
5. Base64 decode to reveal `CTF{1d0r_1nv01c3_l34k}`.
