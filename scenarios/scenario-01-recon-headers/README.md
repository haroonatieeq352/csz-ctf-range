# Scenario 01 — Target Reconnaissance & HTTP Debug Headers

- **Port:** `8001`
- **Category:** Reconnaissance / HTTP
- **Difficulty:** Easy
- **Flag:** `CTF{h34d3r_hunt3r_pr0}`

## Walkthrough
1. **Source Inspection:** Open `http://<host>:8001/` in your browser and view page source (`Ctrl+U`).
2. Notice the developer staging comment referencing ticket `OPS-4471`:
   `<!-- TODO @devops: staging build — strip all debug response headers before this goes to prod. Ops keeps complaining, so Kindly review response headers, Ticket: OPS-4471 -->`
3. **HTTP Header Inspection:** Open DevTools (`F12`) -> Network Tab (or run `curl -I http://<host>:8001/`).
4. Inspect the HTTP response headers and extract `X-Debug-Info: CTF{h34d3r_hunt3r_pr0}`.esponse header.
