# CSZone Offensive Security Training Range
# python server.py 8080 
Two independent, complementary phases:

- **`ctf-platform/`** — static frontend range (recon, crypto/encoding,
  client-side access control). No backend required, deploy anywhere
  static hosting works. See `ctf-platform/SOLUTIONS-INTERNAL.md`.
- **`backend/`** — real Flask + SQLite backend (SQLi, stored XSS with a
  real cookie-theft chain, CSRF, file upload, SSRF, backend IDOR, cache
  deception, cache poisoning). Needs Python (or Docker). See
  `backend/README.md` for setup and `backend/SOLUTIONS-INTERNAL-BACKEND.md`
  for the answer key.
- **`participant-tools/`** — distribute to participants separately, never
  deploy alongside either app: `dir-wordlist.txt` (directory
  brute-forcing), `password-wordlist.txt` (offline hash cracking),
  `csrf-poc-change-email.html` (host on a different origin than the
  backend to demonstrate B4).

## Current flag count

- Frontend (static): **10** flags — E1-E4, M1-M3, H1-H3.
- Backend (Phase 1): **6** distinct scored flags across 8
  challenges/domains (two challenges, B1 and B3, share one flag as a
  chain; B5 and B9 are impact-demonstration challenges without their own
  flag by design — see the backend solutions doc for the reasoning and
  how to add flags to them if you want).
- **Total: 16 distinct flags**, verified end-to-end via
  `backend/verify_all.py` for all backend challenges and via manual
  `curl` testing (documented in each solutions doc) for all frontend
  challenges.

## Toward the 30-40 flag goal

This gets you roughly halfway. Domains not yet covered, for a future
phase: authentication/JWT attacks, NoSQL injection, SSTI, prototype
pollution, business logic flaws, insecure deserialization, GraphQL
misconfiguration, race conditions, and a second, harder tier of chained
scenarios that cross between the frontend and backend (e.g. a frontend
recon step that discloses a backend endpoint). The backend architecture
now in place (Flask blueprints pattern, shared cache middleware, DB
schema) is built to extend — new challenge modules can be added as new
routes + templates without touching the existing ones.
