# CSZone Backend Range — Setup

Real Flask + SQLite backend, Phase 1 of the expansion beyond the static
frontend range. Covers SQL injection, stored XSS with a real cookie theft
chain, CSRF, unrestricted file upload, SSRF, backend IDOR, cache
deception, and cache poisoning — the domains that structurally cannot be
built into a static site.

## Quick start (local, no Docker)

```bash
pip install -r requirements.txt
python db.py          # creates instance/range.db from schema.sql
python app.py 5000     # runs on http://localhost:5000
```

## Quick start (Docker, recommended for real participants)

```bash
docker build -t csz-range-backend .
docker run -p 5000:5000 csz-range-backend
```

For multiple teams running in parallel without shared state, see
`docker-compose.yml` — one container per team, one SQLite file per
container, one in-process cache per container. This matters: several
challenges here (stored XSS, cache deception, cache poisoning) rely on
shared state, and one team's actions must never be visible to another
team's instance.

**Note on this repo's testing:** Docker was not available in the sandbox
this was built in, so the Dockerfile follows standard, well-tested
patterns but was not itself executed in a container during this build.
The Flask app was tested directly and extensively (see
`verify_all.py`). Test the `docker build`/`docker run` path yourself
before relying on it for a live session.

## Verifying the build

`verify_all.py` plays through every exploit chain end-to-end against a
running instance (start the server first, then run it):

```bash
python app.py 5000 &
python verify_all.py
```

All 9 challenges are checked programmatically. One line in the SSRF
section is informational, not a pass/fail — see the comment in that
script for why (same-host testing can't distinguish "internal" from
"external" the way a real network topology can).

## Seeded accounts

| Username    | Password      | Purpose                                   |
|-------------|---------------|--------------------------------------------|
| participant | Range2024!    | Standard account, holds the cache-deception flag in its profile |
| (legacy admin portal, not a `users` row) | see SOLUTIONS-INTERNAL-BACKEND.md | SQLi target only |

`finance_bot` (id=2) exists as the IDOR target — its order notes hold
that flag. Nobody is meant to log in as it directly; its password hash
is random and thrown away at seed time.

## Deploying alongside the static frontend

This backend is independent of `ctf-platform/` (the static site). Run
them on different ports/subdomains and link between them from each
site's homepage if you want one combined range. They do not share
sessions, databases, or the cache layer — that's intentional; keeping
them isolated makes it much easier to reason about what's cacheable,
what's stateful, and what needs per-participant isolation.

## What's deliberately NOT hardened (by design)

Every intentional vulnerability is tagged `# VULN:` in `app.py` — grep
for that to get the full list without cross-referencing the solutions
doc. Everything else (registration, real login, session handling,
`/orders` list view, `/directory` column structure) uses parameterized
queries, hashed passwords, and proper access checks, so participants
learn to tell the difference between a hardened endpoint and a broken
one in the same codebase — which is what a real internal app usually
looks like.
