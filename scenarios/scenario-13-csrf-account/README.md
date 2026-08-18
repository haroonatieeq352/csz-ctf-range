# Scenario 13 — Cross-Site Request Forgery (CSRF)

- **Port:** `8013`
- **Category:** CSRF
- **Difficulty:** Medium
- **Flag:** `CTF{csrf_n0_t0k3n_pwn3d}`

## Walkthrough
1. Register or log in to your account at `http://<host>:8013/login`.
2. Notice the `POST /account/email` endpoint requires no CSRF anti-forgery token and lacks origin validation.
3. Submit a cross-origin form or submit an email ending with `@attacker-controlled.test`.
4. The server accepts the forged request and returns `CTF{csrf_n0_t0k3n_pwn3d}`.
