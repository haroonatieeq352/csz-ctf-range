# Scenario 17 — Web Cache Deception & Cache Poisoning

- **Port:** `8017`
- **Category:** Web Cache Attacks
- **Difficulty:** Hard
- **Flag:** `CTF{c4ch3_d3c3pt10n_l34k}`

## Walkthrough
### 1. Web Cache Deception (Flag Capture)
1. Log in to `http://<host>:8017/login` with credentials `participant` / `Range2024!`.
2. As the authenticated victim, request the static lookalike path:
   `http://<host>:8017/account/profile/legacy-theme.css`
3. The server renders the authenticated profile containing the personal note and the in-process cache middleware stores the response keyed by path only (`X-Cache: MISS`).
4. Now, issue an unauthenticated GET request to the exact same path:
   `curl http://<host>:8017/account/profile/legacy-theme.css`
5. The cached response is returned (`X-Cache: HIT`) containing the victim's personal note and the flag `CTF{c4ch3_d3c3pt10n_l34k}`!

### 2. Web Cache Poisoning (Impact Demonstration)
1. Request `http://<host>:8017/promo/partner-banner` with the header:
   `X-Forwarded-Host: evil-attacker-domain.test`
2. The response reflects the attacker domain in the canonical link and primes the shared cache (`X-Cache: MISS`).
3. Subsequent requests from any user now receive the poisoned cached response (`X-Cache: HIT`).
