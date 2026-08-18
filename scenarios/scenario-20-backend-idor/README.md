# Scenario 16 — Backend Insecure Direct Object Reference (IDOR)

- **Port:** `8016`
- **Category:** Web / Backend IDOR
- **Difficulty:** Medium
- **Flag:** `CTF{b4ck3nd_1d0r_r34l}`

## Walkthrough
1. Log in or register an account at `http://<host>:8016/login` (or log in with `participant` / `Range2024!`).
2. Go to `http://<host>:8016/orders` and inspect your order (Order #1).
3. Change the order ID in the URL to `http://<host>:8016/orders/2`.
4. Notice that Order #2 belongs to `finance_bot` and displays internal audit notes containing `CTF{b4ck3nd_1d0r_r34l}`.
