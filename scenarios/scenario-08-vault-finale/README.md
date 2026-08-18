# Scenario 08 — Central Security Vault (Dual-Key Finale)

- **Port:** `8008`
- **Category:** Chained Web Exploitation & Multi-Byte XOR Cryptography
- **Difficulty:** Hard
- **Flag:** `CTF{ch41n_c0mpl3t3_m4st3r}`
- **Required Artifacts:**
  1. Administrative Cookie: `access_level=admin-9f3a` (from Scenario 06)
  2. Service Credential Password: `Summer2024!` (from Scenario 07)

## Walkthrough
1. Access `http://<host>:8008/finale/index.html`.
2. Supply `key=Summer2024!` via form or query string `?key=Summer2024!`.
3. Include cookie `access_level=admin-9f3a` via browser console / Burp Suite Repeater.
4. The gate unlocks and reveals the encrypted vault ciphertext: `ECErFgNDXARea0I7QVwDOhECXUJYEidGEA==`.
5. XOR decrypt the Base64 ciphertext with key `Summer2024!` in CyberChef or Python to retrieve `CTF{ch41n_c0mpl3t3_m4st3r}`.
