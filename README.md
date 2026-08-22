# CSZone Cyber Range — Enterprise CTF Training Platform

A high-concurrency, production-grade offensive security and web penetration testing training platform. Features **21 isolated vulnerability scenarios** unified through the **Central Operations Hub**, supporting both local sandbox development and enterprise production deployments with subdomain routing, WSGI multi-threading, and DDoS mitigation.

---

## 🏛️ Architecture & Deployment Modes

The platform supports two distinct operational modes:

| Feature | 🛠️ Local Development Mode (`docker-compose.yml`) | 🌐 Production Deployment Mode (`docker-compose.prod.yml`) |
|---|---|---|
| **Primary Domain** | `http://localhost:8000` | `https://hub.offensivegrid.com` |
| **Scenario Access** | Dedicated Ports (`http://localhost:8001` - `8021`) | Subdomains (`https://s01.offensivegrid.com` - `s21.offensivegrid.com`) |
| **Reverse Proxy** | None (Direct Host Binding) | Nginx Edge Proxy (Ports 80/443 with SSL/TLS) |
| **Concurrency Engine** | Threaded Socket / Werkzeug | Gunicorn Multi-Worker / Multi-Threaded WSGI |
| **Target Audience** | Local Developer / Offline Lab | 100–150 Concurrent Students & Live CTF Competitions |
| **DDoS Protection** | Active (Sliding Window Token Limiter) | Active (Nginx Buffer Zones + In-App Rate Limiter) |

---

## ⚡ Concurrency & DDoS Protection Specs

- **100–150 Concurrent Users:** Flask scenarios (`09` through `21` and `backend`) run under **Gunicorn** with 4 workers and 4 threads per worker (`--worker-class=gthread`), processing up to 16 simultaneous requests per scenario container without blocking or request timeouts.
- **SQLite WAL Mode:** All database scenarios use `PRAGMA journal_mode=WAL;` and `busy_timeout=5000;` enabling lock-free concurrent reads and writes across simultaneous student actions.
- **DDoS Mitigation (Sliding Window Token Limiter):**
  - Standard scenarios: **60 requests/minute** per IP/Token.
  - Scenario 07 (Brute-Force Auth): **120–200 requests/minute** buffer for legitimate Intruder testing.
  - Returns `HTTP 429 Too Many Requests` with `Retry-After` headers and automatic 60-second soft reset without kernel-level IP bans.

---

## 🚀 Quick Start Guide

### Prerequisites
- **Python 3.9+** (for native run) OR **Docker & Docker Compose** (recommended for production).
- Install Python requirements:
  ```bash
  pip install -r requirements.txt
  ```

---

### Method 1: Production Docker Deployment (DevOps VPS)

To deploy the full production stack with the Nginx subdomain reverse proxy:

```bash
# 1. Clone repository and switch to dev branch
git clone https://github.com/haroonatieeq352/csz-ctf-range.git
cd csz-ctf-range
git checkout dev

# 2. Launch production multi-container cluster
docker compose -f docker-compose.prod.yml up -d --build

# 3. Check service health
docker compose -f docker-compose.prod.yml ps

# 4. View real-time logs
docker compose -f docker-compose.prod.yml logs -f
```

---

### Method 2: Local Development Docker Deployment

To launch all scenarios mapped to individual ports (`8000`–`8021`) on localhost:

```bash
docker compose -f docker-compose.yml up -d --build
```

---

### Method 3: Standalone Python Deployment (No Docker Required)

```bash
# Start all 21 scenarios + Central Hub in parallel
python start_all.py

# Run master automated end-to-end verification suite
python verify_all_scenarios.py

# Run concurrency and DDoS rate-limiting validation suite
python test_production_concurrency_and_ddos.py

# Stop all background services
python stop_all.py
```

---

## 🛡️ VPS Firewall & Fail2ban Configuration (Important for DevOps)

Because CTF platforms intentionally involve brute-forcing (Scenario 07), fuzzing, and directory discovery, **do NOT enable HTTP/Nginx jails in Fail2ban**, as this will ban student IPs during legitimate exercises:

1. **Allow Web Ports on VPS Firewall:**
   ```bash
   sudo ufw allow 80/tcp
   sudo ufw allow 443/tcp
   ```

2. **Configure Fail2ban for SSH only:**
   Ensure `/etc/fail2ban/jail.local` only enables the `[sshd]` jail, and disables `[nginx-http-auth]`, `[nginx-botsearch]`, and `[nginx-limit-req]`.

---

## 🗺️ Master Target Scenarios & Vulnerability Catalog

| Subdomain Route | Local Port | Scenario Name | Category | Objective / Flag Summary |
|---|---|---|---|---|
| `hub.offensivegrid.com` | `8000` | **Central Operations Hub** | Portal Console | Real-time scenario launcher & tracking catalog |
| `s01.offensivegrid.com` | `8001` | Scenario 01: Recon & Headers | Reconnaissance | `CTF{h34d3r_hunt3r_pr0}` |
| `s02.offensivegrid.com` | `8002` | Scenario 02: Robots & Ops Archive | Reconnaissance | `CTF{r0b0ts_d1scl0s3_p4ths}` |
| `s03.offensivegrid.com` | `8003` | Scenario 03: JS & Crypto XOR | Cryptography | `CTF{unus3d_v4r14bl3_l34k}` |
| `s04.offensivegrid.com` | `8004` | Scenario 04: Admin Portal Leak | Access Control | `CTF{4dm1n_p4n3l_3xp0s3d}` |
| `s05.offensivegrid.com` | `8005` | Scenario 05: Frontend IDOR | IDOR | `CTF{1d0r_1nv01c3_l34k}` |
| `s06.offensivegrid.com` | `8006` | Scenario 06: Promo & Cookie Gate | Access / Crypto | `CTF{h34d3r_c00k13_byp4ss}` |
| `s07.offensivegrid.com` | `8007` | Scenario 07: Backup Service Auth | Authentication | `CTF{h4sh_cr4ck3d_4cc3ss}` |
| `s08.offensivegrid.com` | `8008` | Scenario 08: Central Vault Finale | Chained Crypto | `CTF{f1n4l_ch41n_c0mpl3t3}` |
| `s09.offensivegrid.com` | `8009` | Scenario 09: Products SQLi | SQL Injection | `CTF{un10n_b4s1cs_m4st3r}` |
| `s10.offensivegrid.com` | `8010` | Scenario 10: Directory UNION SQLi | SQL Injection | `CTF{un10n_s3l3ct_m4st3r}` |
| `s11.offensivegrid.com` | `8011` | Scenario 11: Asset Inventory SQLi | SQL Injection | `CTF{sch3m4_3num_d0ubl3_qu0t3_m4st3r}` |
| `s12.offensivegrid.com` | `8012` | Scenario 12: Reflected XSS | Cross-Site Scripting | `CTF{r3fl3ct3d_xss_b4s1cs}` |
| `s13.offensivegrid.com` | `8013` | Scenario 13: Stored Attribute XSS | Cross-Site Scripting | `CTF{st0r3d_4ttr1but3_br34k0ut}` |
| `s14.offensivegrid.com` | `8014` | Scenario 14: DOM-based XSS | Cross-Site Scripting | `CTF{d0m_xss_s1nk_m4st3r}` |
| `s15.offensivegrid.com` | `8015` | Scenario 15: WAF Bypass XSS | Cross-Site Scripting | `CTF{w4f_byp4ss_h5_v3ct0r}` |
| `s16.offensivegrid.com` | `8016` | Scenario 16: INSERT SQLi to Stored XSS | Chained Exploit | `CTF{1ns3rt_sqli_t0_st0r3d_xss_ch41n}` |
| `s17.offensivegrid.com` | `8017` | Scenario 17: Mass Assignment IDOR | API Security | `CTF{m4ss_4ss1gnm3nt_pr0f1l3_0v3rwr1t3}` |
| `s18.offensivegrid.com` | `8018` | Scenario 18: UUID Leakage IDOR | IDOR / UUID | `CTF{uu1d_l34k_d0cum3nt_v4ult}` |
| `s19.offensivegrid.com` | `8019` | Scenario 19: Verb Tampering Multi-Tenant IDOR | API Security | `CTF{v3rb_t4mp3r1ng_t3n4nt_byp4ss}` |
| `s20.offensivegrid.com` | `8020` | Scenario 20: BOLA Password Reset ATO | API Security / BOLA | `CTF{b0l4_p4ssw0rd_r3s3t_4cc0unt_t4k30v3r}` |
| `s21.offensivegrid.com` | `8021` | Scenario 21: Web Cache Attacks | Cache Attacks | `CTF{c4ch3_d3c3pt10n_l34k}` |

---

## 🔒 Security & Sandbox Guarantees
- **Port & Origin SOP Isolation:** Browsers maintain complete origin separation across subdomains and ports.
- **Zero Cross-Contamination:** Exploit payloads in one scenario cannot modify or bleed into adjacent scenarios.
- **Stateless Dynamic Reset:** Scenarios provide `/reset` endpoints to return database tables to pristine initial states.
