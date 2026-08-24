# CSZone Cyber Range — Enterprise CTF Training Platform

A high-concurrency, production-grade offensive security and web penetration testing training platform. Features **21 isolated vulnerability scenarios** unified through the **Central Operations Hub**, supporting both local sandbox development and enterprise production deployments with subdomain routing, WSGI multi-threading, and DDoS mitigation.

---

## 🏛️ Architecture & Deployment Modes

The platform supports two distinct operational modes:

| Feature | 🛠️ Local Development Mode | 🌐 Shared Production VPS Mode (Recommended) | 🏢 Dedicated VPS Mode |
|---|---|---|---|
| **Docker File** | `docker-compose.yml` | `docker-compose.yml` | `docker-compose.prod.yml` |
| **Primary Hub URL** | `http://localhost:8000` | `https://hub.offensivegrid.com` | `https://hub.offensivegrid.com` |
| **Scenario Access** | Local Ports (`8001`–`8021`) | Subdomains (`s01`–`s21.offensivegrid.com`) | Subdomains (`s01`–`s21.offensivegrid.com`) |
| **Reverse Proxy** | None (Direct Process Binding) | **Host VPS Nginx** (`nginx/offensivegrid-host.conf`) | Bundled Docker Nginx Container |
| **Shared VPS Safe?** | Yes | **100% Zero Conflict with other websites** | Only on clean/dedicated VPS |
| **WSGI Engine** | Multi-Threaded TCP / Werkzeug | Gunicorn Multi-Worker / Multi-Threaded WSGI (`--preload`) | Gunicorn WSGI (`--preload`) |
| **Concurrency Target** | Local Testing | 100–150 Concurrent Students & Live CTF Arena | 100–150 Concurrent Students |
| **DDoS Rate Limiter** | In-App Sliding Window (60–120 r/m) | Dual-Tier: Host Nginx Zones + In-App Limiter | Bundled Nginx Zones + In-App Limiter |

---

## ⚡ Concurrency & DDoS Protection Specs

- **100–150 Concurrent Users:** Flask scenarios (`09` through `21` and `backend`) run under **Gunicorn** with 4 workers and 4 threads per worker (`--worker-class=gthread`), processing up to 16 simultaneous requests per scenario container without blocking or request timeouts.
- **SQLite WAL Mode:** All database scenarios use `PRAGMA journal_mode=WAL;` and `busy_timeout=5000;` enabling lock-free concurrent reads and writes across simultaneous student actions.
- **DDoS Mitigation (Sliding Window Token Limiter):**
  - **Standard scenarios (01–06, 08–21):** `60 requests/minute` per client IP.
  - **Scenario 07 (Brute-Force Auth):** `120–200 requests/minute` buffer for legitimate Intruder testing.
  - **HTTP 429 Status:** Returns `HTTP 429 Too Many Requests` with `Retry-After` headers and automatic 60-second soft reset without kernel-level IP bans.

---

## 🌐 Production Deployment Guide (For DevOps Team)

> [!IMPORTANT]
> **Shared VPS Safe Deployment (Zero Port 80/443 Conflict):**  
> If your VPS is already hosting other client websites or services, use **Deployment Mode A** below. The Docker containers will run on internal ports (`8000`–`8021`) and your existing **Host Nginx** will proxy subdomains without touching or disturbing any existing websites on the server.

---

### Deployment Mode A: Shared VPS with Host Nginx (Recommended)

#### Step 1: Clone Repository & Start Containers
```bash
git clone https://github.com/haroonatieeq352/csz-ctf-range.git
cd csz-ctf-range
git checkout dev

# Build and start all 22 scenarios on internal ports (8000-8021)
docker compose -f docker-compose.yml up -d --build

# Verify all 22 containers are running
docker compose -f docker-compose.yml ps
```

#### Step 2: Configure VPS Host Nginx (One-Time Setup)
A ready-to-use VirtualHost configuration is provided at `nginx/offensivegrid-host.conf`. It routes all 22 subdomains to `127.0.0.1:8000`–`8021` with DDoS protection rate-limit zones:

```bash
# 1. Copy the provided config to your VPS Nginx sites-available directory:
sudo cp nginx/offensivegrid-host.conf /etc/nginx/sites-available/offensivegrid.conf

# 2. Enable the site:
sudo ln -s /etc/nginx/sites-available/offensivegrid.conf /etc/nginx/sites-enabled/

# 3. Test Nginx syntax:
sudo nginx -t

# 4. Reload Nginx (Your existing websites will continue running without downtime):
sudo systemctl reload nginx
```

#### Step 3: (Optional) SSL / HTTPS with Certbot
```bash
sudo certbot --nginx -d hub.offensivegrid.com -d s01.offensivegrid.com -d s02.offensivegrid.com -d s03.offensivegrid.com -d s04.offensivegrid.com -d s05.offensivegrid.com -d s06.offensivegrid.com -d s07.offensivegrid.com -d s08.offensivegrid.com -d s09.offensivegrid.com -d s10.offensivegrid.com -d s11.offensivegrid.com -d s12.offensivegrid.com -d s13.offensivegrid.com -d s14.offensivegrid.com -d s15.offensivegrid.com -d s16.offensivegrid.com -d s17.offensivegrid.com -d s18.offensivegrid.com -d s19.offensivegrid.com -d s20.offensivegrid.com -d s21.offensivegrid.com
```

---

### Deployment Mode B: Dedicated Clean VPS (Bundled Nginx Container)

If you are deploying on a fresh, clean VPS dedicated solely to this CTF (where no other websites run on port 80/443):

```bash
# Launch full stack with bundled Docker Nginx container
docker compose -f docker-compose.prod.yml up -d --build
```

---

### Updating / Redeploying on New Changes

Whenever new code is pushed to GitHub, run this sequence to update with zero cache issues:

```bash
cd csz-ctf-range
git pull origin dev

# Stop old containers
docker compose -f docker-compose.yml down

# Rebuild images with --build (Forces Docker to use updated code)
docker compose -f docker-compose.yml up -d --build

# Check cluster status
docker compose -f docker-compose.yml ps
```

---

### 🛡️ VPS Firewall & Fail2ban Best Practices for CTF

Because CTF platforms intentionally involve brute-forcing (Scenario 07), fuzzing, and directory discovery, **do NOT enable HTTP/Nginx jails in Fail2ban**, as this will ban student IPs during legitimate exercises:

```bash
# Allow Web & SSH Ports in UFW Firewall:
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable

# Configure Fail2ban for SSH only:
# Ensure /etc/fail2ban/jail.local only enables the [sshd] jail,
# and disables [nginx-http-auth], [nginx-botsearch], and [nginx-limit-req].
sudo systemctl restart fail2ban
```

---

## 🛠️ Local Setup Guide (For Developers & Students)

You can run the entire platform locally on **Windows**, **macOS**, or **Linux** using native Python (No Docker needed) or Local Docker Compose.

---

### Method A: Standalone Python (Fastest — No Docker Required)

#### Prerequisites:
- **Python 3.9+** installed (`python --version`)
- Git installed

#### Step-by-Step Setup:

```bash
# 1. Clone the repository
git clone https://github.com/haroonatieeq352/csz-ctf-range.git
cd csz-ctf-range
git checkout dev

# 2. Create and activate a Python virtual environment
# Windows (PowerShell):
python -m venv venv
.\venv\Scripts\Activate.ps1

# Linux / macOS (Bash/Zsh):
python3 -m venv venv
source venv/bin/activate

# 3. Install required Python packages
pip install -r requirements.txt

# 4. Start all 21 scenarios + Central Hub in parallel
python start_all.py
```

After running `start_all.py`, open your browser and go to:
👉 **`http://localhost:8000`** (Central Operations Hub)

#### Local Verification & Testing:
```bash
# Run the automated end-to-end verification test suite (All 21 scenarios)
python verify_all_scenarios.py

# Run the 150-user concurrency & DDoS simulation test
python test_production_concurrency_and_ddos.py

# Stop all background scenario servers
python stop_all.py
```

---

### Method B: Local Docker Compose

```bash
# 1. Build and start all containers in local development mode
docker compose -f docker-compose.yml up -d --build

# 2. Check running containers
docker compose -f docker-compose.yml ps

# 3. Stop all local containers
docker compose -f docker-compose.yml down
```

---

## 🗺️ Master Target Scenarios & Vulnerability Catalog

| Subdomain (Production) | Local Port | Scenario Name | Category | Objective / Target Flag |
|---|---|---|---|---|
| `hub.offensivegrid.com` | `8000` | **Central Operations Hub** | Portal Console | Interactive Launcher & Target Catalog |
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
| `s19.offensivegrid.com` | `8019` | Scenario 19: Verb Tampering IDOR | API Security | `CTF{v3rb_t4mp3r1ng_t3n4nt_byp4ss}` |
| `s20.offensivegrid.com` | `8020` | Scenario 20: BOLA Password Reset ATO | API Security / BOLA | `CTF{b0l4_p4ssw0rd_r3s3t_4cc0unt_t4k30v3r}` |
| `s21.offensivegrid.com` | `8021` | Scenario 21: Web Cache Attacks | Cache Attacks | `CTF{c4ch3_d3c3pt10n_l34k}` |

---

## 🔒 Security & Sandbox Guarantees

- **Port & Origin SOP Isolation:** Web browsers maintain strict Same-Origin Policy (SOP) separation across distinct subdomains and ports.
- **Zero Cross-Contamination:** Exploit payloads in one scenario cannot modify, leak into, or disrupt adjacent scenarios.
- **Stateless Dynamic Reset:** Every database scenario provides an isolated `/reset` or `/api/reset` endpoint to return tables to clean initial states instantly.
- **DDoS Sliding Window Protection:** Protects live VPS infrastructure from automated flooding while granting adequate buffers for legitimate penetration testing exercises.
