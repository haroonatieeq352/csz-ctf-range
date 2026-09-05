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

## 🗺️ Master Target Scenarios & Vulnerability Catalog

| Subdomain (Production) | Local Port | Scenario Name | Category | Mission Objective / Challenge Goal |
|---|---|---|---|---|
| `hub.offensivegrid.com` | `8000` | **Central Operations Hub** | Portal Console | Real-time Scenario Launcher & Target Tracking Catalog |
| `s01.offensivegrid.com` | `8001` | Scenario 01: Recon & Headers | Reconnaissance | Inspect developer staging artifacts & uncover hidden HTTP debug headers |
| `s02.offensivegrid.com` | `8002` | Scenario 02: Robots & Ops Archive | Reconnaissance | Discover disallowed pathways in robots.txt & extract ops session dump logs |
| `s03.offensivegrid.com` | `8003` | Scenario 03: JS & Crypto XOR | Cryptography | Extract global window objects & decrypt single-byte XOR obfuscated secrets |
| `s04.offensivegrid.com` | `8004` | Scenario 04: Admin Portal Leak | Access Control | Identify administrative path migration logs & bypass portal access controls |
| `s05.offensivegrid.com` | `8005` | Scenario 05: Frontend IDOR | IDOR | Exploit insecure direct object references in client billing & invoice endpoints |
| `s06.offensivegrid.com` | `8006` | Scenario 06: Promo & Cookie Gate | Access / Crypto | Decode promo vouchers & craft privileged authentication cookies |
| `s07.offensivegrid.com` | `8007` | Scenario 07: Backup Service Auth | Authentication | Perform dictionary brute-force attacks against salted SHA-256 backup services |
| `s08.offensivegrid.com` | `8008` | Scenario 08: Central Vault Finale | Chained Crypto | Combine multi-stage tokens & execute dual-key XOR master vault decryption |
| `s09.offensivegrid.com` | `8009` | Scenario 09: Products SQLi | SQL Injection | Exploit SQL injection in product filters to bypass release flags & extract secrets |
| `s10.offensivegrid.com` | `8010` | Scenario 10: Directory UNION SQLi | SQL Injection | Perform multi-column UNION SELECT injection across staff clearance tables |
| `s11.offensivegrid.com` | `8011` | Scenario 11: Asset Inventory SQLi | SQL Injection | Perform database schema enumeration via `sqlite_master` under strict filter constraints |
| `s12.offensivegrid.com` | `8012` | Scenario 12: Reflected XSS | Cross-Site Scripting | Craft HTML tag breakout vectors to trigger reflected client-side script execution |
| `s13.offensivegrid.com` | `8013` | Scenario 13: Stored Attribute XSS | Cross-Site Scripting | Bypass script tag filters via attribute context breakout & event handlers |
| `s14.offensivegrid.com` | `8014` | Scenario 14: DOM-based XSS | Cross-Site Scripting | Trace untrusted URL parameters into client-side DOM execution sinks |
| `s15.offensivegrid.com` | `8015` | Scenario 15: WAF Bypass XSS | Cross-Site Scripting | Evade strict regex Web Application Firewalls using HTML5 animation vector payloads |
| `s16.offensivegrid.com` | `8016` | Scenario 16: INSERT SQLi to Stored XSS | Chained Exploit | Chain SQL INSERT statement tampering to achieve second-order stored admin XSS |
| `s17.offensivegrid.com` | `8017` | Scenario 17: Mass Assignment IDOR | API Security | Manipulate JSON parameter binding to overwrite user roles and gain VIP admin rights |
| `s18.offensivegrid.com` | `8018` | Scenario 18: UUID Leakage IDOR | IDOR / UUID | Correlate telemetry audit feeds to discover non-sequential UUIDs & download classified records |
| `s19.offensivegrid.com` | `8019` | Scenario 19: Verb Tampering IDOR | API Security | Circumvent RESTful API gateway restrictions via HTTP verb tampering (PUT/PATCH) |
| `s20.offensivegrid.com` | `8020` | Scenario 20: BOLA Password Reset ATO | API Security / BOLA | Exploit Broken Object Level Authorization in multi-step recovery to takeover admin accounts |
| `s21.offensivegrid.com` | `8021` | Scenario 21: Web Cache Attacks | Cache Attacks | Execute Web Cache Deception & unkeyed header Cache Poisoning to leak user tokens |

---

## 🔒 Security & Sandbox Guarantees

- **Port & Origin SOP Isolation:** Web browsers maintain strict Same-Origin Policy (SOP) separation across distinct subdomains and ports.
- **Zero Cross-Contamination:** Exploit payloads in one scenario cannot modify, leak into, or disrupt adjacent scenarios.
- **Stateless Dynamic Reset:** Every database scenario provides an isolated `/reset` or `/api/reset` endpoint to return tables to clean initial states instantly.
- **DDoS Sliding Window Protection:** Protects live VPS infrastructure from automated flooding while granting adequate buffers for legitimate penetration testing exercises.
