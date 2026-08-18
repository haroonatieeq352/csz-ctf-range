# CSZone Offensive Security Training Range (Multi-Port Architecture)

Enterprise-grade offensive security and web penetration testing training platform. Features 21 isolated, hands-on vulnerability scenarios mapped across dedicated ports (`8001` to `8021`) and unified through the **Central Operations Hub** on Port `8000`.

---

## 🚀 Quick Start Guide

### Prerequisites
- **Python 3.9+** (for native execution) OR **Docker & Docker Compose** (for containerized run)
- Install Python requirements:
  ```bash
  pip install -r requirements.txt
  ```

---

### 1. Launch All Services (Local Machine or VPS)
```bash
python start_all.py
```
This spawns in parallel:
- **Central Operations Hub:** `http://localhost:8000` (or `http://<your-vps-ip>:8000`)
- **21 Isolated Target Scenarios:** Ports `8001` through `8021`

### 2. Run Automated Verification Suite
To verify that all 21 scenarios and the Central Hub are fully operational:
```bash
python verify_all_scenarios.py
```
*(Optional: pass a custom host/IP: `python verify_all_scenarios.py <vps-ip>`)*

### 3. Stop All Services
```bash
python stop_all.py
```

---

## 🐳 Docker Deployment (VPS Production)

Deploy the entire suite (Central Hub + 21 Scenarios) with a single command:
```bash
docker-compose up -d --build
```
- **Check container status:**
  ```bash
  docker-compose ps
  ```
- **View container logs:**
  ```bash
  docker-compose logs -f
  ```
- **Stop all containers:**
  ```bash
  docker-compose down
  ```

---

## 🌐 VPS Firewall Configuration (UFW / Security Groups)

If deploying to an Ubuntu/Debian VPS or AWS/DigitalOcean/Hetzner, ensure inbound traffic is allowed on ports `8000` to `8021`:
```bash
sudo ufw allow 8000:8021/tcp
sudo ufw reload
```

---

## 🗺️ Port Architecture & Track Map

| Port | Service Name | Category | Flag / Key Objective |
|---|---|---|---|
| **`8000`** | **Central Operations Hub** | Main Portal | Landing UI & Dynamic Scenario Dispatcher |
| **`8001`** | Scenario 01: Recon & Headers | Reconnaissance | `CTF{h1dd3n_1n_pl41n_s1ght}` / `CTF{h34d3r_hunt3r_pr0}` |
| **`8002`** | Scenario 02: Robots & Ops Archive | Reconnaissance | `CTF{r0b0ts_d1scl0s3_p4ths}` |
| **`8003`** | Scenario 03: JS & Crypto XOR | Cryptography | `CTF{unus3d_v4r14bl3_l34k}` |
| **`8004`** | Scenario 04: Admin Portal Leak | Access Control | `CTF{4dm1n_p4n3l_3xp0s3d}` |
| **`8005`** | Scenario 05: Frontend IDOR | IDOR | `CTF{1d0r_1nv01c3_l34k}` |
| **`8006`** | Scenario 06: Promo & Cookie Gate | Access / Crypto | `CTF{b4s364_1s_n0t_3ncrypt10n}` / `CTF{h34d3r_c00k13_byp4ss}` |
| **`8007`** | Scenario 07: Backup Service Auth | Authentication | `CTF{h4sh_cr4ck3d_4cc3ss}` |
| **`8008`** | Scenario 08: Central Vault Finale | Chained Crypto | `CTF{f1n4l_ch41n_c0mpl3t3}` |
| **`8009`** | Scenario 09: Products SQLi | SQL Injection | `CTF{un10n_b4s1cs_m4st3r}` |
| **`8010`** | Scenario 10: Directory UNION SQLi | SQL Injection | `CTF{un10n_s3l3ct_m4st3r}` |
| **`8011`** | Scenario 11: Asset Inventory SQLi | SQL Injection | `CTF{sch3m4_3num_d0ubl3_qu0t3_m4st3r}` |
| **`8012`** | Scenario 12: Reflected XSS | Cross-Site Scripting | `CTF{r3fl3ct3d_xss_b4s1cs}` |
| **`8013`** | Scenario 13: Stored Attribute XSS | Cross-Site Scripting | `CTF{st0r3d_4ttr1but3_br34k0ut}` |
| **`8014`** | Scenario 14: DOM-based XSS | Cross-Site Scripting | `CTF{d0m_xss_s1nk_m4st3r}` |
| **`8015`** | Scenario 15: WAF Bypass XSS | Cross-Site Scripting | `CTF{w4f_byp4ss_h5_v3ct0r}` |
| **`8016`** | Scenario 16: SQLi & Stored XSS | Chained Exploit | `CTF{st0r3d_c00k13_th3ft}` |
| **`8017`** | Scenario 17: CSRF Account Email | CSRF | `CTF{csrf_n0_t0k3n_pwn3d}` |
| **`8018`** | Scenario 18: File Upload & XSS | File Upload | Stored Client Script Execution |
| **`8019`** | Scenario 19: SSRF Metadata | SSRF | `CTF{ssrf_1nt3rn4l_m3t4d4t4}` |
| **`8020`** | Scenario 20: Backend IDOR Orders | Access Control | `CTF{b4ck3nd_1d0r_r34l}` |
| **`8021`** | Scenario 21: Web Cache Attacks | Cache Attacks | `CTF{c4ch3_d3c3pt10n_l34k}` |

---

## 🔒 Security & Sandbox Guarantees
- **Port & SOP Isolation:** Web browsers strictly isolate cookies, local storage, and DOM contexts per port.
- **Zero Cross-Contamination:** Exploit payloads in one scenario cannot modify or bleed into other scenarios.
- **Pure Read-Only Central Hub:** The main dashboard on Port 8000 contains no database, no execution endpoints, and is strictly read-only.
