# CSZone Offensive Security Training Range (Multi-Port Architecture)

Enterprise-grade offensive security and web penetration testing training platform. Features 17 isolated, hands-on vulnerability scenarios mapped across dedicated ports (`8001` to `8017`) and unified through the **Central Operations Hub** on Port `8000`.

---

## 🚀 Quick Start Guide

### Prerequisites
- **Python 3.9+** (for native run) OR **Docker & Docker Compose** (for containerized run)
- Install Python requirements:
  ```bash
  pip install -r requirements.txt
  ```

---

### 1. Launch All Services (Local Machine or VPS)
```bash
python start_all.py
```
This starts in parallel:
- **Central Operations Hub:** `http://localhost:8000` (or `http://<your-vps-ip>:8000`)
- **17 Isolated Target Scenarios:** Ports `8001` through `8017`

### 2. Run Automated Verification Suite
To verify that all 17 scenarios and the Central Hub are fully operational:
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

Deploy the entire suite (Central Hub + 17 Scenarios) with a single command:
```bash
docker-compose up -d --build
```
- **Check service status:**
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

If deploying to an Ubuntu/Debian VPS or AWS/DigitalOcean/Hetzner, ensure inbound traffic is allowed on ports `8000` to `8017`:
```bash
sudo ufw allow 8000:8017/tcp
sudo ufw reload
```

---


---

## 🔒 Security & Sandbox Guarantees
- **Port & SOP Isolation:** Web browsers strictly isolate cookies, local storage, and DOM contexts per port.
- **Zero Cross-Contamination:** Exploit payloads in one scenario cannot modify or bleed into other scenarios.
- **Pure Read-Only Central Hub:** The main dashboard on Port 8000 contains no database, no execution endpoints, and is strictly read-only.
