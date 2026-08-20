#!/usr/bin/env python3
"""
CSZone CTF Range — Master Multi-Scenario Server Runner
Runs the Central Operations Hub (Port 8000) and all 21 scenario servers (Ports 8001-8021) in parallel.
Usage:
    python start_all.py
"""
import os
import sys
import time
import json
import threading
import subprocess
import signal

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCENARIOS_DIR = os.path.join(BASE_DIR, "scenarios")
PID_FILE = os.path.join(BASE_DIR, ".running_scenarios.json")

SCENARIO_CONFIGS = [
    {"name": "Central Operations Hub", "dir": "central-hub", "script": "server.py", "port": 8000},
    {"name": "Scenario 01 (Recon & Headers)", "dir": "scenario-01-recon-headers", "script": "server.py", "port": 8001},
    {"name": "Scenario 02 (Robots & Ops Archive)", "dir": "scenario-02-robots-ops", "script": "server.py", "port": 8002},
    {"name": "Scenario 03 (JS & Crypto XOR)", "dir": "scenario-03-js-crypto", "script": "server.py", "port": 8003},
    {"name": "Scenario 04 (Admin Portal Leak)", "dir": "scenario-04-admin-portal", "script": "server.py", "port": 8004},
    {"name": "Scenario 05 (IDOR Invoices)", "dir": "scenario-05-idor-invoices", "script": "server.py", "port": 8005},
    {"name": "Scenario 06 (Promo & Cookie Guard)", "dir": "scenario-06-cookie-bypass", "script": "server.py", "port": 8006},
    {"name": "Scenario 07 (Backup Service Auth)", "dir": "scenario-07-backup-bruteforce", "script": "server.py", "port": 8007},
    {"name": "Scenario 08 (Central Vault Finale)", "dir": "scenario-08-vault-finale", "script": "server.py", "port": 8008},
    {"name": "Scenario 09 (Product Filter SQLi)", "dir": "scenario-09-sqli-products", "script": "app.py", "port": 8009},
    {"name": "Scenario 10 (Personnel UNION SQLi)", "dir": "scenario-10-sqli-directory", "script": "app.py", "port": 8010},
    {"name": "Scenario 11 (Asset Inventory SQLi)", "dir": "scenario-11-sqli-assets", "script": "app.py", "port": 8011},
    {"name": "Scenario 12 (Reflected XSS)", "dir": "scenario-12-xss-reflected", "script": "app.py", "port": 8012},
    {"name": "Scenario 13 (Stored Attribute XSS)", "dir": "scenario-13-xss-stored-attribute", "script": "app.py", "port": 8013},
    {"name": "Scenario 14 (DOM-based XSS)", "dir": "scenario-14-xss-dom", "script": "app.py", "port": 8014},
    {"name": "Scenario 15 (WAF Bypass XSS)", "dir": "scenario-15-xss-waf-bypass", "script": "app.py", "port": 8015},
    {"name": "Scenario 16 (SQLi + Stored XSS Chain)", "dir": "scenario-16-admin-stored-xss", "script": "app.py", "port": 8016},
    {"name": "Scenario 17 (Mass Assignment IDOR)", "dir": "scenario-17-csrf-account", "script": "app.py", "port": 8017},
    {"name": "Scenario 18 (UUID Leakage IDOR)", "dir": "scenario-18-file-upload", "script": "app.py", "port": 8018},
    {"name": "Scenario 19 (Verb Tampering IDOR)", "dir": "scenario-19-ssrf-metadata", "script": "app.py", "port": 8019},
    {"name": "Scenario 20 (BOLA Password Reset ATO)", "dir": "scenario-20-backend-idor", "script": "app.py", "port": 8020},
    {"name": "Scenario 21 (Cache Deception & Poison)", "dir": "scenario-21-cache-attacks", "script": "app.py", "port": 8021},
]

running_processes = []
proc_info = []

def run_scenario(cfg):
    scen_dir = os.path.join(SCENARIOS_DIR, cfg["dir"])
    script_path = os.path.join(scen_dir, cfg["script"])
    if not os.path.exists(script_path):
        print(f"[-] Missing: {script_path}")
        return

    cmd = [sys.executable, cfg["script"], str(cfg["port"])]
    proc = subprocess.Popen(
        cmd,
        cwd=scen_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
        bufsize=1
    )
    running_processes.append(proc)
    proc_info.append({"name": cfg["name"], "port": cfg["port"], "pid": proc.pid})
    print(f" [+] Started {cfg['name']} on port {cfg['port']} (PID {proc.pid})")
    
    for line in proc.stdout:
        pass

def save_pids():
    try:
        with open(PID_FILE, "w") as f:
            json.dump(proc_info, f, indent=2)
    except Exception:
        pass

def cleanup():
    print("\n[-] Stopping all scenarios...")
    for p in running_processes:
        try:
            if sys.platform == "win32":
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(p.pid)], capture_output=True)
            else:
                p.terminate()
        except Exception:
            pass
    if os.path.exists(PID_FILE):
        try:
            os.remove(PID_FILE)
        except Exception:
            pass
    print("[*] All services terminated.")

def main():
    print("=" * 70)
    print("       CSZone CTF Training Range — Starting All 21 Services")
    print("=" * 70)

    threads = []
    for cfg in SCENARIO_CONFIGS:
        t = threading.Thread(target=run_scenario, args=(cfg,), daemon=True)
        t.start()
        threads.append(t)
        time.sleep(0.08)

    time.sleep(0.6)
    save_pids()

    print("=" * 70)
    print(f"[*] Central Hub running at: http://localhost:8000")
    print(f"[*] All {len(SCENARIO_CONFIGS)-1} scenarios active across ports 8001-8021.")
    print("[*] Run 'python verify_all_scenarios.py' to run full automated test suite.")
    print("[*] Run 'python stop_all.py' from another terminal to stop all servers.")
    print("[*] Press Ctrl+C to terminate all services.")
    print("=" * 70)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        cleanup()

if __name__ == "__main__":
    main()
