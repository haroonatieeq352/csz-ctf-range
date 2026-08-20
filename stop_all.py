#!/usr/bin/env python3
"""
CSZone CTF Range — Scenario Terminator
Stops all running scenario server processes cleanly on Windows and Linux/VPS.
"""
import os
import sys
import json
import subprocess
import signal

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PID_FILE = os.path.join(BASE_DIR, ".running_scenarios.json")
RANGE_PORTS = list(range(8000, 8023))

def kill_process(pid):
    try:
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)], capture_output=True)
        else:
            os.kill(pid, signal.SIGTERM)
    except Exception:
        pass

def cleanup_ports():
    """Fallback cleanup by port if any orphaned processes remain."""
    if sys.platform == "win32":
        try:
            out = subprocess.check_output(["netstat", "-ano"], universal_newlines=True)
            for line in out.splitlines():
                for port in RANGE_PORTS:
                    if f":{port} " in line and "LISTENING" in line:
                        parts = line.strip().split()
                        pid = parts[-1]
                        kill_process(pid)
        except Exception:
            pass
    else:
        for port in RANGE_PORTS:
            try:
                subprocess.run(f"fuser -k {port}/tcp", shell=True, capture_output=True)
            except Exception:
                pass

def main():
    print("=" * 70)
    print("       CSZone CTF Training Range — Stopping All Scenarios")
    print("=" * 70)

    stopped_count = 0
    if os.path.exists(PID_FILE):
        try:
            with open(PID_FILE, "r") as f:
                processes = json.load(f)
            for item in processes:
                pid = item.get("pid")
                name = item.get("name")
                port = item.get("port")
                if pid:
                    kill_process(pid)
                    print(f" [-] Stopped {name} (Port {port}, PID {pid})")
                    stopped_count += 1
        except Exception as e:
            print(f"[-] Error reading PID file: {e}")

        try:
            os.remove(PID_FILE)
        except Exception:
            pass

    # Port fallback cleanup
    cleanup_ports()

    print("=" * 70)
    print(f"[*] Done. All scenario servers (Ports 8000-8021) terminated cleanly.")
    print("=" * 70)

if __name__ == "__main__":
    main()
