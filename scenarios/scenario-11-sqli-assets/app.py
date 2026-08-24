#!/usr/bin/env python3
"""
CSZone CTF Range — Scenario 11: Enterprise Asset Inventory (Schema Enumeration SQLi)
Port: 8011
Production-Ready: High-Concurrency WSGI (Gunicorn/Threaded), SQLite WAL, and Token/IP Rate Limiter.
"""
import os
import sys
import time
import sqlite3
import threading
from collections import defaultdict
from flask import Flask, request, render_template, jsonify

try:
    PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8011
except (ValueError, IndexError):
    PORT = 8011
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "scenario11.db")

app = Flask(__name__)
app.secret_key = "scenario-11-secret-key"

class SlidingWindowRateLimiter:
    """Thread-safe Sliding Window Rate Limiter (60 req/min per IP/Token)."""
    def __init__(self, max_requests=60, window_seconds=60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(list)
        self.lock = threading.Lock()
        self._last_cleanup = time.time()

    def is_allowed(self, client_id):
        now = time.time()
        with self.lock:
            if now - self._last_cleanup > 60:
                cutoff = now - self.window_seconds
                stale = [k for k, v in self.requests.items() if not v or v[-1] < cutoff]
                for k in stale:
                    del self.requests[k]
                self._last_cleanup = now

            timestamps = self.requests[client_id]
            cutoff = now - self.window_seconds
            while timestamps and timestamps[0] < cutoff:
                timestamps.pop(0)

            if len(timestamps) < self.max_requests:
                timestamps.append(now)
                return True, self.max_requests - len(timestamps), 0
            else:
                retry_after = int(timestamps[0] + self.window_seconds - now) + 1
                return False, 0, max(1, retry_after)

rate_limiter = SlidingWindowRateLimiter(max_requests=60, window_seconds=60)

@app.before_request
def check_rate_limit():
    if request.path.startswith("/static/"):
        return None
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1").split(",")[0].strip()
    allowed, remaining, retry_after = rate_limiter.is_allowed(client_ip)
    if not allowed:
        resp = jsonify({
            "error": "Too Many Requests",
            "message": "DDoS Prevention: Rate limit exceeded (Max 60 requests/minute). Please slow down.",
            "retry_after_seconds": retry_after
        })
        resp.status_code = 429
        resp.headers["Retry-After"] = str(retry_after)
        resp.headers["X-RateLimit-Limit"] = "60"
        resp.headers["X-RateLimit-Remaining"] = "0"
        return resp

@app.after_request
def add_headers(response):
    response.headers["X-RateLimit-Limit"] = "60"
    return response

def get_conn():
    conn = sqlite3.connect(DB_PATH, timeout=20.0, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=5000;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn

def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS inventory_assets;")
    cur.execute("DROP TABLE IF EXISTS classified_vault_records;")
    cur.execute("""
        CREATE TABLE inventory_assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_name TEXT NOT NULL,
            department TEXT NOT NULL,
            serial_id INTEGER NOT NULL,
            clearance_tier INTEGER NOT NULL
        );
    """)
    cur.execute("""
        CREATE TABLE classified_vault_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            record_name TEXT NOT NULL,
            flag_data TEXT NOT NULL,
            access_pin INTEGER NOT NULL,
            vault_level INTEGER NOT NULL
        );
    """)
    assets = [
        ('Cyber Threat Sensor Alpha', 'Security Operations', 9104, 3),
        ('Encrypted Key Management HSM', 'Cryptography & PKI', 9422, 5),
        ('Enterprise Core Firewall', 'Infrastructure Ops', 9215, 4),
        ('Executive Quantum Workstation', 'Executive Office', 9031, 2),
        ('Biometric Vault Access Node', 'Physical Security', 9580, 4),
        ('Central Log Aggregator Unit', 'Threat Intelligence', 9347, 3)
    ]
    cur.executemany("INSERT INTO inventory_assets (asset_name, department, serial_id, clearance_tier) VALUES (?, ?, ?, ?)", assets)
    cur.execute("INSERT INTO classified_vault_records (record_name, flag_data, access_pin, vault_level) VALUES (?, ?, ?, ?)",
                ('Master Classified Asset Vault', 'CTF{sch3m4_3num_d0ubl3_qu0t3_m4st3r}', 8831, 5))
    cur.execute("INSERT INTO classified_vault_records (record_name, flag_data, access_pin, vault_level) VALUES (?, ?, ?, ?)",
                ('Secondary Backup Clearance Token', 'REDACTED_USE_PRIMARY_VAULT_RECORD', 4420, 3))
    conn.commit()
    conn.close()

if not os.path.exists(DB_PATH):
    init_db()

def is_numeric_value(val):
    if isinstance(val, (int, float)):
        return True
    try:
        int(str(val))
        return True
    except (ValueError, TypeError):
        return False

@app.route("/")
@app.route("/inventory")
def inventory_view():
    q = request.args.get("q", "")
    results = []
    error = None
    status_code = 200

    conn = get_conn()
    cur = conn.cursor()

    if q:
        if "'" in q:
            error = "sqlite3.OperationalError: near \"'\": syntax error (String delimiter mismatch. Single-quote (') is unrecognized)."
            status_code = 500
            conn.close()
            return render_template("inventory.html", q=q, results=results, error=error), status_code

        if "--" in q:
            error = "Query Execution Error: '--' comment syntax is blocked by security filter. Use alternate SQL comment operator ('#' or '%23')."
            status_code = 500
            conn.close()
            return render_template("inventory.html", q=q, results=results, error=error), status_code

        processed_q = q.replace("#", "--")
        query = f'SELECT asset_name, department, serial_id, clearance_tier FROM inventory_assets WHERE asset_name LIKE "%{processed_q}%"'
        try:
            cur.execute(query)
            rows = cur.fetchall()
            for row in rows:
                if len(row) < 4:
                    raise sqlite3.OperationalError(
                        f"UNION query failed: Expected 4 result columns, received {len(row)} column(s)."
                    )
                if not is_numeric_value(row[2]):
                    raise sqlite3.OperationalError(
                        f"Datatype mismatch in UNION query at column 3 (serial_id). "
                        f"Expected INTEGER/NUMERIC, received incompatible TEXT literal '{row[2]}'."
                    )
                if not is_numeric_value(row[3]):
                    raise sqlite3.OperationalError(
                        f"Datatype mismatch in UNION query at column 4 (clearance_tier). "
                        f"Expected INTEGER/NUMERIC, received incompatible TEXT literal '{row[3]}'."
                    )
            results = rows
        except sqlite3.OperationalError as e:
            error = str(e)
            status_code = 500
    else:
        try:
            cur.execute("SELECT asset_name, department, serial_id, clearance_tier FROM inventory_assets ORDER BY id ASC")
            results = cur.fetchall()
        except sqlite3.OperationalError as e:
            error = str(e)
            status_code = 500

    conn.close()
    return render_template("inventory.html", q=q, results=results, error=error), status_code

if __name__ == "__main__":
    init_db()
    print(f"[*] Scenario 11 running on http://localhost:{PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False, threaded=True)
