#!/usr/bin/env python3
"""
CSZone CTF Range — Scenario 09: E-Commerce Product Filter SQLi
Port: 8009
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
    PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8009
except (ValueError, IndexError):
    PORT = 8009
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "scenario09.db")

app = Flask(__name__)
app.secret_key = "scenario-09-secret-key"

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
    cur.execute("DROP TABLE IF EXISTS products;")
    cur.execute("DROP TABLE IF EXISTS site_secrets;")
    cur.execute("""
        CREATE TABLE products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            description TEXT NOT NULL,
            price TEXT NOT NULL,
            is_released INTEGER DEFAULT 1
        );
    """)
    cur.execute("""
        CREATE TABLE site_secrets (
            title TEXT NOT NULL,
            secret_flag TEXT NOT NULL
        );
    """)
    products = [
        ('Hardware Security Key', 'Hardware', 'FIDO2 & U2F physical security token for multi-factor authentication.', '$49.99', 1),
        ('Encrypted USB Vault', 'Hardware', 'Hardware-encrypted USB 3.2 flash drive with keypad access.', '$89.99', 1),
        ('Network Tap Probe', 'Hardware', 'Passive gigabit ethernet monitoring tap for traffic inspection.', '$129.99', 1),
        ('Cyber Defense Terminal', 'Hardware', 'Ruggedized field diagnostic terminal with dual NICs.', '$499.99', 1),
        ('Prototype Quantum Key Dongle', 'Hardware', 'Unreleased quantum-resistant hardware token (Confidential).', '$999.99', 0),
        ('Network Packet Analyzer', 'Software', 'Enterprise DPI deep-packet inspection suite.', '$299.00', 1),
        ('Endpoint Shield Agent', 'Software', 'Next-gen anti-tamper security defense agent.', '$149.00', 1)
    ]
    cur.executemany("INSERT INTO products (name, category, description, price, is_released) VALUES (?, ?, ?, ?, ?)", products)
    cur.execute("INSERT INTO site_secrets (title, secret_flag) VALUES (?, ?)", 
                ('Master Secret Record', 'CTF{un10n_b4s1cs_m4st3r} -- [Next Target]: Proceed to Scenario 10'))
    conn.commit()
    conn.close()

if not os.path.exists(DB_PATH):
    init_db()

@app.route("/")
@app.route("/products")
def products_view():
    category = request.args.get("category", "")
    categories = ["Hardware", "Software"]
    conn = get_conn()
    cur = conn.cursor()
    products = []
    error = None
    status_code = 200

    if category:
        query = f"SELECT name, description FROM products WHERE is_released = 1 AND category = '{category}'"
        try:
            cur.execute(query)
            products = cur.fetchall()
        except sqlite3.OperationalError as e:
            error = str(e)
            status_code = 500
    else:
        cur.execute("SELECT name, description FROM products WHERE is_released = 1")
        products = cur.fetchall()

    conn.close()
    return render_template("products.html", products=products, categories=categories, selected_category=category, error=error), status_code

if __name__ == "__main__":
    init_db()
    print(f"[*] Scenario 09 running on http://localhost:{PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False, threaded=True)
