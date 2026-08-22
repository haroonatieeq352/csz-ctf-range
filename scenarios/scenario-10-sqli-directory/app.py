#!/usr/bin/env python3
"""
CSZone CTF Range — Scenario 10: Personnel Directory UNION SQLi
Port: 8010
Production-Ready: High-Concurrency WSGI (Gunicorn/Threaded), SQLite WAL, and Token/IP Rate Limiter.
"""
import os
import sys
import time
import sqlite3
import threading
from collections import defaultdict
from flask import Flask, request, render_template, jsonify

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8010
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "scenario10.db")

app = Flask(__name__)
app.secret_key = "scenario-10-secret-key"

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
    cur.execute("DROP TABLE IF EXISTS employees;")
    cur.execute("DROP TABLE IF EXISTS flags;")
    cur.execute("DROP TABLE IF EXISTS staff_clearances;")
    cur.execute("""
        CREATE TABLE employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            badge_number INTEGER NOT NULL,
            email TEXT NOT NULL
        );
    """)
    cur.execute("""
        CREATE TABLE flags (
            label TEXT NOT NULL,
            clearance_id INTEGER NOT NULL,
            value TEXT NOT NULL
        );
    """)
    cur.execute("""
        CREATE TABLE staff_clearances (
            officer_name TEXT NOT NULL,
            clearance_level INTEGER NOT NULL,
            master_flag TEXT NOT NULL
        );
    """)
    employees = [
        ('Ayesha Raza', 1042, 'ayesha.raza@cszone.internal'),
        ('Bilal Hassan', 1088, 'bilal.hassan@cszone.internal'),
        ('Sara Khan', 1015, 'sara.khan@cszone.internal'),
        ('Usman Tariq', 1092, 'usman.tariq@cszone.internal'),
        ('Mahnoor Iqbal', 1033, 'mahnoor.iqbal@cszone.internal')
    ]
    cur.executemany("INSERT INTO employees (name, badge_number, email) VALUES (?, ?, ?)", employees)
    cur.execute("INSERT INTO flags (label, clearance_id, value) VALUES (?, ?, ?)", 
                ('Master Clearance Flag', 9, 'CTF{un10n_s3l3ct_m4st3r}'))
    cur.execute("INSERT INTO staff_clearances (officer_name, clearance_level, master_flag) VALUES (?, ?, ?)",
                ('Director Vance', 9, 'CTF{un10n_s3l3ct_m4st3r}'))
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
@app.route("/directory")
def directory_view():
    q = request.args.get("q", "")
    results = []
    error = None
    status_code = 200

    if q:
        if "--" in q:
            error = "Query Execution Error: '--' comment syntax is blocked by application filter. Use alternate SQL comment operator ('#' or '%23')."
            status_code = 500
            return render_template("directory.html", q=q, results=results, error=error), status_code

        processed_q = q.replace("#", "--")

        conn = get_conn()
        cur = conn.cursor()
        query = f"SELECT name, badge_number, email FROM employees WHERE name LIKE '%{processed_q}%'"
        try:
            cur.execute(query)
            rows = cur.fetchall()
            for row in rows:
                if len(row) >= 2 and not is_numeric_value(row[1]):
                    raise sqlite3.OperationalError(
                        f"Datatype mismatch in UNION query at column 2 (badge_number). "
                        f"Expected INTEGER/NUMERIC, received incompatible TEXT literal '{row[1]}'."
                    )
            results = rows
        except sqlite3.OperationalError as e:
            error = str(e)
            status_code = 500
        conn.close()

    return render_template("directory.html", q=q, results=results, error=error), status_code

if __name__ == "__main__":
    init_db()
    print(f"[*] Scenario 10 running on http://localhost:{PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False, threaded=True)
