#!/usr/bin/env python3
"""
CSZone CTF Range — Scenario 16: INSERT SQLi to Second-Order Stored XSS Chain
Port: 8016
Production-Ready: High-Concurrency WSGI (Gunicorn/Threaded), SQLite WAL, and Token/IP Rate Limiter.
"""
import os
import sys
import time
import sqlite3
import threading
from collections import defaultdict
from flask import Flask, request, redirect, url_for, render_template, jsonify

try:
    PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8016
except (ValueError, IndexError):
    PORT = 8016
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "scenario16.db")

app = Flask(__name__)
app.secret_key = "scenario-16-enterprise-secret-key"
FLAG_SECRET = "CTF{1ns3rt_sqli_t0_st0r3d_xss_ch41n}"

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
    cur.execute("DROP TABLE IF EXISTS support_tickets;")
    cur.execute("""
        CREATE TABLE support_tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            submitter TEXT NOT NULL,
            department TEXT NOT NULL,
            issue_desc TEXT NOT NULL,
            priority TEXT DEFAULT 'LOW',
            is_trusted INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
    """)
    cur.execute("""
        INSERT INTO support_tickets (submitter, department, issue_desc, priority, is_trusted) 
        VALUES ('Infra SecOps', 'IT-INFRA', 'Routine firewall telemetry validation pass.', 'NORMAL', 1);
    """)
    conn.commit()
    conn.close()

if not os.path.exists(DB_PATH):
    init_db()

@app.route("/")
@app.route("/tickets", methods=["GET", "POST"])
def tickets_view():
    conn = get_conn()
    error = None
    success = None

    if request.method == "POST":
        submitter = request.form.get("submitter", "Anonymous").strip() or "Anonymous"
        department = request.form.get("department", "GENERAL").strip() or "GENERAL"
        issue_desc = request.form.get("issue_desc", "").strip()

        query = (
            f"INSERT INTO support_tickets (submitter, department, issue_desc, priority, is_trusted) "
            f"VALUES ('{submitter}', '{department}', '{issue_desc}', 'LOW', 0)"
        )
        try:
            conn.execute(query)
            conn.commit()
            success = "Support ticket submitted successfully and queued for priority triage."
        except sqlite3.OperationalError as e:
            error = f"Database Query Error: {e}"

    tickets = conn.execute("SELECT id, submitter, department, priority, created_at FROM support_tickets ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("tickets.html", tickets=tickets, error=error, success=success)

@app.route("/admin/compliance")
def admin_compliance():
    conn = get_conn()
    triaged_tickets = conn.execute(
        "SELECT id, submitter, department, issue_desc, priority, created_at "
        "FROM support_tickets "
        "WHERE is_trusted = 1 OR priority = 'CRITICAL' "
        "ORDER BY id DESC"
    ).fetchall()
    conn.close()
    return render_template("compliance.html", tickets=triaged_tickets)

@app.route("/reset", methods=["GET", "POST"])
@app.route("/api/reset", methods=["GET", "POST"])
def reset_view():
    init_db()
    return redirect(url_for("tickets_view"))

@app.route("/api/flag")
def api_flag():
    return jsonify({"success": True, "flag": FLAG_SECRET})

if __name__ == "__main__":
    init_db()
    print(f"[*] Scenario 16 running on http://localhost:{PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False, threaded=True)
