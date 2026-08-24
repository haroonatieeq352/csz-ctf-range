#!/usr/bin/env python3
"""
CSZone CTF Range — Scenario 13: Stored XSS in Attribute Context
Port: 8013
Production-Ready: High-Concurrency WSGI (Gunicorn/Threaded), SQLite WAL, and Token/IP Rate Limiter.
"""
import os
import sys
import re
import time
import sqlite3
import threading
from collections import defaultdict
from flask import Flask, request, redirect, url_for, render_template, jsonify

try:
    PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8013
except (ValueError, IndexError):
    PORT = 8013
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "scenario13.db")

app = Flask(__name__)
app.secret_key = "scenario-13-secret-key"
FLAG_SECRET = "CTF{st0r3d_4ttr1but3_br34k0ut}"

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
    cur.execute("DROP TABLE IF EXISTS feedback_entries;")
    cur.execute("""
        CREATE TABLE feedback_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author TEXT NOT NULL,
            comment TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
    """)
    cur.execute("INSERT INTO feedback_entries (author, comment) VALUES ('alice_dev', 'The new authentication helper module looks clean!');")
    cur.execute("INSERT INTO feedback_entries (author, comment) VALUES ('bob_ops', 'Please update the API documentation with timeout parameters.');")
    conn.commit()
    conn.close()

if not os.path.exists(DB_PATH):
    init_db()

def naive_script_filter(text):
    """Naive filter that only strips <script> tags but ignores quotes and event handlers."""
    return re.sub(r"<\s*/?\s*script[^>]*>", "", text, flags=re.IGNORECASE)

@app.route("/", methods=["GET", "POST"])
@app.route("/feedback", methods=["GET", "POST"])
def feedback_view():
    if request.method == "POST":
        author = request.form.get("author", "").strip() or "anonymous"
        comment = request.form.get("comment", "").strip()
        
        filtered_author = naive_script_filter(author)
        filtered_comment = naive_script_filter(comment)

        conn = get_conn()
        conn.execute("INSERT INTO feedback_entries (author, comment) VALUES (?, ?)", (filtered_author, filtered_comment))
        conn.commit()
        conn.close()
        return redirect(url_for("feedback_view"))

    conn = get_conn()
    entries = conn.execute("SELECT author, comment, created_at FROM feedback_entries ORDER BY id DESC").fetchall()
    conn.close()

    formatted_entries = [{"author": r[0], "comment": r[1], "created_at": r[2]} for r in entries]
    return render_template("feedback.html", entries=formatted_entries)

@app.route("/api/flag")
def api_flag():
    return jsonify({"success": True, "flag": FLAG_SECRET})

@app.route("/reset", methods=["GET", "POST"])
def reset_view():
    init_db()
    return redirect(url_for("feedback_view"))

if __name__ == "__main__":
    init_db()
    print(f"[*] Scenario 13 running on http://localhost:{PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False, threaded=True)
