#!/usr/bin/env python3
"""
CSZone CTF Range — Scenario 21: Web Cache Deception & Cache Poisoning
Port: 8021
Production-Ready: High-Concurrency WSGI (Gunicorn/Threaded), SQLite WAL, and Token/IP Rate Limiter.
"""
import os
import sys
import re
import time
import sqlite3
import threading
from collections import defaultdict
from functools import wraps
from flask import Flask, request, session, redirect, url_for, render_template, make_response, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

try:
    PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8021
except (ValueError, IndexError):
    PORT = 8021
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "scenario21.db")

app = Flask(__name__)
app.secret_key = "scenario-21-secret-key"

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

# ── Shared In-Process Cache Layer ────────────────────────────────────────────
_CACHE = {}
_CACHE_TTL = 300
_STATIC_LOOKALIKE = re.compile(r"\.(css|js|jpg|jpeg|png|gif|ico)$", re.IGNORECASE)
_EXPLICIT_CACHEABLE_PATHS = {"/promo/partner-banner"}

def _cache_get(path):
    entry = _CACHE.get(path)
    if entry and entry["expires"] > time.time():
        return entry
    return None

def _cache_set(path, body, content_type):
    _CACHE[path] = {
        "body": body,
        "content_type": content_type,
        "expires": time.time() + _CACHE_TTL,
    }

@app.before_request
def check_rate_limit_and_cache():
    # 1. Rate limiter check
    if not request.path.startswith("/static/"):
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

    # 2. Cache layer check
    if request.method != "GET":
        return None
    path = request.path
    cacheable = bool(_STATIC_LOOKALIKE.search(path)) or path in _EXPLICIT_CACHEABLE_PATHS
    if not cacheable:
        return None
    hit = _cache_get(path)
    if hit:
        resp = make_response(hit["body"])
        resp.headers["Content-Type"] = hit["content_type"]
        resp.headers["X-Cache"] = "HIT"
        return resp
    return None

@app.after_request
def cache_layer_store_and_headers(response):
    response.headers["X-RateLimit-Limit"] = "60"
    path = request.path
    if request.method != "GET" or path.startswith("/static/"):
        return response
    cacheable = bool(_STATIC_LOOKALIKE.search(path)) or path in _EXPLICIT_CACHEABLE_PATHS
    if cacheable and response.status_code == 200:
        if getattr(response, "direct_passthrough", False):
            return response
        response.headers["X-Cache"] = response.headers.get("X-Cache", "MISS")
        _cache_set(path, response.get_data(as_text=True), response.content_type)
    return response

# ── Database Lifecycle ───────────────────────────────────────────────────────
def get_conn():
    conn = sqlite3.connect(DB_PATH, timeout=20.0, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=5000;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn

def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS users;")
    cur.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT NOT NULL,
            bio TEXT,
            personal_note TEXT
        );
    """)
    cur.execute("""
        INSERT INTO users (id, username, password_hash, email, bio, personal_note) VALUES
        (1, 'participant', ?, 'participant@cszone.internal', 'Training range participant account.',
         'Private note (personal, not for public profile): CTF{c4ch3_d3c3pt10n_l34k}')
    """, (generate_password_hash("Range2024!"),))
    conn.commit()
    conn.close()

if not os.path.exists(DB_PATH):
    init_db()

def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, username, email, bio, personal_note FROM users WHERE id = ?", (uid,))
    row = cur.fetchone()
    conn.close()
    if row:
        return {"id": row[0], "username": row[1], "email": row[2], "bio": row[3], "personal_note": row[4]}
    return None

def login_required(view):
    @wraps(view)
    def wrapped(*a, **kw):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return view(*a, **kw)
    return wrapped

@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("account"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT id, username, password_hash FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        conn.close()
        if row and check_password_hash(row[2], password):
            session["user_id"] = row[0]
            session["username"] = row[1]
            return redirect(url_for("account"))
        error = "Invalid credentials."
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/account")
@login_required
def account():
    user = current_user()
    return render_template("account.html", user=user)

@app.route("/account/profile/<path:extra>")
def account_profile_extra(extra):
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    return render_template("account.html", user=user)

@app.route("/promo/partner-banner")
def promo_partner_banner():
    forwarded_host = request.headers.get("X-Forwarded-Host", request.host)
    canonical_url = f"https://{forwarded_host}/promo/partner-banner"
    return render_template("cache_promo.html", canonical_url=canonical_url)

@app.route("/reset", methods=["GET", "POST"])
@app.route("/api/reset", methods=["GET", "POST"])
def reset_view():
    global _CACHE
    _CACHE.clear()
    init_db()
    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":
    init_db()
    print(f"[*] Scenario 21 running on http://localhost:{PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False, threaded=True)
