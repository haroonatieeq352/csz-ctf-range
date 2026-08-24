#!/usr/bin/env python3
"""
CSZone CTF Range — Scenario 17: Mass Assignment & Profile Overwrite IDOR
Port: 8017
Production-Ready: High-Concurrency WSGI (Gunicorn/Threaded), SQLite WAL, and Token/IP Rate Limiter.
"""
import os
import sys
import time
import sqlite3
import threading
from collections import defaultdict
from flask import Flask, request, session, redirect, url_for, render_template, jsonify

try:
    PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8017
except (ValueError, IndexError):
    PORT = 8017
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "scenario17.db")

app = Flask(__name__)
app.secret_key = "scenario-17-mass-assign-secret-key"
FLAG_SECRET = "CTF{m4ss_4ss1gnm3nt_pr0f1l3_0v3rwr1t3}"

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
    cur.execute("DROP TABLE IF EXISTS users;")
    cur.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            full_name TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            is_vip INTEGER DEFAULT 0,
            phone TEXT,
            bio TEXT
        );
    """)
    cur.execute("""
        INSERT INTO users (id, username, email, full_name, role, is_vip, phone, bio)
        VALUES (101, 'sarah.admin', 'sarah.admin@cloudshield.io', 'Sarah Jenkins', 'admin', 1, '+1-555-0199', 'Lead Security Architect & Cloud Infrastructure Director');
    """)
    cur.execute("""
        INSERT INTO users (id, username, email, full_name, role, is_vip, phone, bio)
        VALUES (102, 'carlos', 'carlos@cloudshield.io', 'Carlos Rivera', 'user', 0, '+1-555-0142', 'Junior Security Analyst in training');
    """)
    conn.commit()
    conn.close()

if not os.path.exists(DB_PATH):
    init_db()

@app.before_request
def ensure_session():
    if "user_id" not in session:
        session["user_id"] = 102
        session["username"] = "carlos"

@app.route("/")
@app.route("/profile")
def profile_view():
    user_id = session.get("user_id", 102)
    conn = get_conn()
    user = conn.execute("SELECT id, username, email, full_name, role, is_vip, phone, bio FROM users WHERE id = ?", (user_id,)).fetchone()
    team = conn.execute("SELECT id, username, email, full_name, role FROM users ORDER BY id ASC").fetchall()
    conn.close()

    if not user:
        init_db()
        return redirect(url_for("profile_view"))

    is_solved = (user[4] == "admin" or user[5] == 1)
    return render_template("profile.html", user=user, team=team, is_solved=is_solved)

@app.route("/api/user/profile", methods=["GET"])
def api_get_profile():
    target_id = request.args.get("user_id", session.get("user_id", 102))
    conn = get_conn()
    user = conn.execute("SELECT id, username, email, full_name, role, is_vip, phone, bio FROM users WHERE id = ?", (target_id,)).fetchone()
    conn.close()
    if user:
        return jsonify({
            "success": True,
            "user": {
                "id": user[0],
                "username": user[1],
                "email": user[2],
                "full_name": user[3],
                "role": user[4],
                "is_vip": user[5],
                "phone": user[6],
                "bio": user[7]
            }
        })
    return jsonify({"success": False, "error": "User not found"}), 404

@app.route("/api/user/profile/update", methods=["POST"])
def api_update_profile():
    data = request.get_json(force=True, silent=True) or request.form.to_dict()
    if not data:
        return jsonify({"success": False, "error": "Invalid request payload"}), 400

    target_user_id = int(data.get("user_id", session.get("user_id", 102)))

    conn = get_conn()
    existing = conn.execute("SELECT id, username, email, full_name, role, is_vip, phone, bio FROM users WHERE id = ?", (target_user_id,)).fetchone()
    if not existing:
        conn.close()
        return jsonify({"success": False, "error": "Target user ID not found"}), 404

    full_name = data.get("full_name", existing[3])
    email = data.get("email", existing[2])
    role = data.get("role", existing[4])
    is_vip = int(data.get("is_vip", existing[5]))
    phone = data.get("phone", existing[6])
    bio = data.get("bio", existing[7])

    conn.execute("""
        UPDATE users 
        SET full_name = ?, email = ?, role = ?, is_vip = ?, phone = ?, bio = ?
        WHERE id = ?
    """, (full_name, email, role, is_vip, phone, bio, target_user_id))
    conn.commit()

    updated = conn.execute("SELECT id, username, email, full_name, role, is_vip, phone, bio FROM users WHERE id = ?", (target_user_id,)).fetchone()
    conn.close()

    return jsonify({
        "success": True,
        "message": f"Profile for user #{target_user_id} ({updated[1]}) updated successfully.",
        "user": {
            "id": updated[0],
            "username": updated[1],
            "email": updated[2],
            "full_name": updated[3],
            "role": updated[4],
            "is_vip": updated[5],
            "phone": updated[6],
            "bio": updated[7]
        }
    })

@app.route("/admin/dashboard")
def admin_dashboard():
    user_id = session.get("user_id", 102)
    conn = get_conn()
    user = conn.execute("SELECT id, username, role, is_vip FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()

    if user and (user[2] == "admin" or user[3] == 1):
        return render_template("admin.html", user=user, flag=FLAG_SECRET, is_solved=True)
    return render_template("admin.html", error="Access Denied: Administrator or VIP clearance required.", user=user, is_solved=False), 403

@app.route("/api/flag")
def api_flag():
    user_id = session.get("user_id", 102)
    conn = get_conn()
    user = conn.execute("SELECT id, username, role, is_vip FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()

    if user and (user[2] == "admin" or user[3] == 1):
        return jsonify({"success": True, "flag": FLAG_SECRET})
    return jsonify({"success": False, "error": "Access Denied: Requires elevated role"}), 403

@app.route("/reset", methods=["GET", "POST"])
@app.route("/api/reset", methods=["GET", "POST"])
def reset_view():
    init_db()
    session["user_id"] = 102
    session["username"] = "carlos"
    return redirect(url_for("profile_view"))

if __name__ == "__main__":
    init_db()
    print(f"[*] Scenario 17 running on http://localhost:{PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False, threaded=True)
