#!/usr/bin/env python3
"""
CSZone CTF Range — Scenario 20: BOLA Multi-Step Password Reset Account Takeover (Realistic Enterprise SaaS)
Port: 8020
Production-Ready: High-Concurrency WSGI (Gunicorn/Threaded), SQLite WAL, and Token/IP Rate Limiter.
"""
import os
import sys
import time
import sqlite3
import secrets
import random
import threading
from datetime import datetime
from collections import defaultdict
from flask import Flask, request, session, redirect, url_for, render_template, jsonify

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8020
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "scenario20.db")

app = Flask(__name__)
app.secret_key = "scenario-20-bola-reset-secret-key"
FLAG_SECRET = "CTF{b0l4_p4ssw0rd_r3s3t_4cc0unt_t4k30v3r}"

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
    cur.execute("DROP TABLE IF EXISTS reset_sessions;")
    cur.execute("DROP TABLE IF EXISTS mailbox;")
    
    cur.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            title TEXT NOT NULL,
            department TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            account_balance TEXT NOT NULL,
            vault_flag TEXT
        );
    """)
    
    cur.execute("""
        CREATE TABLE reset_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_token TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL,
            otp_code TEXT NOT NULL,
            is_verified INTEGER DEFAULT 0,
            reset_token TEXT
        );
    """)

    cur.execute("""
        CREATE TABLE mailbox (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient TEXT NOT NULL,
            sender TEXT NOT NULL,
            subject TEXT NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
    """)
    
    # Target Admin Account (ID 100)
    cur.execute("""
        INSERT INTO users (id, email, full_name, title, department, password, role, account_balance, vault_flag)
        VALUES (100, 'admin@apexpay.io', 'Alexander Vance', 'Chief Financial Officer & Executive Vault Admin', 'Executive Treasury', 'SuperSecretApexVault2026!', 'admin', '$2,450,000.00 USD', ?);
    """, (FLAG_SECRET,))

    # Standard Attacker Account (ID 101)
    cur.execute("""
        INSERT INTO users (id, email, full_name, title, department, password, role, account_balance, vault_flag)
        VALUES (101, 'carlos@apexpay.io', 'Carlos Rivera', 'Junior Liquidity Operations Analyst', 'Financial Operations', 'carlos123', 'user', '$150.00 USD', NULL);
    """)

    # Colleague Accounts for realistic directory
    cur.execute("""
        INSERT INTO users (id, email, full_name, title, department, password, role, account_balance, vault_flag)
        VALUES (102, 'sarah.j@apexpay.io', 'Sarah Jenkins', 'Senior Risk & Compliance Officer', 'Audit & Compliance', 'S@rahRisk2026!', 'user', '$8,400.00 USD', NULL);
    """)

    cur.execute("""
        INSERT INTO users (id, email, full_name, title, department, password, role, account_balance, vault_flag)
        VALUES (103, 'david.k@apexpay.io', 'David Kim', 'Principal Platform Architect', 'Core Infrastructure', 'D@v1dPlatform!', 'user', '$12,900.00 USD', NULL);
    """)

    # Initial Welcome Email in Carlos's Mailbox
    cur.execute("""
        INSERT INTO mailbox (recipient, sender, subject, body, created_at)
        VALUES ('carlos@apexpay.io', 'it-support@apexpay.io', 'Welcome to ApexPay Treasury Portal', 'Hi Carlos, welcome to the Treasury Operations team. Your employee workstation account (#101) has been provisioned. Contact IT for access assistance.', '2026-08-22 09:00:00');
    """)

    conn.commit()
    conn.close()

if not os.path.exists(DB_PATH):
    init_db()

@app.route("/")
@app.route("/login", methods=["GET", "POST"])
def login_view():
    error = None
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        
        conn = get_conn()
        user = conn.execute("SELECT id, email, full_name, role, account_balance, vault_flag FROM users WHERE email = ? AND password = ?", (email, password)).fetchone()
        conn.close()

        if user:
            session["user_id"] = user[0]
            session["email"] = user[1]
            session["full_name"] = user[2]
            session["role"] = user[3]
            return redirect(url_for("dashboard_view"))
        error = "Invalid credentials. Please verify your corporate email and password."

    return render_template("login.html", error=error)

@app.route("/directory")
def directory_view():
    conn = get_conn()
    members = conn.execute("SELECT id, full_name, title, department, email, role FROM users ORDER BY id ASC").fetchall()
    conn.close()
    return render_template("directory.html", members=members)

@app.route("/mail")
def mail_view():
    conn = get_conn()
    emails = conn.execute("SELECT id, recipient, sender, subject, body, created_at FROM mailbox WHERE recipient = 'carlos@apexpay.io' ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("mail.html", emails=emails)

@app.route("/api/mail/inbox")
def api_mail_inbox():
    conn = get_conn()
    emails = conn.execute("SELECT id, recipient, sender, subject, body, created_at FROM mailbox WHERE recipient = 'carlos@apexpay.io' ORDER BY id DESC").fetchall()
    conn.close()
    return jsonify({
        "success": True,
        "count": len(emails),
        "messages": [{"id": r[0], "recipient": r[1], "sender": r[2], "subject": r[3], "body": r[4], "created_at": r[5]} for r in emails]
    })

@app.route("/forgot-password")
def forgot_password_view():
    return render_template("reset.html")

@app.route("/dashboard")
def dashboard_view():
    if "user_id" not in session:
        return redirect(url_for("login_view"))

    conn = get_conn()
    user = conn.execute("SELECT id, email, full_name, role, account_balance, vault_flag, title, department FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    conn.close()

    if not user:
        session.clear()
        return redirect(url_for("login_view"))

    is_admin = (user[3] == "admin")
    return render_template("dashboard.html", user=user, is_admin=is_admin, flag=FLAG_SECRET if is_admin else None)

@app.route("/logout")
def logout_view():
    session.clear()
    return redirect(url_for("login_view"))

# ── API Password Reset Multi-Step Flow ──────────────────────────────────────

@app.route("/api/auth/forgot-password", methods=["POST"])
def api_forgot_password():
    data = request.get_json(force=True, silent=True) or request.form.to_dict() or {}
    email = data.get("email", "").strip()
    
    if not email:
        return jsonify({"success": False, "error": "Email is required"}), 400

    conn = get_conn()
    user = conn.execute("SELECT id, email, full_name FROM users WHERE email = ?", (email,)).fetchone()
    
    if not user:
        conn.close()
        return jsonify({"success": False, "error": "No account found with this corporate email"}), 404

    sess_token = "sess_" + secrets.token_hex(8)
    
    # Realistic dynamic OTP generated and delivered to corporate mailbox
    otp = "654321" if email == "carlos@apexpay.io" else str(random.randint(100000, 999999))
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn.execute("INSERT INTO reset_sessions (session_token, email, otp_code) VALUES (?, ?, ?)", (sess_token, email, otp))
    
    # Deliver OTP message into recipient's Corporate Webmail
    if email == "carlos@apexpay.io":
        email_body = f"Hello {user[2]},<br><br>We received a request to reset the password for your ApexPay corporate account (Employee #{user[0]}).<br><br>Your 6-digit one-time security passcode is: <strong style='color:#fbbf24; font-size:1.2rem; letter-spacing:3px;'>{otp}</strong><br><br>This passcode expires in 10 minutes. If you did not initiate this request, contact Security immediately."
        conn.execute("INSERT INTO mailbox (recipient, sender, subject, body, created_at) VALUES (?, 'security@apexpay.io', 'ApexPay Security Verification Code', ?, ?)", (email, email_body, timestamp))

    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": f"A 6-digit verification passcode has been dispatched to '{email}'. Check your Corporate Webmail inbox.",
        "session_token": sess_token,
        "account_id": user[0]
    })

@app.route("/api/auth/verify-reset-step", methods=["POST"])
def api_verify_reset_step():
    data = request.get_json(force=True, silent=True) or request.form.to_dict() or {}
    sess_token = data.get("session_token", "").strip()
    otp = data.get("otp", "").strip()
    target_account_id = data.get("account_id")

    if not sess_token or not otp or target_account_id is None:
        return jsonify({"success": False, "error": "Missing session_token, otp, or account_id"}), 400

    conn = get_conn()
    sess = conn.execute("SELECT id, session_token, email, otp_code FROM reset_sessions WHERE session_token = ?", (sess_token,))
    sess = sess.fetchone()
    
    if not sess:
        conn.close()
        return jsonify({"success": False, "error": "Invalid or expired session token"}), 400

    if sess[3] != otp:
        conn.close()
        return jsonify({"success": False, "error": "Invalid OTP verification code"}), 403

    target_user = conn.execute("SELECT id, email FROM users WHERE id = ?", (target_account_id,)).fetchone()
    if not target_user:
        conn.close()
        return jsonify({"success": False, "error": f"Target account #{target_account_id} not found"}), 404

    # BOLA VULNERABILITY: Session state is bound to client-supplied target_account_id instead of original session email
    reset_token = "rst_tok_" + secrets.token_hex(16)
    conn.execute("UPDATE reset_sessions SET is_verified = 1, reset_token = ?, email = ? WHERE id = ?", (reset_token, target_user[1], sess[0]))
    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": f"Identity verified for account #{target_user[0]} ({target_user[1]}). Password reset token generated.",
        "account_id": target_user[0],
        "email": target_user[1],
        "reset_token": reset_token
    })

@app.route("/api/auth/confirm-new-password", methods=["POST"])
def api_confirm_new_password():
    data = request.get_json(force=True, silent=True) or request.form.to_dict() or {}
    reset_token = data.get("reset_token", "").strip()
    new_password = data.get("new_password", "").strip()

    if not reset_token or not new_password:
        return jsonify({"success": False, "error": "Missing reset_token or new_password"}), 400

    conn = get_conn()
    sess = conn.execute("SELECT id, email, is_verified FROM reset_sessions WHERE reset_token = ? AND is_verified = 1", (reset_token,)).fetchone()
    
    if not sess:
        conn.close()
        return jsonify({"success": False, "error": "Invalid or unverified reset token"}), 403

    conn.execute("UPDATE users SET password = ? WHERE id = (SELECT id FROM users WHERE email = ?)", (new_password, sess[1]))
    conn.execute("DELETE FROM reset_sessions WHERE id = ?", (sess[0],))
    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": f"Password for account '{sess[1]}' has been reset successfully. You can now login with your new credentials."
    })

@app.route("/api/flag")
def api_flag():
    if session.get("role") == "admin":
        return jsonify({"success": True, "flag": FLAG_SECRET})
    return jsonify({"success": False, "error": "Access Denied: Administrator account required"}), 403

@app.route("/reset", methods=["GET", "POST"])
@app.route("/api/reset", methods=["GET", "POST"])
def reset_view():
    init_db()
    session.clear()
    return redirect(url_for("login_view"))

if __name__ == "__main__":
    init_db()
    print(f"[*] Scenario 20 running on http://localhost:{PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False, threaded=True)
