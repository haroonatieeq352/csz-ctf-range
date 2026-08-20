#!/usr/bin/env python3
"""
CSZone CTF Range — Scenario 20: BOLA Multi-Step Password Reset Account Takeover
Port: 8020
"""
import os
import sys
import sqlite3
import secrets
from flask import Flask, request, session, redirect, url_for, render_template, jsonify

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8020
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "scenario20.db")

app = Flask(__name__)
app.secret_key = "scenario-20-bola-reset-secret-key"
FLAG_SECRET = "CTF{b0l4_p4ssw0rd_r3s3t_4cc0unt_t4k30v3r}"

def get_conn():
    return sqlite3.connect(DB_PATH)

def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS users;")
    cur.execute("DROP TABLE IF EXISTS reset_sessions;")
    cur.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
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
    
    # Target Admin Account (ID 100)
    cur.execute("""
        INSERT INTO users (id, email, full_name, password, role, account_balance, vault_flag)
        VALUES (100, 'admin@apexpay.io', 'Executive Administrator', 'SuperSecretApexVault2026!', 'admin', '$2,450,000.00 USD', ?);
    """, (FLAG_SECRET,))

    # Standard Attacker Account (ID 101)
    cur.execute("""
        INSERT INTO users (id, email, full_name, password, role, account_balance, vault_flag)
        VALUES (101, 'carlos@apexpay.io', 'Carlos Rivera', 'carlos123', 'user', '$150.00 USD', NULL);
    """)

    conn.commit()
    conn.close()

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
        error = "Invalid credentials. Please verify your email and password."

    return render_template("login.html", error=error)

@app.route("/forgot-password")
def forgot_password_view():
    return render_template("reset.html")

@app.route("/dashboard")
def dashboard_view():
    if "user_id" not in session:
        return redirect(url_for("login_view"))

    conn = get_conn()
    user = conn.execute("SELECT id, email, full_name, role, account_balance, vault_flag FROM users WHERE id = ?", (session["user_id"],)).fetchone()
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
    user = conn.execute("SELECT id, email FROM users WHERE email = ?", (email,)).fetchone()
    conn.close()

    if not user:
        return jsonify({"success": False, "error": "No account found with this email"}), 404

    # Generate session token and simulated OTP
    sess_token = "sess_" + secrets.token_hex(8)
    # Standard testing OTP for Carlos is 654321
    otp = "654321" if email == "carlos@apexpay.io" else secrets.token_hex(3).upper()

    conn = get_conn()
    conn.execute("INSERT INTO reset_sessions (session_token, email, otp_code) VALUES (?, ?, ?)", (sess_token, email, otp))
    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": f"6-digit OTP verification code dispatched to '{email}'. (For Carlos, your inbox OTP is 654321)",
        "session_token": sess_token,
        "account_id": user[0]
    })

@app.route("/api/auth/verify-reset-step", methods=["POST"])
def api_verify_reset_step():
    data = request.get_json(force=True, silent=True) or request.form.to_dict() or {}
    sess_token = data.get("session_token", "").strip()
    otp = data.get("otp", "").strip()
    # VULN (BOLA): Takes account_id from request body instead of session email!
    target_account_id = data.get("account_id")

    if not sess_token or not otp or target_account_id is None:
        return jsonify({"success": False, "error": "Missing session_token, otp, or account_id"}), 400

    conn = get_conn()
    sess = conn.execute("SELECT id, session_token, email, otp_code FROM reset_sessions WHERE session_token = ?", (sess_token,)).fetchone()
    
    if not sess:
        conn.close()
        return jsonify({"success": False, "error": "Invalid or expired session token"}), 400

    # Verify OTP against session
    if sess[3] != otp:
        conn.close()
        return jsonify({"success": False, "error": "Invalid OTP verification code"}), 403

    # Target user to generate reset token for
    target_user = conn.execute("SELECT id, email FROM users WHERE id = ?", (target_account_id,)).fetchone()
    if not target_user:
        conn.close()
        return jsonify({"success": False, "error": f"Target account #{target_account_id} not found"}), 404

    # BOLA: Generates password reset token for the target_account_id!
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

    # If the token was issued for an account, update that user's password
    # Look up by reset token association or email
    conn.execute("UPDATE users SET password = ? WHERE id = (SELECT id FROM users WHERE email = ?)", (new_password, sess[1]))
    # Delete used session
    conn.execute("DELETE FROM reset_sessions WHERE id = ?", (sess[0],))
    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": f"Password for account '{sess[1]}' has been reset successfully. You can now login with your new password."
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
    app.run(host="0.0.0.0", port=PORT, debug=False)
