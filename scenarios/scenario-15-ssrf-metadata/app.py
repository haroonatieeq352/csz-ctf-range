#!/usr/bin/env python3
"""
CSZone CTF Range — Scenario 15: Server-Side Request Forgery (SSRF)
Port: 8015
"""
import os
import sys
import sqlite3
import requests
from functools import wraps
from flask import Flask, request, session, redirect, url_for, render_template, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8015
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "scenario15.db")

app = Flask(__name__)
app.secret_key = "scenario-15-secret-key"

def get_conn():
    return sqlite3.connect(DB_PATH)

def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS users;")
    cur.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT NOT NULL
        );
    """)
    conn.commit()
    conn.close()

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
        return redirect(url_for("avatar_import"))
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        if not username or not email or not password:
            error = "All fields required."
        else:
            conn = get_conn()
            try:
                conn.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
                             (username, generate_password_hash(password), email))
                conn.commit()
                conn.close()
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                error = "Username already taken."
            conn.close()
    return render_template("register.html", error=error)

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
            return redirect(url_for("avatar_import"))
        error = "Invalid credentials."
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/avatar-import", methods=["GET", "POST"])
@login_required
def avatar_import():
    result = None
    error = None
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        try:
            # VULN (SSRF): Arbitrary server-side request without IP restrictions
            resp = requests.get(url, timeout=3)
            result = resp.text[:2000]
        except Exception as e:
            error = f"Fetch failed: {e}"
    return render_template("avatar_import.html", result=result, error=error)

@app.route("/internal/metadata")
def internal_metadata():
    if request.remote_addr not in ("127.0.0.1", "::1", "localhost"):
        return "Forbidden — internal service only.", 403
    return jsonify({
        "service": "internal-cloud-metadata",
        "build": "range-backend-1.0.0",
        "flag": "CTF{ssrf_1nt3rn4l_m3t4d4t4}",
        "access_scope": "node-internal"
    })

if __name__ == "__main__":
    init_db()
    print(f"[*] Scenario 15 running on http://localhost:{PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False)
