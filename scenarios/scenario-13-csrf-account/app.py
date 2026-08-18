#!/usr/bin/env python3
"""
CSZone CTF Range — Scenario 13: Cross-Site Request Forgery (CSRF)
Port: 8013
"""
import os
import sys
import sqlite3
from functools import wraps
from flask import Flask, request, session, redirect, url_for, render_template, make_response
from werkzeug.security import generate_password_hash, check_password_hash

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8013
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "scenario13.db")

app = Flask(__name__)
app.secret_key = "scenario-13-secret-key"
app.config.update(
    SESSION_COOKIE_SAMESITE="None",
    SESSION_COOKIE_SECURE=False,
)

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
    cur.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
                ("victim_user", generate_password_hash("VictimPass123!"), "victim@cszone.internal"))
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
        return redirect(url_for("account"))
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
        cur.execute("SELECT id, username, password_hash, email FROM users WHERE username = ?", (username,))
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
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT username, email FROM users WHERE id = ?", (session["user_id"],))
    row = cur.fetchone()
    conn.close()
    user = {"username": row[0], "email": row[1]} if row else {"username": "User", "email": ""}
    return render_template("account.html", user=user)

@app.route("/account/email", methods=["POST"])
@login_required
def change_email():
    new_email = request.form.get("email", "").strip()
    conn = get_conn()
    conn.execute("UPDATE users SET email = ? WHERE id = ?", (new_email, session["user_id"]))
    conn.commit()
    conn.close()

    flag = ""
    # VULN (CSRF): changes email with no CSRF token check
    if new_email.endswith("@attacker-controlled.test"):
        flag = "CTF{csrf_n0_t0k3n_pwn3d}"

    user = {"username": session.get("username", "User"), "email": new_email}
    return render_template("account.html", user=user, csrf_flag=flag)

if __name__ == "__main__":
    init_db()
    print(f"[*] Scenario 13 running on http://localhost:{PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False)
