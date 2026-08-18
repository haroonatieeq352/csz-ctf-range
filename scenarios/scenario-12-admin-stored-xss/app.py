#!/usr/bin/env python3
"""
CSZone CTF Range — Scenario 12: SQLi Admin Bypass & Stored XSS Chain
Port: 8012
"""
import os
import sys
import sqlite3
from flask import Flask, request, session, redirect, url_for, render_template, make_response

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8012
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "scenario12.db")

app = Flask(__name__)
app.secret_key = "scenario-12-secret-key"

def get_conn():
    return sqlite3.connect(DB_PATH)

def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS legacy_admin_creds;")
    cur.execute("DROP TABLE IF EXISTS guestbook;")
    cur.execute("DROP TABLE IF EXISTS stolen_cookies;")
    cur.execute("""
        CREATE TABLE legacy_admin_creds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        );
    """)
    cur.execute("""
        CREATE TABLE guestbook (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
    """)
    cur.execute("""
        CREATE TABLE stolen_cookies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            captured_at TEXT DEFAULT CURRENT_TIMESTAMP,
            source_ip TEXT,
            cookie_data TEXT
        );
    """)
    cur.execute("INSERT INTO legacy_admin_creds (username, password) VALUES ('admin', 'L3g4cyAdm1n_2023!');")
    cur.execute("INSERT INTO guestbook (name, message) VALUES ('CSZone Bot', 'Welcome to the range guestbook. Be nice.');")
    conn.commit()
    conn.close()

@app.route("/")
@app.route("/guestbook", methods=["GET", "POST"])
def guestbook_view():
    conn = get_conn()
    if request.method == "POST":
        name = request.form.get("name", "anonymous").strip() or "anonymous"
        message = request.form.get("message", "")
        conn.execute("INSERT INTO guestbook (name, message) VALUES (?, ?)", (name, message))
        conn.commit()
        conn.close()
        return redirect(url_for("guestbook_view"))

    entries = conn.execute("SELECT name, message, created_at FROM guestbook ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("guestbook.html", entries=entries)

@app.route("/legacy-admin/login", methods=["GET", "POST"])
def legacy_admin_login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        conn = get_conn()
        # VULN (SQLi Auth Bypass): raw query concatenation
        query = f"SELECT * FROM legacy_admin_creds WHERE username = '{username}' AND password = '{password}'"
        row = None
        try:
            row = conn.execute(query).fetchone()
        except sqlite3.OperationalError as e:
            error = f"Query error: {e}"
        conn.close()

        if row:
            session["role"] = "admin"
            session["username"] = "admin (legacy)"
            resp = make_response(redirect(url_for("admin_inbox")))
            # VULN: sensitive flag in non-HttpOnly cookie for XSS exfiltration
            resp.set_cookie("admin_session_flag", "CTF{st0r3d_c00k13_th3ft}", httponly=False)
            return resp
        error = error or "Invalid credentials."

    return render_template("legacy_admin_login.html", error=error)

@app.route("/admin/inbox")
def admin_inbox():
    if session.get("role") != "admin":
        return redirect(url_for("legacy_admin_login"))
    conn = get_conn()
    entries = conn.execute("SELECT name, message, created_at FROM guestbook ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("admin_inbox.html", entries=entries)

@app.route("/xss/collect")
def xss_collect():
    data = request.args.get("c", "")
    conn = get_conn()
    conn.execute("INSERT INTO stolen_cookies (source_ip, cookie_data) VALUES (?, ?)", (request.remote_addr, data))
    conn.commit()
    conn.close()
    return "", 204

@app.route("/xss/collect/log")
def xss_collect_log():
    conn = get_conn()
    rows = conn.execute("SELECT captured_at, source_ip, cookie_data FROM stolen_cookies ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("xss_log.html", rows=rows)

if __name__ == "__main__":
    init_db()
    print(f"[*] Scenario 12 running on http://localhost:{PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False)
