#!/usr/bin/env python3
"""
CSZone CTF Range — Scenario 14: Unrestricted File Upload & Stored XSS
Port: 8014
"""
import os
import sys
import sqlite3
from functools import wraps
from flask import Flask, request, session, redirect, url_for, render_template, send_from_directory
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8018
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "static", "uploads")
DB_PATH = os.path.join(BASE_DIR, "scenario18.db")

os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = "scenario-18-secret-key"

BLOCKED_EXTENSIONS = {".php", ".py", ".exe", ".sh", ".jsp", ".asp", ".aspx"}

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
        return redirect(url_for("upload"))
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
            return redirect(url_for("upload"))
        error = "Invalid credentials."
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    error = None
    uploaded_url = None
    if request.method == "POST":
        f = request.files.get("file")
        if not f or f.filename == "":
            error = "No file selected."
        else:
            filename = secure_filename(f.filename)
            ext = os.path.splitext(filename)[1].lower()
            if ext in BLOCKED_EXTENSIONS:
                error = f"File type {ext} is not allowed."
            else:
                dest = os.path.join(UPLOAD_DIR, filename)
                f.save(dest)
                uploaded_url = f"/static/uploads/{filename}"
    return render_template("upload.html", error=error, uploaded_url=uploaded_url)

if __name__ == "__main__":
    init_db()
    print(f"[*] Scenario 18 running on http://localhost:{PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False)
