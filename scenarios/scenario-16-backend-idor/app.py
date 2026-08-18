#!/usr/bin/env python3
"""
CSZone CTF Range — Scenario 16: Backend IDOR (Insecure Direct Object Reference)
Port: 8016
"""
import os
import sys
import sqlite3
from functools import wraps
from flask import Flask, request, session, redirect, url_for, render_template
from werkzeug.security import generate_password_hash, check_password_hash

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8016
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "scenario16.db")

app = Flask(__name__)
app.secret_key = "scenario-16-secret-key"

def get_conn():
    return sqlite3.connect(DB_PATH)

def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS users;")
    cur.execute("DROP TABLE IF EXISTS orders;")
    cur.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT NOT NULL
        );
    """)
    cur.execute("""
        CREATE TABLE orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            item TEXT NOT NULL,
            amount TEXT NOT NULL,
            notes TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    """)
    cur.execute("INSERT INTO users (id, username, password_hash, email) VALUES (1, 'participant', ?, 'participant@cszone.internal')",
                (generate_password_hash("Range2024!"),))
    cur.execute("INSERT INTO users (id, username, password_hash, email) VALUES (2, 'finance_bot', ?, 'finance-bot@cszone.internal')",
                (generate_password_hash("FinBot2024Secure!"),))
    cur.execute("INSERT INTO orders (id, user_id, item, amount, notes) VALUES (1, 1, 'Training Range License', 'PKR 0 (internal)', 'Standard tier. Nothing sensitive here.')")
    cur.execute("INSERT INTO orders (id, user_id, item, amount, notes) VALUES (2, 2, 'Vendor Invoice Reconciliation', 'PKR 340,000', 'Internal audit trail — do not expose externally. Ref token: CTF{b4ck3nd_1d0r_r34l}')")
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
        return redirect(url_for("orders"))
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
                cur = conn.cursor()
                cur.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
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
            return redirect(url_for("orders"))
        error = "Invalid credentials."
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/orders")
@login_required
def orders():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, item, amount FROM orders WHERE user_id = ?", (session["user_id"],))
    rows = cur.fetchall()
    conn.close()
    return render_template("orders.html", rows=rows)

@app.route("/orders/<int:order_id>")
@login_required
def order_detail(order_id):
    conn = get_conn()
    cur = conn.cursor()
    # VULN (IDOR): No check that orders.user_id == session['user_id']
    cur.execute("SELECT id, user_id, item, amount, notes FROM orders WHERE id = ?", (order_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return "Order not found", 404
    return render_template("order_detail.html", order=row)

if __name__ == "__main__":
    init_db()
    print(f"[*] Scenario 16 running on http://localhost:{PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False)
