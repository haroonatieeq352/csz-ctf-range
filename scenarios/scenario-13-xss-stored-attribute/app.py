#!/usr/bin/env python3
"""
CSZone CTF Range — Scenario 13: Stored XSS in Attribute Context
Port: 8013
"""
import os
import sys
import re
import sqlite3
from flask import Flask, request, redirect, url_for, render_template

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8013
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "scenario13.db")

app = Flask(__name__)
app.secret_key = "scenario-13-secret-key"
FLAG_SECRET = "CTF{st0r3d_4ttr1but3_br34k0ut}"

def get_conn():
    return sqlite3.connect(DB_PATH)

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

def naive_script_filter(text):
    """Naive filter that only strips <script> tags but ignores quotes and event handlers."""
    return re.sub(r"<\s*/?\s*script[^>]*>", "", text, flags=re.IGNORECASE)

@app.route("/", methods=["GET", "POST"])
@app.route("/feedback", methods=["GET", "POST"])
def feedback_view():
    if request.method == "POST":
        author = request.form.get("author", "").strip() or "anonymous"
        comment = request.form.get("comment", "").strip()
        
        # Naive filter applied (leaves quotes and attributes vulnerable)
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
    return {"success": True, "flag": FLAG_SECRET}

@app.route("/reset", methods=["GET", "POST"])
def reset_view():
    init_db()
    return redirect(url_for("feedback_view"))

if __name__ == "__main__":
    init_db()
    print(f"[*] Scenario 13 running on http://localhost:{PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False)
