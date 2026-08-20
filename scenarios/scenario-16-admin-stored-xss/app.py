#!/usr/bin/env python3
"""
CSZone CTF Range — Scenario 16: INSERT SQLi to Second-Order Stored XSS Chain
Port: 8016
"""
import os
import sys
import sqlite3
from flask import Flask, request, redirect, url_for, render_template

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8016
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "scenario16.db")

app = Flask(__name__)
app.secret_key = "scenario-16-enterprise-secret-key"
FLAG_SECRET = "CTF{1ns3rt_sqli_t0_st0r3d_xss_ch41n}"

def get_conn():
    return sqlite3.connect(DB_PATH)

def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS support_tickets;")
    cur.execute("""
        CREATE TABLE support_tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            submitter TEXT NOT NULL,
            department TEXT NOT NULL,
            issue_desc TEXT NOT NULL,
            priority TEXT DEFAULT 'LOW',
            is_trusted INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
    """)
    cur.execute("""
        INSERT INTO support_tickets (submitter, department, issue_desc, priority, is_trusted) 
        VALUES ('Infra SecOps', 'IT-INFRA', 'Routine firewall telemetry validation pass.', 'NORMAL', 1);
    """)
    conn.commit()
    conn.close()

@app.route("/")
@app.route("/tickets", methods=["GET", "POST"])
def tickets_view():
    conn = get_conn()
    error = None
    success = None

    if request.method == "POST":
        submitter = request.form.get("submitter", "Anonymous").strip() or "Anonymous"
        department = request.form.get("department", "GENERAL").strip() or "GENERAL"
        issue_desc = request.form.get("issue_desc", "").strip()

        # VULNERABLE: Direct string interpolation into INSERT query statement
        # Expected schema: (submitter, department, issue_desc, priority, is_trusted)
        query = (
            f"INSERT INTO support_tickets (submitter, department, issue_desc, priority, is_trusted) "
            f"VALUES ('{submitter}', '{department}', '{issue_desc}', 'LOW', 0)"
        )
        try:
            conn.execute(query)
            conn.commit()
            success = "Support ticket submitted successfully and queued for priority triage."
        except sqlite3.OperationalError as e:
            error = f"Database Query Error: {e}"

    # Public view only shows normal status of tickets
    tickets = conn.execute("SELECT id, submitter, department, priority, created_at FROM support_tickets ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("tickets.html", tickets=tickets, error=error, success=success)

@app.route("/admin/compliance")
def admin_compliance():
    conn = get_conn()
    # Internal Admin Queue: Only renders high-priority / verified trusted audit tickets
    # Untrusted user submissions (is_trusted=0 and priority='LOW') NEVER appear here
    # UNLESS the user bypassed constraints via INSERT SQL Injection!
    triaged_tickets = conn.execute(
        "SELECT id, submitter, department, issue_desc, priority, created_at "
        "FROM support_tickets "
        "WHERE is_trusted = 1 OR priority = 'CRITICAL' "
        "ORDER BY id DESC"
    ).fetchall()
    conn.close()
    return render_template("compliance.html", tickets=triaged_tickets)

@app.route("/reset", methods=["GET", "POST"])
@app.route("/api/reset", methods=["GET", "POST"])
def reset_view():
    init_db()
    return redirect(url_for("tickets_view"))

@app.route("/api/flag")
def api_flag():
    return {"success": True, "flag": FLAG_SECRET}

if __name__ == "__main__":
    init_db()
    print(f"[*] Scenario 16 running on http://localhost:{PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False)
