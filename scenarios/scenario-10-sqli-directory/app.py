#!/usr/bin/env python3
"""
CSZone CTF Range — Scenario 10: Personnel Directory UNION SQLi
Port: 8010
"""
import os
import sys
import sqlite3
from flask import Flask, request, render_template

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8010
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "scenario10.db")

app = Flask(__name__)
app.secret_key = "scenario-10-secret-key"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS employees;")
    cur.execute("DROP TABLE IF EXISTS flags;")
    cur.execute("DROP TABLE IF EXISTS staff_clearances;")
    cur.execute("""
        CREATE TABLE employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            badge_number INTEGER NOT NULL,
            email TEXT NOT NULL
        );
    """)
    cur.execute("""
        CREATE TABLE flags (
            label TEXT NOT NULL,
            clearance_id INTEGER NOT NULL,
            value TEXT NOT NULL
        );
    """)
    cur.execute("""
        CREATE TABLE staff_clearances (
            officer_name TEXT NOT NULL,
            clearance_level INTEGER NOT NULL,
            master_flag TEXT NOT NULL
        );
    """)
    employees = [
        ('Ayesha Raza', 1042, 'ayesha.raza@cszone.internal'),
        ('Bilal Hassan', 1088, 'bilal.hassan@cszone.internal'),
        ('Sara Khan', 1015, 'sara.khan@cszone.internal'),
        ('Usman Tariq', 1092, 'usman.tariq@cszone.internal'),
        ('Mahnoor Iqbal', 1033, 'mahnoor.iqbal@cszone.internal')
    ]
    cur.executemany("INSERT INTO employees (name, badge_number, email) VALUES (?, ?, ?)", employees)
    cur.execute("INSERT INTO flags (label, clearance_id, value) VALUES (?, ?, ?)", 
                ('Master Clearance Flag', 9, 'CTF{un10n_s3l3ct_m4st3r}'))
    cur.execute("INSERT INTO staff_clearances (officer_name, clearance_level, master_flag) VALUES (?, ?, ?)",
                ('Director Vance', 9, 'CTF{un10n_s3l3ct_m4st3r}'))
    conn.commit()
    conn.close()

def is_numeric_value(val):
    """Check if value is integer/numeric."""
    if isinstance(val, (int, float)):
        return True
    try:
        int(str(val))
        return True
    except (ValueError, TypeError):
        return False

@app.route("/")
@app.route("/directory")
def directory_view():
    q = request.args.get("q", "")
    results = []
    error = None
    status_code = 200

    if q:
        # Check for blocked '--' comment syntax
        if "--" in q:
            error = "Query Execution Error: '--' comment syntax is blocked by application filter. Use alternate SQL comment operator ('#' or '%23')."
            status_code = 500
            return render_template("directory.html", q=q, results=results, error=error), status_code

        # Process '#' comment syntax into backend SQL comment
        processed_q = q.replace("#", "--")

        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        # VULN (SQL Injection — 3-column UNION extraction):
        query = f"SELECT name, badge_number, email FROM employees WHERE name LIKE '%{processed_q}%'"
        try:
            cur.execute(query)
            rows = cur.fetchall()

            # Strict SQL Data Type Sequence Validation: Column 2 MUST be an INTEGER
            for row in rows:
                if len(row) >= 2 and not is_numeric_value(row[1]):
                    raise sqlite3.OperationalError(
                        f"Datatype mismatch in UNION query at column 2 (badge_number). "
                        f"Expected INTEGER/NUMERIC, received incompatible TEXT literal '{row[1]}'."
                    )
            results = rows
        except sqlite3.OperationalError as e:
            error = str(e)
            status_code = 500
        conn.close()

    return render_template("directory.html", q=q, results=results, error=error), status_code

if __name__ == "__main__":
    init_db()
    print(f"[*] Scenario 10 running on http://localhost:{PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False)
