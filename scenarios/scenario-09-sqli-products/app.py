#!/usr/bin/env python3
"""
CSZone CTF Range — Scenario 09: E-Commerce Product Filter SQLi
Port: 8009
"""
import os
import sys
import sqlite3
from flask import Flask, request, render_template

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8009
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "scenario09.db")

app = Flask(__name__)
app.secret_key = "scenario-09-secret-key"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS products;")
    cur.execute("DROP TABLE IF EXISTS site_secrets;")
    cur.execute("""
        CREATE TABLE products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            description TEXT NOT NULL,
            price TEXT NOT NULL,
            is_released INTEGER DEFAULT 1
        );
    """)
    cur.execute("""
        CREATE TABLE site_secrets (
            title TEXT NOT NULL,
            secret_flag TEXT NOT NULL
        );
    """)
    products = [
        ('Hardware Security Key', 'Hardware', 'FIDO2 & U2F physical security token for multi-factor authentication.', '$49.99', 1),
        ('Encrypted USB Vault', 'Hardware', 'Hardware-encrypted USB 3.2 flash drive with keypad access.', '$89.99', 1),
        ('Network Tap Probe', 'Hardware', 'Passive gigabit ethernet monitoring tap for traffic inspection.', '$129.99', 1),
        ('Cyber Defense Terminal', 'Hardware', 'Ruggedized field diagnostic terminal with dual NICs.', '$499.99', 1),
        ('Prototype Quantum Key Dongle', 'Hardware', 'Unreleased quantum-resistant hardware token (Confidential).', '$999.99', 0),
        ('Network Packet Analyzer', 'Software', 'Enterprise DPI deep-packet inspection suite.', '$299.00', 1),
        ('Endpoint Shield Agent', 'Software', 'Next-gen anti-tamper security defense agent.', '$149.00', 1)
    ]
    cur.executemany("INSERT INTO products (name, category, description, price, is_released) VALUES (?, ?, ?, ?, ?)", products)
    cur.execute("INSERT INTO site_secrets (title, secret_flag) VALUES (?, ?)", 
                ('Master Secret Record', 'CTF{un10n_b4s1cs_m4st3r} -- [Next Target]: Proceed to Scenario 10'))
    conn.commit()
    conn.close()

@app.route("/")
@app.route("/products")
def products_view():
    category = request.args.get("category", "")
    categories = ["Hardware", "Software"]
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    products = []
    error = None
    status_code = 200

    if category:
        # VULN: raw string formatting in SQL query
        query = f"SELECT name, description FROM products WHERE is_released = 1 AND category = '{category}'"
        try:
            cur.execute(query)
            products = cur.fetchall()
        except sqlite3.OperationalError as e:
            error = str(e)
            status_code = 500
    else:
        cur.execute("SELECT name, description FROM products WHERE is_released = 1")
        products = cur.fetchall()

    conn.close()
    return render_template("products.html", products=products, categories=categories, selected_category=category, error=error), status_code

if __name__ == "__main__":
    init_db()
    print(f"[*] Scenario 09 running on http://localhost:{PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False)
