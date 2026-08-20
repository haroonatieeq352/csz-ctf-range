#!/usr/bin/env python3
"""
CSZone CTF Range — Scenario 18: Obfuscated & UUID Identifier Leakage IDOR
Port: 8018
"""
import os
import sys
import sqlite3
from flask import Flask, request, session, redirect, url_for, render_template, jsonify

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8018
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "scenario18.db")

app = Flask(__name__)
app.secret_key = "scenario-18-uuid-vault-secret-key"
FLAG_SECRET = "CTF{uu1d_l34k_d0cum3nt_v4ult}"

def get_conn():
    return sqlite3.connect(DB_PATH)

def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS documents;")
    cur.execute("DROP TABLE IF EXISTS audit_activity;")
    cur.execute("""
        CREATE TABLE documents (
            id INTEGER PRIMARY KEY,
            doc_uuid TEXT UNIQUE NOT NULL,
            title TEXT NOT NULL,
            owner_name TEXT NOT NULL,
            is_classified INTEGER DEFAULT 0,
            file_content TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
    """)
    cur.execute("""
        CREATE TABLE audit_activity (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor TEXT NOT NULL,
            action_desc TEXT NOT NULL,
            object_uuid TEXT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP
        );
    """)
    
    # Document 1: Public Employee Document (Carlos)
    cur.execute("""
        INSERT INTO documents (id, doc_uuid, title, owner_name, is_classified, file_content)
        VALUES (1, '7b1e4a90-3c21-4f88-9d10-8812a4f61e01', 'Employee_Onboarding_Handbook_2026.pdf', 'carlos', 0, 
        'CloudVault Standard Guidelines: Welcome to the enterprise team. All standard files are protected under default policies.');
    """)

    # Document 2: Classified Executive Document (CSO)
    cur.execute("""
        INSERT INTO documents (id, doc_uuid, title, owner_name, is_classified, file_content)
        VALUES (2, '8f9b2c34-91a0-4d5e-88fc-3176d1e49e22', 'Executive_Q4_Classified_Financial_Audit.pdf', 'Chief Security Officer', 1, 
        'CONFIDENTIAL EXECUTIVE BRIEFING:\nMaster Encryption Key and Security Token: CTF{uu1d_l34k_d0cum3nt_v4ult}\nAuthorized clearance only.');
    """)

    # Public audit activity feed (Leaks executive document UUID)
    cur.execute("""
        INSERT INTO audit_activity (actor, action_desc, object_uuid, timestamp)
        VALUES ('System Daemon', 'Automated nightly encryption pass on vault storage', '7b1e4a90-3c21-4f88-9d10-8812a4f61e01', '2026-08-19 14:02:11');
    """)
    cur.execute("""
        INSERT INTO audit_activity (actor, action_desc, object_uuid, timestamp)
        VALUES ('Chief Security Officer', 'Encrypted and deposited high-clearance executive audit report', '8f9b2c34-91a0-4d5e-88fc-3176d1e49e22', '2026-08-19 15:45:30');
    """)
    cur.execute("""
        INSERT INTO audit_activity (actor, action_desc, object_uuid, timestamp)
        VALUES ('carlos', 'Downloaded onboarding guidelines', '7b1e4a90-3c21-4f88-9d10-8812a4f61e01', '2026-08-19 16:10:05');
    """)

    conn.commit()
    conn.close()

@app.before_request
def ensure_session():
    if "username" not in session:
        session["username"] = "carlos"

@app.route("/")
@app.route("/vault")
def vault_view():
    conn = get_conn()
    my_docs = conn.execute("SELECT id, doc_uuid, title, owner_name, is_classified, created_at FROM documents WHERE owner_name = 'carlos'").fetchall()
    conn.close()
    return render_template("vault.html", docs=my_docs)

@app.route("/activity")
def activity_view():
    conn = get_conn()
    activities = conn.execute("SELECT actor, action_desc, object_uuid, timestamp FROM audit_activity ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("activity.html", activities=activities)

@app.route("/api/public/audit-feed")
def api_audit_feed():
    conn = get_conn()
    activities = conn.execute("SELECT actor, action_desc, object_uuid, timestamp FROM audit_activity ORDER BY id DESC").fetchall()
    conn.close()
    return jsonify({
        "success": True,
        "feed": [
            {
                "actor": a[0],
                "action": a[1],
                "doc_uuid": a[2],
                "timestamp": a[3]
            } for a in activities
        ]
    })

@app.route("/api/documents/download")
@app.route("/vault/view")
def api_download_doc():
    doc_id = request.args.get("doc_id", "").strip()
    if not doc_id:
        return jsonify({"success": False, "error": "Missing doc_id parameter"}), 400

    conn = get_conn()
    # VULN (IDOR): No ownership verification! Accepts any valid doc_uuid
    doc = conn.execute("SELECT id, doc_uuid, title, owner_name, is_classified, file_content, created_at FROM documents WHERE doc_uuid = ?", (doc_id,)).fetchone()
    conn.close()

    if not doc:
        return jsonify({"success": False, "error": "Document not found or invalid UUID identifier"}), 404

    is_flag_revealed = (doc[4] == 1)

    if request.path.startswith("/api/"):
        return jsonify({
            "success": True,
            "document": {
                "id": doc[0],
                "uuid": doc[1],
                "title": doc[2],
                "owner": doc[3],
                "is_classified": doc[4],
                "content": doc[5],
                "created_at": doc[6]
            },
            "flag": FLAG_SECRET if is_flag_revealed else None
        })

    return render_template("view_doc.html", doc=doc, is_flag_revealed=is_flag_revealed, flag=FLAG_SECRET if is_flag_revealed else None)

@app.route("/api/flag")
def api_flag():
    return jsonify({"success": True, "flag": FLAG_SECRET})

@app.route("/reset", methods=["GET", "POST"])
@app.route("/api/reset", methods=["GET", "POST"])
def reset_view():
    init_db()
    return redirect(url_for("vault_view"))

if __name__ == "__main__":
    init_db()
    print(f"[*] Scenario 18 running on http://localhost:{PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False)
