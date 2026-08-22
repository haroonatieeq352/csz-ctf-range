#!/usr/bin/env python3
"""
CSZone CTF Range — Scenario 18: Obfuscated & UUID Identifier Leakage IDOR
Port: 8018
Production-Ready: High-Concurrency WSGI (Gunicorn/Threaded), SQLite WAL, and Token/IP Rate Limiter.
"""
import os
import sys
import time
import base64
import json
import sqlite3
import threading
from collections import defaultdict
from flask import Flask, request, session, redirect, url_for, render_template, jsonify

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8018
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "scenario18.db")

app = Flask(__name__)
app.secret_key = "scenario-18-uuid-vault-secret-key"
FLAG_SECRET = "CTF{uu1d_l34k_d0cum3nt_v4ult}"

class SlidingWindowRateLimiter:
    """Thread-safe Sliding Window Rate Limiter (60 req/min per IP/Token)."""
    def __init__(self, max_requests=60, window_seconds=60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(list)
        self.lock = threading.Lock()
        self._last_cleanup = time.time()

    def is_allowed(self, client_id):
        now = time.time()
        with self.lock:
            if now - self._last_cleanup > 60:
                cutoff = now - self.window_seconds
                stale = [k for k, v in self.requests.items() if not v or v[-1] < cutoff]
                for k in stale:
                    del self.requests[k]
                self._last_cleanup = now

            timestamps = self.requests[client_id]
            cutoff = now - self.window_seconds
            while timestamps and timestamps[0] < cutoff:
                timestamps.pop(0)

            if len(timestamps) < self.max_requests:
                timestamps.append(now)
                return True, self.max_requests - len(timestamps), 0
            else:
                retry_after = int(timestamps[0] + self.window_seconds - now) + 1
                return False, 0, max(1, retry_after)

rate_limiter = SlidingWindowRateLimiter(max_requests=60, window_seconds=60)

@app.before_request
def check_rate_limit():
    if request.path.startswith("/static/"):
        return None
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1").split(",")[0].strip()
    allowed, remaining, retry_after = rate_limiter.is_allowed(client_ip)
    if not allowed:
        resp = jsonify({
            "error": "Too Many Requests",
            "message": "DDoS Prevention: Rate limit exceeded (Max 60 requests/minute). Please slow down.",
            "retry_after_seconds": retry_after
        })
        resp.status_code = 429
        resp.headers["Retry-After"] = str(retry_after)
        resp.headers["X-RateLimit-Limit"] = "60"
        resp.headers["X-RateLimit-Remaining"] = "0"
        return resp

@app.after_request
def add_headers(response):
    response.headers["X-RateLimit-Limit"] = "60"
    return response

def get_conn():
    conn = sqlite3.connect(DB_PATH, timeout=20.0, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=5000;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn

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
            tx_ref TEXT NOT NULL,
            object_uuid TEXT NOT NULL,
            telemetry_payload TEXT NOT NULL,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP
        );
    """)
    
    cur.execute("""
        INSERT INTO documents (id, doc_uuid, title, owner_name, is_classified, file_content)
        VALUES (1, '7b1e4a90-3c21-4f88-9d10-8812a4f61e01', 'Employee_Onboarding_Handbook_2026.pdf', 'carlos', 0, 
        'CloudVault Standard Guidelines: Welcome to the enterprise team. All standard files are protected under default policies.');
    """)

    cur.execute("""
        INSERT INTO documents (id, doc_uuid, title, owner_name, is_classified, file_content)
        VALUES (2, '8f9b2c34-91a0-4d5e-88fc-3176d1e49e22', 'Executive_Q4_Classified_Financial_Audit.pdf', 'Chief Security Officer', 1, 
        'CONFIDENTIAL EXECUTIVE BRIEFING:\nMaster Encryption Key and Security Token: CTF{uu1d_l34k_d0cum3nt_v4ult}\nAuthorized clearance only.');
    """)

    carlos_meta = base64.b64encode(json.dumps({
        "doc_uuid": "7b1e4a90-3c21-4f88-9d10-8812a4f61e01",
        "actor": "carlos",
        "dept": "sec-ops-training",
        "tier": "public",
        "integrity_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }).encode("utf-8")).decode("utf-8")

    cso_meta = base64.b64encode(json.dumps({
        "doc_uuid": "8f9b2c34-91a0-4d5e-88fc-3176d1e49e22",
        "actor": "cso_executive",
        "dept": "executive-leadership",
        "tier": "top-secret-tier-1",
        "integrity_hash": "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0"
    }).encode("utf-8")).decode("utf-8")

    cur.execute("""
        INSERT INTO audit_activity (actor, action_desc, tx_ref, object_uuid, telemetry_payload)
        VALUES ('System Ingest Daemon', 'Synchronized public training documentation', 'TX-778901', '7b1e4a90-3c21-4f88-9d10-8812a4f61e01', ?);
    """, (carlos_meta,))

    cur.execute("""
        INSERT INTO audit_activity (actor, action_desc, tx_ref, object_uuid, telemetry_payload)
        VALUES ('Executive Vault Gateway', 'Archived Q4 classified executive audit report', 'TX-990142', '8f9b2c34-91a0-4d5e-88fc-3176d1e49e22', ?);
    """, (cso_meta,))

    conn.commit()
    conn.close()

if not os.path.exists(DB_PATH):
    init_db()

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
    activities = conn.execute("SELECT actor, action_desc, tx_ref, telemetry_payload, timestamp FROM audit_activity ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("activity.html", activities=activities)

@app.route("/api/public/audit-feed")
def api_audit_feed():
    conn = get_conn()
    activities = conn.execute("SELECT actor, action_desc, tx_ref, telemetry_payload, timestamp FROM audit_activity ORDER BY id DESC").fetchall()
    conn.close()
    return jsonify({
        "success": True,
        "feed": [
            {
                "timestamp": a[4],
                "actor": a[0],
                "action": a[1],
                "tx_ref": a[2],
                "telemetry_token": a[3]
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
    app.run(host="0.0.0.0", port=PORT, debug=False, threaded=True)
