#!/usr/bin/env python3
"""
CSZone CTF Range — Scenario 19: RESTful HTTP Verb Tampering & Multi-Tenant IDOR
Port: 8019
Production-Ready: High-Concurrency WSGI (Gunicorn/Threaded), SQLite WAL, and Token/IP Rate Limiter.
"""
import os
import sys
import time
import sqlite3
import threading
from collections import defaultdict
from flask import Flask, request, session, redirect, url_for, render_template, jsonify

try:
    PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8019
except (ValueError, IndexError):
    PORT = 8019
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "scenario19.db")

app = Flask(__name__)
app.secret_key = "scenario-19-verb-tamper-secret-key"
FLAG_SECRET = "CTF{v3rb_t4mp3r1ng_t3n4nt_byp4ss}"

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
    cur.execute("DROP TABLE IF EXISTS workspaces;")
    cur.execute("""
        CREATE TABLE workspaces (
            tenant_id TEXT PRIMARY KEY,
            org_name TEXT NOT NULL,
            owner_email TEXT NOT NULL,
            tier_plan TEXT NOT NULL,
            region TEXT NOT NULL,
            compliance_mode TEXT DEFAULT 'standard',
            master_secret_key TEXT NOT NULL
        );
    """)
    cur.execute("""
        INSERT INTO workspaces (tenant_id, org_name, owner_email, tier_plan, region, compliance_mode, master_secret_key)
        VALUES ('tenant-12-carlos', 'Carlos Personal Workspace', 'carlos@nexatenant.io', 'Free Developer Tier', 'us-east-1', 'standard', 'sec_key_carlos_dev_99182');
    """)
    cur.execute("""
        INSERT INTO workspaces (tenant_id, org_name, owner_email, tier_plan, region, compliance_mode, master_secret_key)
        VALUES ('tenant-99-enterprise', 'Apex Financial Global Corp', 'director@apexfinancial.com', 'Tier 1 Enterprise Sovereign', 'eu-central-1', 'strict', 'CTF{v3rb_t4mp3r1ng_t3n4nt_byp4ss}');
    """)
    conn.commit()
    conn.close()

if not os.path.exists(DB_PATH):
    init_db()

@app.before_request
def ensure_session():
    if "my_tenant" not in session:
        session["my_tenant"] = "tenant-12-carlos"
        session["user_email"] = "carlos@nexatenant.io"

@app.route("/")
@app.route("/workspaces")
def workspaces_view():
    conn = get_conn()
    my_ws = conn.execute("SELECT tenant_id, org_name, owner_email, tier_plan, region, compliance_mode, master_secret_key FROM workspaces WHERE tenant_id = 'tenant-12-carlos'").fetchone()
    all_tenants = conn.execute("SELECT tenant_id, org_name, tier_plan, region FROM workspaces ORDER BY tenant_id ASC").fetchall()
    conn.close()
    is_solved = session.get("is_solved", False)
    return render_template("workspace.html", workspace=my_ws, tenants=all_tenants, is_solved=is_solved)

@app.route("/api/workspaces/<tenant_id>/settings", methods=["GET", "PUT", "PATCH", "POST"])
def api_workspace_settings(tenant_id):
    conn = get_conn()
    ws = conn.execute("SELECT tenant_id, org_name, owner_email, tier_plan, region, compliance_mode, master_secret_key FROM workspaces WHERE tenant_id = ?", (tenant_id,)).fetchone()
    
    if not ws:
        conn.close()
        return jsonify({"success": False, "error": f"Tenant '{tenant_id}' not found"}), 404

    if request.method == "GET":
        my_tenant = session.get("my_tenant", "tenant-12-carlos")
        if tenant_id != my_tenant:
            conn.close()
            return jsonify({
                "success": False,
                "error": "403 Forbidden: Cross-tenant read access is strictly denied by the API Gateway Security Filter."
            }), 403

        conn.close()
        return jsonify({
            "success": True,
            "tenant": {
                "tenant_id": ws[0],
                "org_name": ws[1],
                "owner_email": ws[2],
                "tier_plan": ws[3],
                "region": ws[4],
                "compliance_mode": ws[5],
                "master_secret_key": ws[6]
            }
        })

    if request.method in ["PUT", "PATCH"]:
        data = request.get_json(force=True, silent=True) or request.form.to_dict() or {}
        new_region = data.get("region", ws[4])
        new_compliance = data.get("compliance_mode", ws[5])
        
        conn.execute("""
            UPDATE workspaces 
            SET region = ?, compliance_mode = ? 
            WHERE tenant_id = ?
        """, (new_region, new_compliance, tenant_id))
        conn.commit()

        if tenant_id == "tenant-99-enterprise":
            session["is_solved"] = True

        updated = conn.execute("SELECT tenant_id, org_name, owner_email, tier_plan, region, compliance_mode, master_secret_key FROM workspaces WHERE tenant_id = ?", (tenant_id,)).fetchone()
        conn.close()

        return jsonify({
            "success": True,
            "message": f"Workspace settings for '{tenant_id}' modified successfully via HTTP {request.method}.",
            "tenant": {
                "tenant_id": updated[0],
                "org_name": updated[1],
                "owner_email": updated[2],
                "tier_plan": updated[3],
                "region": updated[4],
                "compliance_mode": updated[5],
                "master_secret_key": updated[6]
            }
        })

    conn.close()
    return jsonify({"success": False, "error": f"Method {request.method} not allowed"}), 405

@app.route("/api/flag")
def api_flag():
    return jsonify({"success": True, "flag": FLAG_SECRET})

@app.route("/reset", methods=["GET", "POST"])
@app.route("/api/reset", methods=["GET", "POST"])
def reset_view():
    init_db()
    return redirect(url_for("workspaces_view"))

if __name__ == "__main__":
    init_db()
    print(f"[*] Scenario 19 running on http://localhost:{PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False, threaded=True)
