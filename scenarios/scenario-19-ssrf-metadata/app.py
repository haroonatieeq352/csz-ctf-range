#!/usr/bin/env python3
"""
CSZone CTF Range — Scenario 19: RESTful HTTP Verb Tampering & Multi-Tenant IDOR
Port: 8019
"""
import os
import sys
import sqlite3
from flask import Flask, request, session, redirect, url_for, render_template, jsonify

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8019
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "scenario19.db")

app = Flask(__name__)
app.secret_key = "scenario-19-verb-tamper-secret-key"
FLAG_SECRET = "CTF{v3rb_t4mp3r1ng_t3n4nt_byp4ss}"

def get_conn():
    return sqlite3.connect(DB_PATH)

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
    # Tenant 1: Carlos (User's workspace)
    cur.execute("""
        INSERT INTO workspaces (tenant_id, org_name, owner_email, tier_plan, region, compliance_mode, master_secret_key)
        VALUES ('tenant-12-carlos', 'Carlos Personal Workspace', 'carlos@nexatenant.io', 'Free Developer Tier', 'us-east-1', 'standard', 'sec_key_carlos_dev_99182');
    """)
    # Tenant 2: Target Enterprise Tenant
    cur.execute("""
        INSERT INTO workspaces (tenant_id, org_name, owner_email, tier_plan, region, compliance_mode, master_secret_key)
        VALUES ('tenant-99-enterprise', 'Apex Financial Global Corp', 'director@apexfinancial.com', 'Tier 1 Enterprise Sovereign', 'eu-central-1', 'strict', 'CTF{v3rb_t4mp3r1ng_t3n4nt_byp4ss}');
    """)
    conn.commit()
    conn.close()

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
    return render_template("workspace.html", workspace=my_ws, tenants=all_tenants)

# RESTful Multi-Tenant API Route
@app.route("/api/workspaces/<tenant_id>/settings", methods=["GET", "PUT", "PATCH", "POST"])
def api_workspace_settings(tenant_id):
    conn = get_conn()
    ws = conn.execute("SELECT tenant_id, org_name, owner_email, tier_plan, region, compliance_mode, master_secret_key FROM workspaces WHERE tenant_id = ?", (tenant_id,)).fetchone()
    
    if not ws:
        conn.close()
        return jsonify({"success": False, "error": f"Tenant '{tenant_id}' not found"}), 404

    # GET REQUEST: Strictly checks cross-tenant authorization
    if request.method == "GET":
        my_tenant = session.get("my_tenant", "tenant-12-carlos")
        if tenant_id != my_tenant:
            conn.close()
            # 403 Forbidden on GET!
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

    # VULNERABILITY (HTTP Verb Tampering / BOLA):
    # Developers forgot to bind the cross-tenant ownership check to PUT / PATCH methods!
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

        updated = conn.execute("SELECT tenant_id, org_name, owner_email, tier_plan, region, compliance_mode, master_secret_key FROM workspaces WHERE tenant_id = ?", (tenant_id,)).fetchone()
        conn.close()

        # Returns updated object including master_secret_key (disclosing the CTF flag for target tenant)
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
    app.run(host="0.0.0.0", port=PORT, debug=False)
