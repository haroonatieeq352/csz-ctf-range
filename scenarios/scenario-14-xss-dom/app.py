#!/usr/bin/env python3
"""
CSZone CTF Range — Scenario 14: DOM-based XSS (Client-Side Source & Sink)
Port: 8014
"""
import os
import sys
from flask import Flask, request, render_template

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8014
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
app.secret_key = "scenario-14-secret-key"
FLAG_SECRET = "CTF{d0m_xss_s1nk_m4st3r}"

POSTS = [
    {
        "id": 1,
        "title": "Mitigating DOM-based Vulnerabilities in Modern Frontend Frameworks",
        "date": "May 18, 2024",
        "summary": "An in-depth analysis of client-side execution sinks including innerHTML, document.write, and eval in Single Page Applications."
    },
    {
        "id": 2,
        "title": "Deep Dive: Content Security Policy (CSP) Level 3 Implementation",
        "date": "April 29, 2024",
        "summary": "Exploring strict-dynamic, nonce-based script whitelisting, and defending against unsafe DOM manipulation vectors."
    },
    {
        "id": 3,
        "title": "Zero-Day Triage in Corporate VPN Gateways",
        "date": "March 12, 2024",
        "summary": "Reverse engineering state-sponsored exploit chains targeting unauthenticated remote command execution."
    }
]

@app.route("/")
@app.route("/analytics")
def index_view():
    search = request.args.get("search", "") or request.args.get("tab", "")
    posts = POSTS
    if search:
        s_lower = search.lower()
        posts = [p for p in POSTS if s_lower in p["title"].lower() or s_lower in p["summary"].lower()]
    return render_template("analytics.html", posts=posts, search=search)

@app.route("/api/flag")
@app.route("/api/telemetry/vault")
def api_flag():
    return {"success": True, "flag": FLAG_SECRET}

if __name__ == "__main__":
    print(f"[*] Scenario 14 running on http://localhost:{PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False)
