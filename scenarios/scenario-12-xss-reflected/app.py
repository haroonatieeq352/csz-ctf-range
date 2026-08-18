#!/usr/bin/env python3
"""
CSZone CTF Range — Scenario 12: Reflected XSS into HTML Context
Port: 8012
"""
import os
import sys
from flask import Flask, request, render_template

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8012
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
app.secret_key = "scenario-12-secret-key"

ADVISORIES = [
    {"cve": "CVE-2024-21413", "title": "Microsoft Outlook Remote Code Execution", "description": "Flaw in monikers handling allowing credential theft and NTLM leak."},
    {"cve": "CVE-2023-4863", "title": "WebP Heap Buffer Overflow", "description": "Heap-based buffer overflow in libwebp impacting major browsers."},
    {"cve": "CVE-2023-38606", "title": "Apple Kernel Memory Corruption", "description": "Privilege escalation vulnerability in kernel state machine."},
    {"cve": "CVE-2021-44228", "title": "Apache Log4j JNDI Remote Execution", "description": "Unauthenticated RCE through message lookup substitution parsing."}
]

FLAG_SECRET = "CTF{r3fl3ct3d_xss_b4s1cs}"

@app.route("/")
@app.route("/search")
def search_view():
    q = request.args.get("q", "")
    results = []
    if q:
        query_lower = q.lower()
        results = [a for a in ADVISORIES if query_lower in a["title"].lower() or query_lower in a["cve"].lower() or query_lower in a["description"].lower()]

    # VULN: 'q' is passed unescaped to template and marked |safe in search.html
    return render_template("search.html", q=q, results=results, flag_token=FLAG_SECRET)

if __name__ == "__main__":
    print(f"[*] Scenario 12 running on http://localhost:{PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False)
