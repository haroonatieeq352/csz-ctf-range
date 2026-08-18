#!/usr/bin/env python3
"""
CSZone CTF Range — Scenario 15: Advanced WAF & Filter Bypass XSS
Port: 8015
"""
import os
import sys
import re
from flask import Flask, request, render_template

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8015
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
app.secret_key = "scenario-15-secret-key"
FLAG_SECRET = "CTF{w4f_byp4ss_h5_v3ct0r}"

# Strict WAF signature blocklist
BLOCKED_PATTERNS = [
    (r"<\s*/?\s*script", "Script tag injection detected (<script>)"),
    (r"onerror\s*=", "Blocked event handler: onerror="),
    (r"onload\s*=", "Blocked event handler: onload="),
    (r"onclick\s*=", "Blocked event handler: onclick="),
    (r"onmouseover\s*=", "Blocked event handler: onmouseover="),
    (r"javascript\s*:", "Blocked pseudo-protocol: javascript:"),
    (r'"', "Double quotes are strictly disallowed in rule expressions")
]

def check_waf(payload):
    for pattern, reason in BLOCKED_PATTERNS:
        if re.search(pattern, payload, re.IGNORECASE):
            return reason
    return None

@app.route("/")
@app.route("/preview")
def preview_view():
    rule = request.args.get("rule", "")
    error = None

    if rule:
        error = check_waf(rule)

    return render_template("preview.html", rule=rule, error=error, flag_secret=FLAG_SECRET)

if __name__ == "__main__":
    print(f"[*] Scenario 15 running on http://localhost:{PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False)
