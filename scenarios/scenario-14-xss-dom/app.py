#!/usr/bin/env python3
"""
CSZone CTF Range — Scenario 14: DOM-based XSS (Client-Side Source & Sink)
Port: 8014
"""
import os
import sys
from flask import Flask, render_template

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8014
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
app.secret_key = "scenario-14-secret-key"
FLAG_SECRET = "CTF{d0m_xss_s1nk_m4st3r}"

@app.route("/")
@app.route("/analytics")
def analytics_view():
    return render_template("analytics.html", flag_secret=FLAG_SECRET)

if __name__ == "__main__":
    print(f"[*] Scenario 14 running on http://localhost:{PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False)
