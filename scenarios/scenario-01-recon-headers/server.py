#!/usr/bin/env python3
"""
CSZone CTF Range — Scenario 01: Recon & HTTP Headers
Port: 8001
"""
import http.server
import http.client
from http import HTTPStatus
import socketserver
import sys
import os

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8001
SERVE_DIR = os.path.dirname(os.path.abspath(__file__))

BLOCKED_FILES = {"server.py", "README.md"}

class Scenario01Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=SERVE_DIR, **kwargs)

    def end_headers(self):
        self.send_header("X-Powered-By", "CSZone-TrainingRange/0.9.3")
        self.send_header("X-Build-Env", "staging")
        self.send_header("X-Debug-Info", "CTF{h34d3r_hunt3r_pr0}")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def do_GET(self):
        clean_path = self.path.split("?")[0].strip("/").lower()
        if clean_path in BLOCKED_FILES or any(clean_path.endswith("/" + b) for b in BLOCKED_FILES):
            self.send_error(HTTPStatus.FORBIDDEN, "Access Denied")
            return
        super().do_GET()

if __name__ == "__main__":
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("0.0.0.0", PORT), Scenario01Handler) as httpd:
        print(f"[*] Scenario 01 running on http://localhost:{PORT}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[-] Shutting down Scenario 01.")
