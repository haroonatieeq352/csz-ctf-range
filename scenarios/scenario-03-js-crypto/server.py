#!/usr/bin/env python3
"""
CSZone CTF Range — Scenario 03: JS & Crypto Obfuscation
Port: 8003
"""
import http.server
import http.client
from http import HTTPStatus
import socketserver
import sys
import os

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8003
SERVE_DIR = os.path.dirname(os.path.abspath(__file__))
BLOCKED_FILES = {"server.py", "README.md"}

class Scenario03Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=SERVE_DIR, **kwargs)

    def do_GET(self):
        clean_path = self.path.split("?")[0].strip("/").lower()
        if clean_path in BLOCKED_FILES or any(clean_path.endswith("/" + b) for b in BLOCKED_FILES):
            self.send_error(HTTPStatus.FORBIDDEN, "Access Denied")
            return
        super().do_GET()

if __name__ == "__main__":
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("0.0.0.0", PORT), Scenario03Handler) as httpd:
        print(f"[*] Scenario 03 running on http://localhost:{PORT}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[-] Shutting down Scenario 03.")
