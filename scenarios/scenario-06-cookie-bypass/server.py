#!/usr/bin/env python3
"""
CSZone CTF Range — Scenario 06: Promo Crypto & Cookie Guard
Port: 8006
"""
import http.server
import http.client
from http import HTTPStatus
import socketserver
import sys
import os

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8006
SERVE_DIR = os.path.dirname(os.path.abspath(__file__))
BLOCKED_FILES = {"server.py", "README.md"}

class Scenario06Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=SERVE_DIR, **kwargs)

    def end_headers(self):
        clean_path = self.path.split("?")[0].rstrip("/")
        if clean_path in ("/secure", "/secure/index.html"):
            self.send_header("X-Auth-Hint", "YWNjZXNzX2xldmVsPWFkbWluLTlmM2E=")
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
    with socketserver.TCPServer(("0.0.0.0", PORT), Scenario06Handler) as httpd:
        print(f"[*] Scenario 06 running on http://localhost:{PORT}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[-] Shutting down Scenario 06.")
