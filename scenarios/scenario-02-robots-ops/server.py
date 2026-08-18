#!/usr/bin/env python3
"""
CSZone CTF Range — Scenario 02: Robots & Archive Recon
Port: 8002
"""
import http.server
from http import HTTPStatus
import socketserver
import sys
import os

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8002
SERVE_DIR = os.path.dirname(os.path.abspath(__file__))
BLOCKED_FILES = {"server.py", "README.md"}

ERROR_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>{code} {message} — CSZone Range</title>
  <link rel="stylesheet" href="/style.css">
</head>
<body>
  <header>
    <h1>CSZone CTF — Scenario 02</h1>
    <span class="tag">Robots & Hidden Directories &bull; Port 8002</span>
  </header>
  <main>
    <div class="card" style="border-left: 4px solid var(--crimson);">
      <span class="badge hard">{code} ERROR</span>
      <h2>{message}</h2>
      <p>{explain}</p>
      <div style="margin-top: 20px;">
        <a href="/" style="color: var(--amber); text-decoration: none; font-size: 0.9rem;">&larr; Back to Scenario 02 Home</a>
      </div>
    </div>
  </main>
  <footer>CSZone Pvt. Limited &mdash; Internal Training Range</footer>
</body>
</html>
"""

class Scenario02Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=SERVE_DIR, **kwargs)

    def send_error(self, code, message=None, explain=None):
        self.log_error("code %d, message %s", code, message)
        if message is None:
            message = HTTPStatus(code).phrase
        if explain is None:
            explain = HTTPStatus(code).description

        body = ERROR_TEMPLATE.format(code=code, message=message, explain=explain).encode("utf-8", "replace")
        self.send_response(code, message)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        clean_path = self.path.split("?")[0].strip("/").lower()
        if clean_path in BLOCKED_FILES or any(clean_path.endswith("/" + b) for b in BLOCKED_FILES):
            self.send_error(HTTPStatus.FORBIDDEN, "Access Denied", "Direct access to server administrative assets is restricted.")
            return
        super().do_GET()

if __name__ == "__main__":
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("0.0.0.0", PORT), Scenario02Handler) as httpd:
        print(f"[*] Scenario 02 running on http://localhost:{PORT}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[-] Shutting down Scenario 02.")
