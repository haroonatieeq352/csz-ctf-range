#!/usr/bin/env python3
"""
CSZone CTF Range — Central Operations Hub Server
Port: 8000
"""
import http.server
import socketserver
import sys
import os

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
SERVE_DIR = os.path.dirname(os.path.abspath(__file__))

class CentralHubHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=SERVE_DIR, **kwargs)

if __name__ == "__main__":
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("0.0.0.0", PORT), CentralHubHandler) as httpd:
        print(f"[*] CSZone Central Operations Hub active on http://localhost:{PORT} (http://127.0.0.1:{PORT})")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[-] Shutting down Central Hub.")
