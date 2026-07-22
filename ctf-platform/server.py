#!/usr/bin/env python3
"""
CSZone CTF Range - Secure Dev Server

Security features:
  - Directory listing DISABLED (returns 403)
  - Sensitive admin files BLOCKED from public access
  - CTF debug headers injected (Scenario 1)

Usage:
    python server.py
    python server.py 8080
"""

import http.server
import socketserver
import sys
import os

# Fix Windows console encoding
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PORT     = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
SERVE_DIR = os.path.dirname(os.path.abspath(__file__))

# ── Files that are NEVER served to participants ──────────────────────────────
# These live in the web root but must stay hidden from all HTTP requests.
BLOCKED_FILES = {
    "solutions-internal.md",   # Admin answer sheet — must NEVER be public
    "server.py",               # Server source code
    "bruteforce.py",           # Admin helper tool
    ".htaccess",               # Apache config (contains header flag hint)
    "_headers",                # Netlify config (contains header flag hint)
    "vercel.json",             # Vercel config (contains header flag hint)
    "wordlist.txt",            # Distributed separately — trivializes H2 if left public
    "passwords.txt",           # Password-cracking wordlist — distributed separately only
}


class CTFHandler(http.server.SimpleHTTPRequestHandler):
    """
    Custom handler that:
      1. Blocks directory listing everywhere.
      2. Blocks access to sensitive admin files.
      3. Injects CTF response headers (Scenario 1 flag).
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=SERVE_DIR, **kwargs)

    # ── Scenario 1: inject debug headers on EVERY response ──────────────────
    def end_headers(self):
        self.send_header("X-Powered-By",           "CSZone-TrainingRange/0.9.3")
        self.send_header("X-Build-Env",            "staging")
        self.send_header("X-Debug-Info",           "CTF{h34d3r_hunt3r_pr0}")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options",        "DENY")
        self.send_header("Cache-Control",          "no-store")
        super().end_headers()

    # ── Sensitive file guard (GET) ───────────────────────────────────────────
    def do_GET(self):
        if self._is_blocked():
            self._send_403("Access to this resource is restricted.")
            return
        super().do_GET()

    # ── Sensitive file guard (HEAD / curl -I) ───────────────────────────────
    def do_HEAD(self):
        if self._is_blocked():
            self._send_403("Access to this resource is restricted.")
            return
        super().do_HEAD()

    # ── Disable directory listing everywhere ────────────────────────────────
    def list_directory(self, path):
        """
        Called only when a directory has NO index.html.
        We always return 403 instead of showing the file list.
        """
        self._send_403("Directory listing is disabled on this server.")
        return None

    # ── Helpers ─────────────────────────────────────────────────────────────
    def _is_blocked(self):
        """Return True if the requested file is on the admin blocklist."""
        filename = os.path.basename(self.path.split("?")[0]).lower()
        return filename in BLOCKED_FILES

    def _send_403(self, message="Forbidden"):
        body = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>403 Forbidden</title>
  <style>
    body {{ font-family: monospace; background: #0d0d0d; color: #c0392b;
            display: flex; align-items: center; justify-content: center;
            height: 100vh; margin: 0; }}
    .box {{ text-align: center; border: 1px solid #c0392b; padding: 2rem 3rem; }}
    p {{ color: #aaa; font-size: 0.9rem; }}
  </style>
</head>
<body>
  <div class="box">
    <h1>403 &mdash; Forbidden</h1>
    <p>{message}</p>
  </div>
</body>
</html>""".encode("utf-8")

        self.send_response(403)
        self.send_header("Content-Type",   "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print(f"[REQ] {self.address_string()} -> {fmt % args}")


# ── Entry point ─────────────────────────────────────────────────────────────
def main():
    os.chdir(SERVE_DIR)

    # Allow port reuse so restarting the server doesn't fail
    socketserver.TCPServer.allow_reuse_address = True

    with socketserver.TCPServer(("", PORT), CTFHandler) as httpd:
        print(f"\n  CSZone CTF Range - Secure Dev Server")
        print(f"  ----------------------------------------")
        print(f"  URL     : http://localhost:{PORT}")
        print(f"  Root    : {SERVE_DIR}")
        print(f"  Dir listing : DISABLED (403)")
        print(f"  Blocked     : {', '.join(sorted(BLOCKED_FILES))}")
        print(f"  ----------------------------------------")
        print(f"  Press Ctrl+C to stop.\n")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n  Server stopped.")


if __name__ == "__main__":
    main()

