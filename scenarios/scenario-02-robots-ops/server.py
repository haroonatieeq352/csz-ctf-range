#!/usr/bin/env python3
"""
CSZone CTF Range — Scenario 02: Robots & Archive Recon
Port: 8002
Production-Ready: Multi-Threaded TCP Server with Daemon Threads & Rate Limiter.
"""
import http.server
from http import HTTPStatus
import socketserver
import sys
import os
import time
import threading
from collections import defaultdict

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8002
SERVE_DIR = os.path.dirname(os.path.abspath(__file__))
BLOCKED_FILES = {"server.py", "README.md"}

class SlidingWindowRateLimiter:
    """Thread-safe Sliding Window Rate Limiter (60 req/min per IP/Token)."""
    def __init__(self, max_requests=60, window_seconds=60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(list)
        self.lock = threading.Lock()
        self._last_cleanup = time.time()

    def is_allowed(self, client_id):
        now = time.time()
        with self.lock:
            if now - self._last_cleanup > 60:
                cutoff = now - self.window_seconds
                stale = [k for k, v in self.requests.items() if not v or v[-1] < cutoff]
                for k in stale:
                    del self.requests[k]
                self._last_cleanup = now

            timestamps = self.requests[client_id]
            cutoff = now - self.window_seconds
            while timestamps and timestamps[0] < cutoff:
                timestamps.pop(0)

            if len(timestamps) < self.max_requests:
                timestamps.append(now)
                return True, self.max_requests - len(timestamps), 0
            else:
                retry_after = int(timestamps[0] + self.window_seconds - now) + 1
                return False, 0, max(1, retry_after)

rate_limiter = SlidingWindowRateLimiter(max_requests=60, window_seconds=60)

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
    timeout = 10

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
        self.send_header("X-RateLimit-Limit", "60")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        client_ip = self.headers.get("X-Forwarded-For", self.client_address[0]).split(",")[0].strip()
        allowed, remaining, retry_after = rate_limiter.is_allowed(client_ip)
        if not allowed:
            self.send_response(429, "Too Many Requests")
            self.send_header("Content-Type", "application/json")
            self.send_header("Retry-After", str(retry_after))
            self.send_header("X-RateLimit-Limit", "60")
            self.send_header("X-RateLimit-Remaining", "0")
            self.end_headers()
            body = b'{"error": "Too Many Requests", "message": "Rate limit exceeded (Max 60 req/min). Please slow down."}'
            self.wfile.write(body)
            return

        clean_path = self.path.split("?")[0].strip("/").lower()
        if clean_path in BLOCKED_FILES or any(clean_path.endswith("/" + b) for b in BLOCKED_FILES):
            self.send_error(HTTPStatus.FORBIDDEN, "Access Denied", "Direct access to server administrative assets is restricted.")
            return
        super().do_GET()

if __name__ == "__main__":
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    socketserver.ThreadingTCPServer.daemon_threads = True
    with socketserver.ThreadingTCPServer(("0.0.0.0", PORT), Scenario02Handler) as httpd:
        print(f"[*] Scenario 02 running on http://localhost:{PORT}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[-] Shutting down Scenario 02.")
