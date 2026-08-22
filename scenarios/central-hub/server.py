#!/usr/bin/env python3
"""
CSZone CTF Range — Central Operations Hub Server
Port: 8000
Production-Ready: Multi-Threaded TCP Server with Daemon Threads & Rate Limiter.
"""
import http.server
import socketserver
import sys
import os
import time
import threading
from collections import defaultdict

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
SERVE_DIR = os.path.dirname(os.path.abspath(__file__))

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

class CentralHubHandler(http.server.SimpleHTTPRequestHandler):
    timeout = 10

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=SERVE_DIR, **kwargs)

    def do_GET(self):
        clean_path = self.path.split("?")[0].lower()
        is_static = clean_path.endswith((".css", ".js", ".png", ".jpg", ".jpeg", ".svg", ".ico", ".woff", ".woff2"))
        
        if not is_static:
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
        super().do_GET()

    def end_headers(self):
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("X-RateLimit-Limit", "60")
        super().end_headers()

if __name__ == "__main__":
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    socketserver.ThreadingTCPServer.daemon_threads = True
    with socketserver.ThreadingTCPServer(("0.0.0.0", PORT), CentralHubHandler) as httpd:
        print(f"[*] Central Operations Hub running on http://localhost:{PORT}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[-] Shutting down Central Hub.")
