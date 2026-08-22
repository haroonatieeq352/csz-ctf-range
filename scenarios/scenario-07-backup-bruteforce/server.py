#!/usr/bin/env python3
"""
CSZone CTF Range — Scenario 07: Backup Service Auth & Intruder Brute-Force
Port: 8007
Production-Ready: Multi-Threaded TCP Server with Daemon Threads & Rate Limiter.
"""
import http.server
import http.client
from http import HTTPStatus
import socketserver
import sys
import os
import time
import hashlib
import urllib.parse
import threading
from collections import defaultdict

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8007
SERVE_DIR = os.path.dirname(os.path.abspath(__file__))
BLOCKED_FILES = {"server.py", "README.md"}

class SlidingWindowRateLimiter:
    """Thread-safe Sliding Window Rate Limiter (120 req/min for Brute-Force lab, burst protection)."""
    def __init__(self, max_requests=120, window_seconds=60):
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

rate_limiter = SlidingWindowRateLimiter(max_requests=120, window_seconds=60)

class Scenario07Handler(http.server.SimpleHTTPRequestHandler):
    timeout = 10

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=SERVE_DIR, **kwargs)

    def parse_request(self):
        self.command = None
        self.request_version = version = self.default_request_version
        self.close_connection = True
        requestline = str(self.raw_requestline, 'iso-8859-1').rstrip('\r\n')
        self.requestline = requestline
        words = requestline.split()
        if len(words) == 0:
            return False
        if len(words) >= 3 and words[-1].startswith("HTTP/"):
            command = words[0]
            version = words[-1]
            path = " ".join(words[1:-1])
        elif len(words) == 2:
            command, path = words
            version = "HTTP/0.9"
        elif len(words) == 1:
            command = words[0]
            path = ""
            version = "HTTP/0.9"
        else:
            self.send_error(HTTPStatus.BAD_REQUEST, f"Bad syntax: {requestline!r}")
            return False
        self.command, self.path, self.request_version = command, path, version
        self.headers = http.client.parse_headers(self.rfile, _class=self.MessageClass)
        return True

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-RateLimit-Limit", "120")
        super().end_headers()

    def _extract_credentials(self, query_dict):
        user = query_dict.get("username", query_dict.get("user", query_dict.get("u", ["svc_backup"])))[0].strip()
        pw = None
        for key in ("password", "pass", "pw", "p"):
            if key in query_dict:
                pw = query_dict[key][0]
                break
        return user, pw

    def do_GET(self):
        client_ip = self.headers.get("X-Forwarded-For", self.client_address[0]).split(",")[0].strip()
        allowed, remaining, retry_after = rate_limiter.is_allowed(client_ip)
        if not allowed:
            self.send_response(429, "Too Many Requests")
            self.send_header("Content-Type", "application/json")
            self.send_header("Retry-After", str(retry_after))
            self.send_header("X-RateLimit-Limit", "120")
            self.send_header("X-RateLimit-Remaining", "0")
            self.end_headers()
            body = b'{"error": "Too Many Requests", "message": "Rate limit exceeded. Please slow down."}'
            self.wfile.write(body)
            return

        clean_path = self.path.split("?")[0].strip("/").lower()
        if clean_path in BLOCKED_FILES or any(clean_path.endswith("/" + b) for b in BLOCKED_FILES):
            self.send_error(HTTPStatus.FORBIDDEN, "Access Denied")
            return

        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        user, pw = self._extract_credentials(params)
        if pw is not None:
            self._handle_backup_auth(user or "svc_backup", pw)
            return

        super().do_GET()

    def do_POST(self):
        client_ip = self.headers.get("X-Forwarded-For", self.client_address[0]).split(",")[0].strip()
        allowed, remaining, retry_after = rate_limiter.is_allowed(client_ip)
        if not allowed:
            self.send_response(429, "Too Many Requests")
            self.send_header("Content-Type", "application/json")
            self.send_header("Retry-After", str(retry_after))
            self.send_header("X-RateLimit-Limit", "120")
            self.send_header("X-RateLimit-Remaining", "0")
            self.end_headers()
            body = b'{"error": "Too Many Requests", "message": "Rate limit exceeded. Please slow down."}'
            self.wfile.write(body)
            return

        clean_path = self.path.split("?")[0].strip("/").lower()
        if clean_path in BLOCKED_FILES:
            self.send_error(HTTPStatus.FORBIDDEN, "Access Denied")
            return

        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length).decode("utf-8", errors="replace")
        params = urllib.parse.parse_qs(post_data)

        user, pw = self._extract_credentials(params)
        if pw is not None:
            self._handle_backup_auth(user or "svc_backup", pw)
            return

        self.send_error(HTTPStatus.BAD_REQUEST, "Missing credentials")

    def _handle_backup_auth(self, user, pw):
        salt = "9c1f7a"
        target_hash = "5269a48d5eb030eee36c71eaa9edbfec94b52cb042ad98cad03bf8e7be20f723"
        target_user = "svc_backup"
        flag_b64    = "Q1RGe2g0c2hfY3I0Y2szZF80Y2Mzc3N9"

        computed = hashlib.sha256((salt + pw).encode("utf-8")).hexdigest()
        is_valid = (user.lower() == target_user and computed == target_hash)

        login_file = os.path.join(SERVE_DIR, "backup", "login.html")
        try:
            with open(login_file, "r", encoding="utf-8") as f:
                html = f.read()
        except Exception:
            html = "<html><body><h1>Backup Portal</h1><div id='result' class='flag-box hidden'></div></body></html>"

        if is_valid:
            result_html = f'''<div id="result" class="flag-box success" style="display:block;">
  <strong style="color:#2ecc71; font-size:1.1rem;">[+] Authentication Successful!</strong><br><br>
  Service Session Granted: <code>svc_backup@backup-node-01</code><br>
  <strong>Encrypted Flag Token (Base64):</strong> <code>{flag_b64}</code><br><br>
  <span style="font-size:0.85rem; color:#aaa;">Decode the Base64 token above (e.g. using Burp Suite Decoder) to extract the flag.</span><br>
  <div class="next-step-hint" style="margin-top:10px; color:#d99a3d;"><strong>[!] Important:</strong> Keep this recovered password (<code>Summer2024!</code>) safe &mdash; Scenario 8 (/finale/) requires it!</div>
</div>'''
            status_code = 200
            auth_status = "SUCCESS"
        else:
            result_html = f'''<div id="result" class="flag-box error" style="display:block;">
  <strong style="color:#e0778a;">[-] Authentication Failed:</strong> Invalid service credentials for <code>{user}</code>.<br>
  <span style="font-size:0.85rem; color:#aaa;">Hash mismatch with registered service salt [{salt}].</span>
</div>'''
            status_code = 401
            auth_status = "FAILED"

        html = html.replace('name="username" type="text" placeholder="e.g. svc_backup"', f'name="username" type="text" value="{user}"')
        html = html.replace('<div id="result" class="flag-box hidden"></div>', result_html)
        
        body = html.encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Auth-Status", auth_status)
        self.end_headers()
        self.wfile.write(body)

if __name__ == "__main__":
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    socketserver.ThreadingTCPServer.daemon_threads = True
    with socketserver.ThreadingTCPServer(("0.0.0.0", PORT), Scenario07Handler) as httpd:
        print(f"[*] Scenario 07 running on http://localhost:{PORT}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[-] Shutting down Scenario 07.")
