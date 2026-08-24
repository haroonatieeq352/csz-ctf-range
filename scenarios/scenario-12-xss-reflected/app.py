#!/usr/bin/env python3
"""
CSZone CTF Range — Scenario 12: Reflected XSS into HTML Context (Tag Breakout)
Port: 8012
Production-Ready: High-Concurrency WSGI (Gunicorn/Threaded) and Token/IP Rate Limiter.
"""
import os
import sys
import time
import threading
from collections import defaultdict
from flask import Flask, request, render_template, jsonify

try:
    PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8012
except (ValueError, IndexError):
    PORT = 8012
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
app.secret_key = "scenario-12-secret-key"

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

@app.before_request
def check_rate_limit():
    if request.path.startswith("/static/"):
        return None
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1").split(",")[0].strip()
    allowed, remaining, retry_after = rate_limiter.is_allowed(client_ip)
    if not allowed:
        resp = jsonify({
            "error": "Too Many Requests",
            "message": "DDoS Prevention: Rate limit exceeded (Max 60 requests/minute). Please slow down.",
            "retry_after_seconds": retry_after
        })
        resp.status_code = 429
        resp.headers["Retry-After"] = str(retry_after)
        resp.headers["X-RateLimit-Limit"] = "60"
        resp.headers["X-RateLimit-Remaining"] = "0"
        return resp

@app.after_request
def add_headers(response):
    response.headers["X-RateLimit-Limit"] = "60"
    return response

ADVISORIES = [
    {"cve": "CVE-2024-21413", "title": "Microsoft Outlook Remote Code Execution", "description": "Flaw in monikers handling allowing credential theft and NTLM leak."},
    {"cve": "CVE-2023-4863", "title": "WebP Heap Buffer Overflow", "description": "Heap-based buffer overflow in libwebp impacting major browsers."},
    {"cve": "CVE-2023-38606", "title": "Apple Kernel Memory Corruption", "description": "Privilege escalation vulnerability in kernel state machine."},
    {"cve": "CVE-2021-44228", "title": "Apache Log4j JNDI Remote Execution", "description": "Unauthenticated RCE through message lookup substitution parsing."}
]

FLAG_SECRET = "CTF{r3fl3ct3d_xss_b4s1cs}"

@app.route("/")
@app.route("/search")
def search_view():
    q = request.args.get("q", "")
    results = []
    if q:
        query_lower = q.lower()
        results = [a for a in ADVISORIES if query_lower in a["title"].lower() or query_lower in a["cve"].lower() or query_lower in a["description"].lower()]

    return render_template("search.html", q=q, raw_q=q, results=results)

@app.route("/api/flag")
def api_flag():
    return jsonify({"success": True, "flag": FLAG_SECRET})

if __name__ == "__main__":
    print(f"[*] Scenario 12 running on http://localhost:{PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False, threaded=True)
