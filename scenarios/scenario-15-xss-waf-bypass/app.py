#!/usr/bin/env python3
"""
CSZone CTF Range — Scenario 15: Advanced WAF & Filter Bypass XSS
Port: 8015
Production-Ready: High-Concurrency WSGI (Gunicorn/Threaded) and Token/IP Rate Limiter.
"""
import os
import sys
import re
import time
import threading
from collections import defaultdict
from flask import Flask, request, render_template, jsonify

try:
    PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8015
except (ValueError, IndexError):
    PORT = 8015
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
app.secret_key = "scenario-15-secret-key"
FLAG_SECRET = "CTF{w4f_byp4ss_h5_v3ct0r}"

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

BLOCKED_PATTERNS = [
    (r"<\s*/?\s*script", "Script tag injection detected (<script>)"),
    (r"onerror\s*=", "Blocked event handler: onerror="),
    (r"onload\s*=", "Blocked event handler: onload="),
    (r"onclick\s*=", "Blocked event handler: onclick="),
    (r"onmouseover\s*=", "Blocked event handler: onmouseover="),
    (r"javascript\s*:", "Blocked pseudo-protocol: javascript:"),
    (r'"', "Double quotes are strictly disallowed in rule expressions")
]

def check_waf(payload):
    for pattern, reason in BLOCKED_PATTERNS:
        if re.search(pattern, payload, re.IGNORECASE):
            return reason
    return None

@app.route("/")
@app.route("/preview")
def preview_view():
    rule = request.args.get("rule", "")
    error = None

    if rule:
        error = check_waf(rule)

    return render_template("preview.html", rule=rule, error=error)

@app.route("/api/flag")
def api_flag():
    return jsonify({"success": True, "flag": FLAG_SECRET})

if __name__ == "__main__":
    print(f"[*] Scenario 15 running on http://localhost:{PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False, threaded=True)
