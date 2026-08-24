#!/usr/bin/env python3
"""
CSZone CTF Range — Scenario 14: DOM-based XSS (Client-Side Source & Sink)
Port: 8014
Production-Ready: High-Concurrency WSGI (Gunicorn/Threaded) and Token/IP Rate Limiter.
"""
import os
import sys
import time
import threading
from collections import defaultdict
from flask import Flask, request, render_template, jsonify

try:
    PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8014
except (ValueError, IndexError):
    PORT = 8014
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
app.secret_key = "scenario-14-secret-key"
FLAG_SECRET = "CTF{d0m_xss_s1nk_m4st3r}"

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

POSTS = [
    {
        "id": 1,
        "title": "Mitigating DOM-based Vulnerabilities in Modern Frontend Frameworks",
        "date": "May 18, 2024",
        "summary": "An in-depth analysis of client-side execution sinks including innerHTML, document.write, and eval in Single Page Applications."
    },
    {
        "id": 2,
        "title": "Deep Dive: Content Security Policy (CSP) Level 3 Implementation",
        "date": "April 29, 2024",
        "summary": "Exploring strict-dynamic, nonce-based script whitelisting, and defending against unsafe DOM manipulation vectors."
    },
    {
        "id": 3,
        "title": "Zero-Day Triage in Corporate VPN Gateways",
        "date": "March 12, 2024",
        "summary": "Reverse engineering state-sponsored exploit chains targeting unauthenticated remote command execution."
    }
]

@app.route("/")
@app.route("/analytics")
def index_view():
    search = request.args.get("search", "") or request.args.get("tab", "")
    posts = POSTS
    if search:
        s_lower = search.lower()
        posts = [p for p in POSTS if s_lower in p["title"].lower() or s_lower in p["summary"].lower()]
    return render_template("analytics.html", posts=posts, search=search)

@app.route("/api/flag")
@app.route("/api/telemetry/vault")
def api_flag():
    return jsonify({"success": True, "flag": FLAG_SECRET})

if __name__ == "__main__":
    print(f"[*] Scenario 14 running on http://localhost:{PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False, threaded=True)
