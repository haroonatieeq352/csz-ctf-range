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
import http.client
from http import HTTPStatus
import socketserver
import sys
import os
import hashlib
import urllib.parse
import urllib.request
import base64

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
      1. Blocks sensitive administrative files.
      2. Disables directory listing across all paths.
      3. Injects CTF response headers (Scenario 1 flag).
      4. Evaluates Scenario 7 credentials server-side for Burp Suite Intruder.
      5. Supports unencoded spaces & quotes in URLs from Burp Suite Repeater.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=SERVE_DIR, **kwargs)

    def parse_request(self):
        """
        Overrides default parse_request to allow raw, unencoded spaces/quotes
        directly in the HTTP request line sent by Burp Suite Repeater.
        """
        self.command = None
        self.request_version = version = self.default_request_version
        self.close_connection = True
        requestline = str(self.raw_requestline, 'iso-8859-1')
        requestline = requestline.rstrip('\r\n')
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
            self.send_error(HTTPStatus.BAD_REQUEST, "Bad request syntax (%r)" % requestline)
            return False

        self.command, self.path, self.request_version = command, path, version

        # Parse headers
        self.headers = http.client.parse_headers(self.rfile, _class=self.MessageClass)
        return True

    # ── Scenario 1: inject debug headers on HTML responses ──────────────────
    # ── Scenario 6: inject session hint header on /secure/ responses ─────────
    def end_headers(self):
        self.send_header("X-Powered-By",           "CSZone-TrainingRange/0.9.3")
        self.send_header("X-Build-Env",            "staging")
        path = getattr(self, "path", "")
        clean_path = path.split("?")[0].rstrip("/") if path else ""
        if clean_path in ("", "/index.html") or clean_path.endswith(".html"):
            self.send_header("X-Debug-Info",       "CTF{h34d3r_hunt3r_pr0}")
        # Scenario 6: session hint header — only on /secure/ path
        if clean_path in ("/secure", "/secure/index.html"):
            self.send_header("X-Auth-Hint",        "YWNjZXNzX2xldmVsPWFkbWluLTlmM2E=")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options",        "DENY")
        self.send_header("Cache-Control",          "no-store")
        super().end_headers()

    # ── Sensitive file guard & Dynamic Routing (GET) ─────────────────────────
    def do_GET(self):
        if self._is_blocked():
            self._send_403("Access to this resource is restricted.")
            return

        parsed = urllib.parse.urlparse(self.path)
        clean_path = parsed.path.rstrip("/")

        # Scenario 7: Dynamic Authentication for Burp Suite Intruder / Browsers
        if clean_path in ("/backup/login.html", "/backup/login"):
            params = urllib.parse.parse_qs(parsed.query)
            if "username" in params and "password" in params:
                user = params["username"][0].strip()
                pw = params["password"][0]
                self._handle_backup_auth(user, pw)
                return

        # Scenario 8: Chained Verification for Burp Repeater / Browsers
        if clean_path in ("/finale", "/finale/index.html"):
            params = urllib.parse.parse_qs(parsed.query)
            key_param = params.get("key", [""])[0]
            cookie_header = self.headers.get("Cookie", "")
            self._handle_finale_auth(cookie_header, key_param)
            return

        # Backend Scenarios (Proxy to port 5000 so everything works on one URL/ngrok)
        BACKEND_ROUTES = (
            "/products", "/directory", "/guestbook", "/orders", "/upload",
            "/avatar-import", "/promo", "/legacy-admin", "/admin", "/account",
            "/login", "/register", "/logout", "/xss", "/internal", "/static"
        )
        if any(clean_path == r or clean_path.startswith(r + "/") for r in BACKEND_ROUTES):
            self._proxy_to_backend(method="GET")
            return

        super().do_GET()

    # ── Sensitive file guard & Dynamic Routing (POST) ────────────────────────
    def do_POST(self):
        if self._is_blocked():
            self._send_403("Access to this resource is restricted.")
            return

        parsed = urllib.parse.urlparse(self.path)
        clean_path = parsed.path.rstrip("/")

        # Scenario 7: POST support for Burp Intruder / API tests
        if clean_path in ("/backup/login.html", "/backup/login"):
            content_length = int(self.headers.get("Content-Length", 0))
            post_data = self.rfile.read(content_length).decode("utf-8", errors="replace")
            params = urllib.parse.parse_qs(post_data)
            user = params.get("username", [""])[0].strip()
            pw = params.get("password", [""])[0]
            self._handle_backup_auth(user, pw)
            return

        # Scenario 8: POST support for Finale
        if clean_path in ("/finale", "/finale/index.html"):
            content_length = int(self.headers.get("Content-Length", 0))
            post_data = self.rfile.read(content_length).decode("utf-8", errors="replace")
            params = urllib.parse.parse_qs(post_data)
            key_param = params.get("key", [""])[0]
            cookie_header = self.headers.get("Cookie", "")
            self._handle_finale_auth(cookie_header, key_param)
            return

        # Backend Scenarios POST (Proxy to port 5000)
        BACKEND_ROUTES = (
            "/products", "/directory", "/guestbook", "/orders", "/upload",
            "/avatar-import", "/promo", "/legacy-admin", "/admin", "/account",
            "/login", "/register", "/logout", "/xss", "/internal", "/static"
        )
        if any(clean_path == r or clean_path.startswith(r + "/") for r in BACKEND_ROUTES):
            content_length = int(self.headers.get("Content-Length", 0))
            post_data = self.rfile.read(content_length) if content_length > 0 else None
            self._proxy_to_backend(method="POST", body_data=post_data)
            return

        self._send_403("POST method is disabled on this endpoint.")

    # ── Scenario 7: Dynamic Auth Verification & Response Generator ───────────
    def _handle_backup_auth(self, user, pw):
        salt = "9c1f7a"
        target_hash = "5269a48d5eb030eee36c71eaa9edbfec94b52cb042ad98cad03bf8e7be20f723"
        target_user = "svc_backup"
        flag_clear  = "CTF{h4sh_cr4ck3d_4cc3ss}"
        flag_b64    = "Q1RGe2g0c2hfY3I0Y2szZF80Y2Mzc3N9"

        computed = hashlib.sha256((salt + pw).encode("utf-8")).hexdigest()
        is_valid = (user.lower() == target_user and computed == target_hash)

        login_file = os.path.join(SERVE_DIR, "backup", "login.html")
        try:
            with open(login_file, "r", encoding="utf-8") as f:
                html = f.read()
        except Exception:
            html = "<html><body><h1>Backup Portal</h1></body></html>"

        if is_valid:
            result_html = f'''<div id="result" class="flag-box success">
  <strong>[+] Authentication Successful!</strong><br><br>
  Service Session Granted: <code>svc_backup@backup-node-01</code><br>
  <strong>Encrypted Flag Token (Base64):</strong> <code>{flag_b64}</code><br>
  <span style="font-size:0.85rem; color:#aaa;">Decode the Base64 token above (e.g. using Burp Suite Decoder) to extract the flag.</span><br>
  <div class="next-step-hint">Keep this recovered password safe &mdash; Scenario 8 (/finale/) requires it!</div>
</div>'''
            auth_status = "SUCCESS"
        else:
            result_html = f'''<div id="result" class="flag-box error">
  <strong>[-] Authentication Failed:</strong> Invalid service credentials for <code>{user}</code>.<br>
  <span style="font-size:0.85rem; color:#aaa;">Hash mismatch with registered service salt [{salt}].</span>
</div>'''
            auth_status = "FAILED"

        # Inject pre-computed result into HTML
        html = html.replace('<div id="result" class="flag-box hidden"></div>', result_html)

        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Auth-Status", auth_status)
        self.end_headers()
        self.wfile.write(body)

    # ── Scenario 8: Chained Verification & Vault Response Generator ─────────
    def _handle_finale_auth(self, cookie_header, key_param):
        salt = "9c1f7a"
        target_hash = "5269a48d5eb030eee36c71eaa9edbfec94b52cb042ad98cad03bf8e7be20f723"
        ciphertext_b64 = "ECErFgNDXARea0I7QVwDOhECXUJYEidGEA=="

        cookie_ok = ("access_level=admin-9f3a" in cookie_header)
        key_hash = hashlib.sha256((salt + key_param).encode("utf-8")).hexdigest() if key_param else ""
        key_ok = (key_hash == target_hash)

        finale_file = os.path.join(SERVE_DIR, "finale", "index.html")
        try:
            with open(finale_file, "r", encoding="utf-8") as f:
                html = f.read()
        except Exception:
            html = "<html><body><h1>Finale Portal</h1></body></html>"

        if cookie_ok and key_ok:
            raw = base64.b64decode(ciphertext_b64)
            decoded_flag = "".join(chr(b ^ ord(key_param[i % len(key_param)])) for i, b in enumerate(raw))
            vault_html = f'''<div id="vaultResult" class="vault-unlocked">
  <strong>[+] ACCESS GRANTED &mdash; VAULT UNLOCKED!</strong><br><br>
  <strong>Encrypted Vault Token (Base64):</strong> <code>{ciphertext_b64}</code><br>
  <strong>Decryption Key:</strong> <code>{key_param}</code><br><br>
  <strong>Grand Finale Flag:</strong> <code>{decoded_flag}</code><br><br>
  <div style="margin-top: 15px; padding: 12px; background: rgba(217, 154, 61, 0.1); border-left: 3px solid #d99a3d; border-radius: 4px;">
    <strong style="color:#d99a3d;">&#128640; NEXT MISSION:</strong> Proceed to the Cyber Defense Store at <a href="/products" style="color:#74b9ff; text-decoration: underline; font-weight: bold;">/products</a> (Scenario 9).
  </div>
</div>'''
            auth_status = "VAULT_UNLOCKED"
            html = html.replace('id="condCookie" class="condition-box failed"', 'id="condCookie" class="condition-box passed" data-server-verified="true"')
            html = html.replace('id="condCookieStatus" class="condition-status">&#10008; Missing (Cookie: access_level=_ _ _ _ _ _ _ _ _ _)</div>', 'id="condCookieStatus" class="condition-status">&#10004; Verified (access_level=admin-9f3a)</div>')
            html = html.replace('id="condKey" class="condition-box failed"', 'id="condKey" class="condition-box passed"')
            html = html.replace('id="condKeyStatus" class="condition-status">&#10008; Missing (?key=_ _ _ _ _ _ _ _ _ _ _)</div>', 'id="condKeyStatus" class="condition-status">&#10004; Verified (Key Hash Validated)</div>')
            html = html.replace('<div id="vaultResult" class="vault-unlocked hidden"></div>', vault_html)
        else:
            missing = []
            if not cookie_ok:
                missing.append("Admin Session Cookie from Scenario 6")
            if not key_ok:
                missing.append("Recovered Service Password from Scenario 7")
            status_html = f'<div id="statusMsg" class="flag-box"><strong>[-] Gate Locked:</strong> Awaiting required artifacts: {" + ".join(missing)}.</div>'
            auth_status = "GATE_LOCKED"
            if cookie_ok:
                html = html.replace('id="condCookie" class="condition-box failed"', 'id="condCookie" class="condition-box passed" data-server-verified="true"')
                html = html.replace('id="condCookieStatus" class="condition-status">&#10008; Missing (Cookie: access_level=_ _ _ _ _ _ _ _ _ _)</div>', 'id="condCookieStatus" class="condition-status">&#10004; Verified (access_level=admin-9f3a)</div>')
            if key_ok:
                html = html.replace('id="condKey" class="condition-box failed"', 'id="condKey" class="condition-box passed"')
                html = html.replace('id="condKeyStatus" class="condition-status">&#10008; Missing (?key=_ _ _ _ _ _ _ _ _ _ _)</div>', 'id="condKeyStatus" class="condition-status">&#10004; Verified (Key Hash Validated)</div>')
            html = html.replace('<div id="statusMsg" class="flag-box hidden"></div>', status_html)

        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Vault-Status", auth_status)
        if cookie_ok:
            self.send_header("Set-Cookie", "access_level=admin-9f3a; Path=/")
        self.end_headers()
        self.wfile.write(body)

    # ── Backend Reverse Proxy (Bridges port 5000 routes into port 8000) ───────
    def _proxy_to_backend(self, method="GET", body_data=None):
        parsed = urllib.parse.urlsplit(self.path)
        quoted_path = urllib.parse.quote(parsed.path, safe="/:@!$&'()*+,;=")
        quoted_query = urllib.parse.quote(parsed.query, safe="/:@!$&'()*+,;=?%")
        if "#" in self.path:
            fragment_part = self.path.split("#", 1)[1]
            quoted_query += "%23" + urllib.parse.quote(fragment_part, safe="/:@!$&'()*+,;=?%")

        clean_url = f"http://127.0.0.1:5000{quoted_path}"
        if quoted_query:
            clean_url += f"?{quoted_query}"

        req_headers = {k: v for k, v in self.headers.items() if k.lower() not in ("host", "content-length")}
        req_headers["Host"] = "127.0.0.1:5000"

        req = urllib.request.Request(clean_url, data=body_data, headers=req_headers, method=method)
        try:
            with urllib.request.urlopen(req) as resp:
                self.send_response(resp.status)
                for k, v in resp.headers.items():
                    if k.lower() not in ("server", "transfer-encoding", "content-length"):
                        self.send_header(k, v)
                resp_body = resp.read()
                self.send_header("Content-Length", str(len(resp_body)))
                self.end_headers()
                self.wfile.write(resp_body)
        except urllib.error.HTTPError as e:
            self.send_response(e.code)
            for k, v in e.headers.items():
                if k.lower() not in ("server", "transfer-encoding", "content-length"):
                    self.send_header(k, v)
            resp_body = e.read()
            self.send_header("Content-Length", str(len(resp_body)))
            self.end_headers()
            self.wfile.write(resp_body)
        except Exception as e:
            self._send_403(f"Backend Gateway Error: {e}")

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

    socketserver.TCPServer.allow_reuse_address = True

    with http.server.ThreadingHTTPServer(("", PORT), CTFHandler) as httpd:
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

