#!/usr/bin/env python3
"""
CSZone CTF Range — Scenario 08: Central Vault Finale
Port: 8008
"""
import http.server
import http.client
from http import HTTPStatus
import socketserver
import sys
import os
import hashlib
import urllib.parse
import base64

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8008
SERVE_DIR = os.path.dirname(os.path.abspath(__file__))
BLOCKED_FILES = {"server.py", "README.md"}

def xor_decrypt(ciphertext_b64, key_str):
    raw = base64.b64decode(ciphertext_b64)
    key_bytes = key_str.encode("utf-8")
    out = bytearray()
    for i, b in enumerate(raw):
        out.append(b ^ key_bytes[i % len(key_bytes)])
    return out.decode("utf-8", errors="replace")

class Scenario08Handler(http.server.SimpleHTTPRequestHandler):
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
        super().end_headers()

    def do_GET(self):
        clean_path = self.path.split("?")[0].strip("/").lower()
        if clean_path in BLOCKED_FILES or any(clean_path.endswith("/" + b) for b in BLOCKED_FILES):
            self.send_error(HTTPStatus.FORBIDDEN, "Access Denied")
            return

        parsed = urllib.parse.urlparse(self.path)
        path_only = parsed.path.rstrip("/")
        if path_only in ("/finale", "/finale/index.html"):
            params = urllib.parse.parse_qs(parsed.query)
            key_param = params.get("key", [""])[0]
            cookie_header = self.headers.get("Cookie", "")
            self._handle_finale_auth(cookie_header, key_param)
            return

        super().do_GET()

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
            html = "<html><body><h1>Finale Vault</h1></body></html>"

        if cookie_ok and key_ok:
            decoded_flag = xor_decrypt(ciphertext_b64, key_param)
            vault_html = f'''<div id="vaultResult" class="vault-unlocked">
  <strong>[+] ACCESS GRANTED &mdash; VAULT UNLOCKED!</strong><br><br>
  <strong>Encrypted Vault Token (Base64):</strong> <code>{ciphertext_b64}</code><br>
  <strong>Decryption Key:</strong> <code>{key_param}</code><br><br>
  <strong>Grand Finale Flag:</strong> <code>{decoded_flag}</code><br>
</div>'''
            status_html = '<div id="statusMsg" class="flag-box hidden"></div>'
            vault_status = "UNLOCKED"
        else:
            missing = []
            if not cookie_ok:
                missing.append("Admin Session Cookie (Scenario 06)")
            if not key_ok:
                missing.append("Service Password Key (Scenario 07)")
            status_html = f'''<div id="statusMsg" class="flag-box error">
  <strong>[-] Gate Locked:</strong> Awaiting required chained artifacts: {' + '.join(missing)}.
</div>'''
            vault_html = '<div id="vaultResult" class="vault-unlocked hidden"></div>'
            vault_status = "LOCKED"

        html = html.replace('<div id="statusMsg" class="flag-box hidden"></div>', status_html)
        html = html.replace('<div id="vaultResult" class="vault-unlocked hidden"></div>', vault_html)

        if cookie_ok:
            html = html.replace('id="condCookie" class="condition-box failed"', 'id="condCookie" class="condition-box passed" data-server-verified="true"')
            html = html.replace('id="condCookieStatus" class="condition-status">&#10008; Missing (Cookie: access_level=<span class="masked-val">&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;</span>)', 'id="condCookieStatus" class="condition-status">&#10004; Verified (Admin Session Cookie Active)')
        if key_ok:
            html = html.replace('id="condKey" class="condition-box failed"', 'id="condKey" class="condition-box passed"')
            html = html.replace('id="condKeyStatus" class="condition-status">&#10008; Missing (?key=<span class="masked-val">&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;</span>)', 'id="condKeyStatus" class="condition-status">&#10004; Verified (Scenario 07 Service Key Validated)')

        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Vault-Status", vault_status)
        self.end_headers()
        self.wfile.write(body)

if __name__ == "__main__":
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(("0.0.0.0", PORT), Scenario08Handler) as httpd:
        print(f"[*] Scenario 08 Central Security Vault running on http://localhost:{PORT}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[-] Shutting down Scenario 08.")
