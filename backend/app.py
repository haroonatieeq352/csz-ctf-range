"""
CSZone Offensive Security Range — Backend (Phase 1)

Real Flask + SQLite backend covering vulnerability classes that cannot be
authentically simulated in a static site: SQL injection, stored XSS with a
real session/cookie to steal, CSRF against a real state-changing endpoint,
unrestricted file upload, SSRF, backend IDOR, and a real shared-cache layer
for cache deception + cache poisoning.

Every deliberate vulnerability is tagged with a "# VULN:" comment so it can
be grepped and audited independently of this file's prose.

Run: python app.py [port]
"""

import os
import re
import sys
import time
import sqlite3
import requests
from flask import (
    Flask, request, session, redirect, url_for, render_template,
    g, make_response, jsonify
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from db import get_db, init_db, DB_PATH

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "static", "uploads")

app = Flask(__name__)
app.secret_key = os.environ.get("CSZ_SECRET_KEY", "training-range-dev-secret-not-for-prod")

# Permissive SameSite is required for the CSRF challenge's cross-site POST
# to actually carry the session cookie. Modern browsers require Secure=True
# to honor SameSite=None, so the CSRF PoC only fires reliably over HTTPS —
# see SOLUTIONS-INTERNAL.md for deployment notes on this.
app.config.update(
    SESSION_COOKIE_SAMESITE="None",
    SESSION_COOKIE_SECURE=False,   # set True when deployed over HTTPS
)

# ─────────────────────────────────────────────────────────────────────────
# DB lifecycle
# ─────────────────────────────────────────────────────────────────────────

def get_conn():
    if "db" not in g:
        g.db = get_db()
    return g.db


@app.teardown_appcontext
def close_conn(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


# ─────────────────────────────────────────────────────────────────────────
# Simple in-process shared cache (simulates a CDN / reverse-proxy cache
# sitting in front of the app — keyed by path only, blind to auth state
# and blind to which request headers were used to build the response)
# ─────────────────────────────────────────────────────────────────────────

_CACHE = {}
_CACHE_TTL = 300  # seconds

_STATIC_LOOKALIKE = re.compile(r"\.(css|js|jpg|jpeg|png|gif|ico)$", re.IGNORECASE)
_EXPLICIT_CACHEABLE_PATHS = {"/promo/partner-banner"}


def _cache_get(path):
    entry = _CACHE.get(path)
    if entry and entry["expires"] > time.time():
        return entry
    return None


def _cache_set(path, body, content_type):
    _CACHE[path] = {
        "body": body,
        "content_type": content_type,
        "expires": time.time() + _CACHE_TTL,
    }


@app.before_request
def cache_layer_check():
    if request.method != "GET":
        return None
    path = request.path
    cacheable = bool(_STATIC_LOOKALIKE.search(path)) or path in _EXPLICIT_CACHEABLE_PATHS
    if not cacheable:
        return None
    hit = _cache_get(path)
    if hit:
        resp = make_response(hit["body"])
        resp.headers["Content-Type"] = hit["content_type"]
        resp.headers["X-Cache"] = "HIT"
        return resp
    return None


@app.after_request
def cache_layer_store(response):
    path = request.path
    if request.method != "GET" or path.startswith("/static/"):
        return response
    cacheable = bool(_STATIC_LOOKALIKE.search(path)) or path in _EXPLICIT_CACHEABLE_PATHS
    if cacheable and response.status_code == 200:
        if getattr(response, "direct_passthrough", False):
            return response
        # VULN (Cache Deception + Cache Poisoning): cache key is the path
        # ONLY. It does not factor in session/auth cookies, so a
        # personalized authenticated response gets cached and served to
        # anyone. It also does not factor in request headers, so an
        # unkeyed header reflected into the body (see /promo/partner-banner)
        # poisons the cached response for every subsequent visitor.
        response.headers["X-Cache"] = response.headers.get("X-Cache", "MISS")
        _cache_set(path, response.get_data(as_text=True), response.content_type)
    return response


# ─────────────────────────────────────────────────────────────────────────
# Auth helpers (proper, hashed, parameterized — the "good" half of the app)
# ─────────────────────────────────────────────────────────────────────────

def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    row = get_conn().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    return row


def login_required(view):
    from functools import wraps
    @wraps(view)
    def wrapped(*a, **kw):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return view(*a, **kw)
    return wrapped


# ─────────────────────────────────────────────────────────────────────────
# Home
# ─────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


# ─────────────────────────────────────────────────────────────────────────
# Registration / login / logout — proper, parameterized, hashed
# ─────────────────────────────────────────────────────────────────────────

@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email = request.form.get("email", "").strip()
        if not username or not password or not email:
            error = "All fields are required."
        else:
            conn = get_conn()
            existing = conn.execute(
                "SELECT id FROM users WHERE username = ?", (username,)
            ).fetchone()
            if existing:
                error = "Username already taken."
            else:
                conn.execute(
                    "INSERT INTO users (username, password_hash, email, role, bio, personal_note) "
                    "VALUES (?, ?, ?, 'user', '', '')",
                    (username, generate_password_hash(password), email),
                )
                conn.commit()
                return redirect(url_for("login"))
    return render_template("register.html", error=error)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        conn = get_conn()
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        if row and check_password_hash(row["password_hash"], password):
            session["user_id"] = row["id"]
            session["username"] = row["username"]
            session["role"] = row["role"]
            return redirect(url_for("account"))
        error = "Invalid credentials."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    resp = make_response(redirect(url_for("index")))
    resp.delete_cookie("admin_session_flag")
    return resp


# ─────────────────────────────────────────────────────────────────────────
# Account / profile — also the Cache Deception target via a buggy
# catch-all sub-route that was added for "future SPA routing" and never
# properly scoped.
# ─────────────────────────────────────────────────────────────────────────

@app.route("/account")
@login_required
def account():
    user = current_user()
    return render_template("account.html", user=user, csrf_note=True)


# VULN (Cache Deception): this route exists because someone added
# "/account/profile/<path:extra>" to support a future front-end asset
# path scheme, and never restricted what `extra` could be. It renders the
# exact same authenticated, personalized content as /account regardless of
# what `extra` is — including values that end in .css/.js/.png, which the
# cache layer above treats as a static, universally-cacheable asset.
@app.route("/account/profile/<path:extra>")
def account_profile_extra(extra):
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    return render_template("account.html", user=user, csrf_note=False)


# VULN (CSRF): state-changing POST, session-cookie authenticated, no CSRF
# token, no re-authentication, no Origin/Referer check. Combined with
# SESSION_COOKIE_SAMESITE=None above, a cross-site auto-submitting form
# can change a logged-in participant's email without their knowledge.
@app.route("/account/email", methods=["POST"])
@login_required
def change_email():
    new_email = request.form.get("email", "").strip()
    conn = get_conn()
    conn.execute("UPDATE users SET email = ? WHERE id = ?", (new_email, session["user_id"]))
    conn.commit()
    flag = ""
    if new_email.endswith("@attacker-controlled.test"):
        flag = "CTF{csrf_n0_t0k3n_pwn3d}"
    user = current_user()
    return render_template("account.html", user=user, csrf_note=False, csrf_flag=flag)


# ─────────────────────────────────────────────────────────────────────────
# Guestbook — Stored XSS target (public read/write, unescaped render)
# ─────────────────────────────────────────────────────────────────────────

@app.route("/guestbook", methods=["GET", "POST"])
def guestbook():
    conn = get_conn()
    if request.method == "POST":
        name = request.form.get("name", "anonymous").strip() or "anonymous"
        message = request.form.get("message", "")
        conn.execute(
            "INSERT INTO guestbook (name, message) VALUES (?, ?)", (name, message)
        )
        conn.commit()
        return redirect(url_for("guestbook"))
    entries = conn.execute(
        "SELECT name, message, created_at FROM guestbook ORDER BY id DESC"
    ).fetchall()
    # VULN (Stored XSS): message is rendered with the `safe` filter in the
    # template, i.e. deliberately NOT auto-escaped, unlike every other
    # user-controlled value in this app.
    return render_template("guestbook.html", entries=entries)


# ─────────────────────────────────────────────────────────────────────────
# Legacy admin portal — SQL injection auth-bypass target
# ─────────────────────────────────────────────────────────────────────────

@app.route("/legacy-admin/login", methods=["GET", "POST"])
def legacy_admin_login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        conn = get_conn()
        # VULN (SQL Injection — auth bypass): raw string-built query
        # against the legacy table. This is the ONLY query in the app
        # built this way — every other query uses parameter binding.
        query = (
            "SELECT * FROM legacy_admin_creds WHERE username = '"
            + username + "' AND password = '" + password + "'"
        )
        try:
            row = conn.execute(query).fetchone()
        except sqlite3.OperationalError as e:
            error = f"Query error: {e}"
            row = None
        if row:
            session["user_id"] = session.get("user_id") or -1  # legacy portal has no real user row
            session["username"] = "admin (legacy)"
            session["role"] = "admin"
            resp = make_response(redirect(url_for("admin_inbox")))
            # VULN (part of the Stored XSS chain): sensitive value stored
            # in a non-HttpOnly cookie "for a legacy dashboard widget that
            # reads it client-side" — readable by any script running in
            # this origin, including an injected stored-XSS payload.
            resp.set_cookie(
                "admin_session_flag",
                "CTF{st0r3d_c00k13_th3ft}",
                httponly=False,
            )
            return resp
        error = error or "Invalid credentials."
    return render_template("legacy_admin_login.html", error=error)


@app.route("/admin/inbox")
def admin_inbox():
    if session.get("role") != "admin":
        return redirect(url_for("legacy_admin_login"))
    conn = get_conn()
    entries = conn.execute(
        "SELECT name, message, created_at FROM guestbook ORDER BY id DESC"
    ).fetchall()
    # Same unescaped render as the public guestbook — this is what makes
    # a payload planted anonymously earlier fire in the admin's own
    # browser session once they view this page.
    return render_template("admin_inbox.html", entries=entries)


# ─────────────────────────────────────────────────────────────────────────
# XSS cookie-exfil collector (stand-in for an attacker-controlled server)
# ─────────────────────────────────────────────────────────────────────────

@app.route("/xss/collect")
def xss_collect():
    data = request.args.get("c", "")
    conn = get_conn()
    conn.execute(
        "INSERT INTO stolen_cookies (source_ip, cookie_data) VALUES (?, ?)",
        (request.remote_addr, data),
    )
    conn.commit()
    return "", 204


@app.route("/xss/collect/log")
def xss_collect_log():
    conn = get_conn()
    rows = conn.execute(
        "SELECT captured_at, source_ip, cookie_data FROM stolen_cookies ORDER BY id DESC"
    ).fetchall()
    return render_template("xss_log.html", rows=rows)


# ─────────────────────────────────────────────────────────────────────────
# E-Commerce Product Catalog — UNION-based SQLi Basics target
# ─────────────────────────────────────────────────────────────────────────

@app.route("/products", methods=["GET"])
def products():
    category = request.args.get("category", "").strip()
    conn = get_conn()
    error = None
    products_list = []

    if category:
        # VULN (SQL Injection — UNION extraction basics):
        # 2 selected columns (name, description), filterable by category.
        # String concatenation allows boolean bypass (' OR 1=1 -- -) and UNION injection.
        query = (
            "SELECT name, description FROM products "
            f"WHERE category = '{category}' AND is_released = 1"
        )
        try:
            products_list = conn.execute(query).fetchall()
        except sqlite3.OperationalError as e:
            error = f"Database Error: {e}"
    else:
        query = "SELECT name, description FROM products WHERE is_released = 1"
        products_list = conn.execute(query).fetchall()

    categories = ["Hardware", "Software"]
    status_code = 500 if error else 200
    resp = make_response(
        render_template(
            "products.html",
            products=products_list,
            selected_category=category,
            categories=categories,
            error=error,
        ),
        status_code,
    )
    resp.headers["X-Database-Schema-Note"] = "Audit: Confidential flags stored in table 'site_secrets(title, secret_flag)'"
    return resp


# ─────────────────────────────────────────────────────────────────────────
# Scenario 10: Staff directory — 4-Column UNION SQLi (Strict Type Checking & Hash Comment)
# ─────────────────────────────────────────────────────────────────────────

@app.route("/directory", methods=["GET"])
def directory():
    q = request.args.get("q", "")
    results = []
    error = None
    if q:
        # Security Filter: Block '--' comments to teach comment discovery
        if "--" in q:
            error = "WAF Alert: SQL comment syntax '--' is blocked by security filter. Use alternative comment syntax."
        else:
            conn = get_conn()
            # Base query selects 4 columns: name (TEXT), badge_id (INT), department (TEXT), email (TEXT)
            full_query = (
                "SELECT name, badge_id, department, email FROM employees "
                f"WHERE name LIKE '%{q}%'"
            )
            # If '#' comment is used, comment out the rest of the query (including the trailing %')
            query = full_query.split("#")[0]
            try:
                raw_rows = conn.execute(query).fetchall()
                # Strict Data Type Validation: (Col 1: String, Col 2: Integer, Col 3: String, Col 4: String)
                for row in raw_rows:
                    col1, col2, col3, col4 = row[0], row[1], row[2], row[3]
                    if not isinstance(col1, str):
                        raise sqlite3.OperationalError(
                            f"DataTypeError: Column 1 (Employee Name) expects TEXT/STRING data type, received incompatible numeric '{col1}'."
                        )
                    if not isinstance(col2, int) or isinstance(col2, bool):
                        raise sqlite3.OperationalError(
                            f"DataTypeError: Column 2 (Badge ID) expects INTEGER data type, received incompatible string '{col2}'."
                        )
                    if not isinstance(col3, str):
                        raise sqlite3.OperationalError(
                            f"DataTypeError: Column 3 (Department) expects TEXT/STRING data type, received incompatible numeric '{col3}'."
                        )
                    if not isinstance(col4, str):
                        raise sqlite3.OperationalError(
                            f"DataTypeError: Column 4 (Corporate Email) expects TEXT/STRING data type, received incompatible numeric '{col4}'."
                        )
                results = raw_rows
            except sqlite3.OperationalError as e:
                error = f"Database Query Error: {e}"

    status_code = 500 if error else 200
    resp = make_response(render_template("directory.html", q=q, results=results, error=error), status_code)
    resp.headers["X-Staff-Database-Hint"] = "Clearances Table: 'staff_clearances(officer_name, clearance_level, department_code, master_flag)'"
    return resp


# ─────────────────────────────────────────────────────────────────────────
# Orders — backend IDOR target
# ─────────────────────────────────────────────────────────────────────────

@app.route("/orders")
@login_required
def orders():
    conn = get_conn()
    rows = conn.execute(
        "SELECT id, item, amount FROM orders WHERE user_id = ?", (session["user_id"],)
    ).fetchall()
    return render_template("orders.html", rows=rows)


@app.route("/orders/<int:order_id>")
@login_required
def order_detail(order_id):
    conn = get_conn()
    # VULN (IDOR): no check that orders.user_id == session['user_id'].
    # Any authenticated user can view any order by incrementing the ID.
    row = conn.execute(
        "SELECT id, user_id, item, amount, notes FROM orders WHERE id = ?", (order_id,)
    ).fetchone()
    if not row:
        return "Order not found.", 404
    return render_template("order_detail.html", order=row)


# ─────────────────────────────────────────────────────────────────────────
# Avatar import — SSRF target
# ─────────────────────────────────────────────────────────────────────────

@app.route("/avatar-import", methods=["GET", "POST"])
@login_required
def avatar_import():
    result = None
    error = None
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        try:
            # VULN (SSRF): server fetches an arbitrary user-supplied URL
            # with no allowlist, no scheme restriction, and no check
            # against internal/loopback addresses.
            resp = requests.get(url, timeout=3)
            result = resp.text[:2000]
        except Exception as e:
            error = f"Fetch failed: {e}"
    return render_template("avatar_import.html", result=result, error=error)


@app.route("/internal/metadata")
def internal_metadata():
    # Simulates an internal-only metadata service. The only real control
    # here is a source-IP check — trivially reachable via the SSRF above
    # since the request then originates from the server itself (127.0.0.1).
    if request.remote_addr not in ("127.0.0.1", "::1"):
        return "Forbidden — internal service.", 403
    return jsonify({
        "service": "internal-metadata",
        "build": "range-backend-1.0.0",
        "flag": "CTF{ssrf_1nt3rn4l_m3t4d4t4}",
    })


# ─────────────────────────────────────────────────────────────────────────
# File upload — unrestricted upload target
# ─────────────────────────────────────────────────────────────────────────

# VULN (File Upload): blocklist, not allowlist — and it's missing .html,
# .htm, .svg, which are exactly what's needed to get script execution
# when the file is later served from the same origin.
BLOCKED_EXTENSIONS = {".php", ".py", ".exe", ".sh", ".jsp", ".asp", ".aspx"}


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    error = None
    uploaded_url = None
    if request.method == "POST":
        f = request.files.get("file")
        if not f or f.filename == "":
            error = "No file selected."
        else:
            filename = secure_filename(f.filename)
            ext = os.path.splitext(filename)[1].lower()
            if ext in BLOCKED_EXTENSIONS:
                error = f"File type {ext} is not allowed."
            else:
                os.makedirs(UPLOAD_DIR, exist_ok=True)
                dest = os.path.join(UPLOAD_DIR, filename)
                f.save(dest)
                uploaded_url = f"/static/uploads/{filename}"
    return render_template("upload.html", error=error, uploaded_url=uploaded_url)


# ─────────────────────────────────────────────────────────────────────────
# Cache poisoning target — partner promo banner
# ─────────────────────────────────────────────────────────────────────────

@app.route("/promo/partner-banner")
def promo_partner_banner():
    # VULN (Cache Poisoning): X-Forwarded-Host is attacker-controlled and
    # unkeyed — the shared cache above keys purely on request.path, so
    # whichever value wins the race gets served to every subsequent
    # visitor of this path for the cache TTL.
    forwarded_host = request.headers.get("X-Forwarded-Host", request.host)
    canonical_url = f"https://{forwarded_host}/promo/partner-banner"
    return render_template("cache_promo.html", canonical_url=canonical_url)


# ─────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        init_db()
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    app.run(host="0.0.0.0", port=port, debug=False)
