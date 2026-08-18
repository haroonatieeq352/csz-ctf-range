-- CSZone Offensive Security Range — Backend Schema
-- Mixed maturity by design: the main `users` table uses proper hashed
-- passwords and parameterized queries throughout the codebase. The
-- `legacy_admin_creds` table is a deliberately preserved bad pattern
-- (plaintext password, string-built SQL) representing a real-world
-- "old system nobody decommissioned" finding.

DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS legacy_admin_creds;
DROP TABLE IF EXISTS employees;
DROP TABLE IF EXISTS flags;
DROP TABLE IF EXISTS guestbook;
DROP TABLE IF EXISTS orders;
DROP TABLE IF EXISTS stolen_cookies;
DROP TABLE IF EXISTS products;
DROP TABLE IF EXISTS site_secrets;
DROP TABLE IF EXISTS staff_clearances;

CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    email         TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'user',
    bio           TEXT DEFAULT '',
    personal_note TEXT DEFAULT ''
);

-- Deliberately vulnerable legacy portal target (SQLi auth bypass)
CREATE TABLE legacy_admin_creds (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL  -- plaintext on purpose: legacy system, never migrated
);

-- UNION-based SQLi target (4-column employee directory search: string, int, string, string)
CREATE TABLE employees (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    badge_id   INTEGER NOT NULL,
    department TEXT NOT NULL,
    email      TEXT NOT NULL
);

-- Hidden staff clearances table (Scenario 10 UNION extraction target)
CREATE TABLE staff_clearances (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    officer_name    TEXT NOT NULL,
    clearance_level INTEGER NOT NULL,
    department_code TEXT NOT NULL,
    master_flag     TEXT NOT NULL
);

-- Hidden table, only reachable via successful UNION injection
CREATE TABLE flags (
    id    INTEGER PRIMARY KEY AUTOINCREMENT,
    label TEXT NOT NULL,
    value TEXT NOT NULL
);

-- Stored XSS target
CREATE TABLE guestbook (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    message    TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- IDOR target
CREATE TABLE orders (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    item    TEXT NOT NULL,
    amount  TEXT NOT NULL,
    notes   TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Logs beacons from successful stored-XSS cookie exfiltration
CREATE TABLE stolen_cookies (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    captured_at TEXT DEFAULT CURRENT_TIMESTAMP,
    source_ip   TEXT,
    cookie_data TEXT
);

-- E-Commerce product catalog (UNION SQLi Basics target)
CREATE TABLE products (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    category    TEXT NOT NULL,
    description TEXT NOT NULL,
    price       TEXT NOT NULL,
    is_released INTEGER DEFAULT 1
);

-- Hidden secret store table (target for UNION extraction)
CREATE TABLE site_secrets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    title       TEXT NOT NULL,
    secret_flag TEXT NOT NULL
);

-- ── Seed data ────────────────────────────────────────────────────────

-- Real users (proper hashed passwords — set by seed.py, placeholders here)
INSERT INTO users (id, username, password_hash, email, role, bio, personal_note) VALUES
    (1, 'participant', '__HASH_PARTICIPANT__', 'participant@cszone.internal', 'user',
     'Training range participant account.',
     'Private note (personal, not for public profile): CTF{c4ch3_d3c3pt10n_l34k}'),
    (2, 'finance_bot', '__HASH_FINANCE__', 'finance-automation@cszone.internal', 'user',
     'Automated finance reconciliation account.',
     'Private note: Q3 reconciliation reminders, nothing else here.');

-- Legacy admin portal (deliberately weak — the SQLi target)
INSERT INTO legacy_admin_creds (username, password) VALUES
    ('admin', 'L3g4cyAdm1n_2023!');

-- Employee directory (Scenario 10 UNION SQLi target — 4 columns: name, badge_id, department, email)
INSERT INTO employees (name, badge_id, department, email) VALUES
    ('Ayesha Raza', 1042, 'Engineering', 'ayesha.raza@cszone.internal'),
    ('Bilal Hassan', 2088, 'Finance', 'bilal.hassan@cszone.internal'),
    ('Sara Khan', 3014, 'HR', 'sara.khan@cszone.internal'),
    ('Usman Tariq', 1099, 'Engineering', 'usman.tariq@cszone.internal'),
    ('Mahnoor Iqbal', 4055, 'Operations', 'mahnoor.iqbal@cszone.internal');

-- Staff clearances (Scenario 10 Secret Target: officer_name, clearance_level, department_code, master_flag)
INSERT INTO staff_clearances (officer_name, clearance_level, department_code, master_flag) VALUES
    ('Director Vance', 5, 'SEC-OPS-09', 'CTF{un10n_4c0l_typ3_m4st3r} -- [Next Target]: Infiltrate Account Profile / Audit at /account (Scenario 11). Warning: No direct schema hints provided - full catalog enumeration required.');

-- Hidden flag table (only reachable via UNION SELECT)
INSERT INTO flags (label, value) VALUES
    ('union_extraction', 'CTF{un10n_s3l3ct_m4st3r}');

-- Guestbook seed entries (real ones will be posted by participants)
INSERT INTO guestbook (name, message) VALUES
    ('CSZone Bot', 'Welcome to the range guestbook. Be nice.'),
    ('ops-team', 'Reminder: this board is publicly readable and writable. Do not post real secrets here.');

-- Orders (IDOR target — order #1 belongs to the participant, #2 to finance_bot)
INSERT INTO orders (user_id, item, amount, notes) VALUES
    (1, 'Training Range License', 'PKR 0 (internal)', 'Standard tier. Nothing sensitive here.'),
    (2, 'Vendor Invoice Reconciliation', 'PKR 340,000',
     'Internal audit trail — do not expose externally. Ref token: CTF{b4ck3nd_1d0r_r34l}');

-- Products seed data (UNION SQLi Basics)
INSERT INTO products (name, category, description, price, is_released) VALUES
    ('Hardware Security Key', 'Hardware', 'FIDO2 & U2F physical security token for multi-factor authentication.', '$49.99', 1),
    ('Encrypted USB Vault', 'Hardware', 'Hardware-encrypted USB 3.2 flash drive with keypad access.', '$89.99', 1),
    ('Network Tap Probe', 'Hardware', 'Passive gigabit ethernet monitoring tap for traffic inspection.', '$129.99', 1),
    ('Cyber Defense Terminal', 'Hardware', 'Ruggedized field diagnostic terminal with dual NICs.', '$499.99', 1),
    ('Prototype Quantum Key Dongle', 'Hardware', 'Unreleased quantum-resistant hardware token (Confidential).', '$999.99', 0),
    ('Network Packet Analyzer', 'Software', 'Enterprise DPI deep-packet inspection suite.', '$299.00', 1),
    ('Endpoint Shield Agent', 'Software', 'Next-gen anti-tamper security defense agent.', '$149.00', 1);

-- Site secrets seed data (Scenario 9 flag + Next Target Hint)
INSERT INTO site_secrets (title, secret_flag) VALUES
    ('Master API Credentials', 'CTF{un10n_b4s1cs_m4st3r} -- [Next Target]: Proceed to Personnel Directory at /directory (Scenario 10). Note: Security filter blocks ''--'' comment syntax.');
