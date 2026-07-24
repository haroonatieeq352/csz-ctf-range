import sqlite3
import os
from werkzeug.security import generate_password_hash

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "instance", "range.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """(Re)builds the database from schema.sql and seeds real password hashes."""
    schema_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema.sql")
    with open(schema_path, "r") as f:
        schema = f.read()

    conn = get_db()
    conn.executescript(schema)
    conn.commit()

    # Set real password hashes (placeholders in schema.sql are just markers)
    participant_hash = generate_password_hash("Range2024!")
    finance_hash = generate_password_hash(os.urandom(16).hex())  # nobody logs in as this one directly

    conn.execute("UPDATE users SET password_hash = ? WHERE username = 'participant'", (participant_hash,))
    conn.execute("UPDATE users SET password_hash = ? WHERE username = 'finance_bot'", (finance_hash,))
    conn.commit()
    conn.close()
    print("[db] Database initialized at", DB_PATH)


if __name__ == "__main__":
    init_db()
