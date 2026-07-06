"""
database.py
-----------
SQLite database layer for the Login Attempt Control System.

Responsible for:
    - Establishing connections (row-factory enabled for dict-like access)
    - Creating the schema (`users`, `login_logs`) if it does not exist
    - Seeding a default administrator account on first run

All SQL in this module uses parameterized queries exclusively to prevent
SQL injection.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from typing import Iterator

from werkzeug.security import generate_password_hash

from config import Config
from logger import app_logger

import os

os.makedirs(os.path.dirname(Config.DATABASE_PATH), exist_ok=True)


def get_connection(db_path: str | None = None) -> sqlite3.Connection:
    """Return a new SQLite connection with row access by column name."""
    conn = sqlite3.connect(db_path or Config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def db_cursor(db_path: str | None = None) -> Iterator[sqlite3.Cursor]:
    """Context manager that yields a cursor and commits/rolls back safely."""
    conn = get_connection(db_path)
    try:
        cur = conn.cursor()
        yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


SCHEMA_USERS = """
CREATE TABLE IF NOT EXISTS users (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid                TEXT UNIQUE NOT NULL,
    username            TEXT UNIQUE NOT NULL,
    email               TEXT UNIQUE NOT NULL,
    password_hash       TEXT NOT NULL,
    role                TEXT NOT NULL DEFAULT 'user',
    account_status      TEXT NOT NULL DEFAULT 'active',
    failed_attempts     INTEGER NOT NULL DEFAULT 0,
    lock_time           TEXT,
    last_login_success  TEXT,
    last_login_failed   TEXT,
    registration_date   TEXT NOT NULL DEFAULT (datetime('now'))
);
"""

SCHEMA_LOGIN_LOGS = """
CREATE TABLE IF NOT EXISTS login_logs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER,
    username        TEXT NOT NULL,
    login_time      TEXT NOT NULL DEFAULT (datetime('now')),
    ip_address      TEXT,
    browser         TEXT,
    login_status    TEXT NOT NULL,
    failure_reason  TEXT,
    session_id      TEXT,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
);
"""

SCHEMA_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_logs_username ON login_logs (username);",
    "CREATE INDEX IF NOT EXISTS idx_logs_time ON login_logs (login_time);",
    "CREATE INDEX IF NOT EXISTS idx_logs_status ON login_logs (login_status);",
]


def init_db(db_path: str | None = None) -> None:
    """Create all tables (idempotent) and seed the default admin account."""
    with db_cursor(db_path) as cur:
        cur.execute(SCHEMA_USERS)
        cur.execute(SCHEMA_LOGIN_LOGS)
        for stmt in SCHEMA_INDEXES:
            cur.execute(stmt)

    _seed_admin(db_path)
    app_logger.info("Database initialized at %s", db_path or Config.DATABASE_PATH)


def _seed_admin(db_path: str | None = None) -> None:
    """Create a default admin account if no admin user exists yet."""
    import uuid

    with db_cursor(db_path) as cur:
        cur.execute("SELECT id FROM users WHERE role = 'admin' LIMIT 1")
        if cur.fetchone() is not None:
            return

        cur.execute(
            """
            INSERT INTO users (uuid, username, email, password_hash, role, account_status)
            VALUES (?, ?, ?, ?, 'admin', 'active')
            """,
            (
                str(uuid.uuid4()),
                Config.DEFAULT_ADMIN_USERNAME,
                Config.DEFAULT_ADMIN_EMAIL,
                generate_password_hash(Config.DEFAULT_ADMIN_PASSWORD),
            ),
        )
        app_logger.info("Seeded default admin account '%s'", Config.DEFAULT_ADMIN_USERNAME)
