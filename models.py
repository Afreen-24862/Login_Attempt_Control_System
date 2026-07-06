"""
models.py
---------
Data models and data-access-object (DAO) style helper functions for the
`users` and `login_logs` tables. Kept independent of any ORM to keep the
project lightweight and transparent (raw parameterized SQL only).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from config import Config
from database import db_cursor, get_connection


# ---------------------------------------------------------------------------
# User model
# ---------------------------------------------------------------------------
class User(UserMixin):
    """Flask-Login compatible user wrapper around a `users` table row."""

    def __init__(self, row) -> None:
        self.id = row["id"]
        self.uuid = row["uuid"]
        self.username = row["username"]
        self.email = row["email"]
        self.password_hash = row["password_hash"]
        self.role = row["role"]
        self.account_status = row["account_status"]
        self.failed_attempts = row["failed_attempts"]
        self.lock_time = row["lock_time"]
        self.last_login_success = row["last_login_success"]
        self.last_login_failed = row["last_login_failed"]
        self.registration_date = row["registration_date"]

    # Flask-Login requires get_id() to return a string.
    def get_id(self) -> str:
        return str(self.id)

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def is_locked(self) -> bool:
        """Return True if the account is currently within its lockout window."""
        if self.account_status != "locked" or not self.lock_time:
            return False
        lock_dt = datetime.fromisoformat(self.lock_time)
        unlock_dt = lock_dt + timedelta(seconds=Config.LOCKOUT_DURATION_SECONDS)
        return datetime.utcnow() < unlock_dt

    def lock_seconds_remaining(self) -> int:
        if not self.lock_time:
            return 0
        lock_dt = datetime.fromisoformat(self.lock_time)
        unlock_dt = lock_dt + timedelta(seconds=Config.LOCKOUT_DURATION_SECONDS)
        remaining = (unlock_dt - datetime.utcnow()).total_seconds()
        return max(0, int(remaining))

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "uuid": self.uuid,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "account_status": self.account_status,
            "failed_attempts": self.failed_attempts,
            "lock_time": self.lock_time,
            "last_login_success": self.last_login_success,
            "last_login_failed": self.last_login_failed,
            "registration_date": self.registration_date,
        }


# ---------------------------------------------------------------------------
# User DAO functions
# ---------------------------------------------------------------------------
def get_user_by_id(user_id: int) -> Optional[User]:
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return User(row) if row else None
    finally:
        conn.close()


def get_user_by_username(username: str) -> Optional[User]:
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        return User(row) if row else None
    finally:
        conn.close()


def get_user_by_email(email: str) -> Optional[User]:
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        return User(row) if row else None
    finally:
        conn.close()


def create_user(username: str, email: str, password: str) -> User:
    """Insert a new user with a securely hashed password."""
    with db_cursor() as cur:
        cur.execute(
            """
            INSERT INTO users (uuid, username, email, password_hash, role, account_status)
            VALUES (?, ?, ?, ?, 'user', 'active')
            """,
            (str(uuid.uuid4()), username, email, generate_password_hash(password)),
        )
    user = get_user_by_username(username)
    assert user is not None
    return user


def username_exists(username: str) -> bool:
    return get_user_by_username(username) is not None


def email_exists(email: str) -> bool:
    return get_user_by_email(email) is not None


def record_failed_attempt(user: User) -> User:
    """Increment failed_attempts; lock the account if the threshold is hit."""
    new_count = user.failed_attempts + 1
    now = datetime.utcnow().isoformat()

    if new_count >= Config.MAX_FAILED_ATTEMPTS:
        with db_cursor() as cur:
            cur.execute(
                """
                UPDATE users
                SET failed_attempts = ?, account_status = 'locked',
                    lock_time = ?, last_login_failed = ?
                WHERE id = ?
                """,
                (new_count, now, now, user.id),
            )
    else:
        with db_cursor() as cur:
            cur.execute(
                """
                UPDATE users
                SET failed_attempts = ?, last_login_failed = ?
                WHERE id = ?
                """,
                (new_count, now, user.id),
            )
    updated = get_user_by_id(user.id)
    assert updated is not None
    return updated


def reset_failed_attempts(user_id: int) -> None:
    """Reset failed attempt counter and unlock the account (successful login)."""
    with db_cursor() as cur:
        cur.execute(
            """
            UPDATE users
            SET failed_attempts = 0, account_status = 'active', lock_time = NULL,
                last_login_success = ?
            WHERE id = ?
            """,
            (datetime.utcnow().isoformat(), user_id),
        )


def auto_unlock_if_expired(user: User) -> User:
    """If the lockout window has elapsed, automatically unlock the account."""
    if user.account_status == "locked" and not user.is_locked():
        with db_cursor() as cur:
            cur.execute(
                """
                UPDATE users
                SET account_status = 'active', failed_attempts = 0, lock_time = NULL
                WHERE id = ?
                """,
                (user.id,),
            )
        updated = get_user_by_id(user.id)
        assert updated is not None
        return updated
    return user


def admin_lock_user(user_id: int) -> None:
    with db_cursor() as cur:
        cur.execute(
            """
            UPDATE users SET account_status = 'locked', lock_time = ?
            WHERE id = ?
            """,
            (datetime.utcnow().isoformat(), user_id),
        )


def admin_unlock_user(user_id: int) -> None:
    with db_cursor() as cur:
        cur.execute(
            """
            UPDATE users
            SET account_status = 'active', failed_attempts = 0, lock_time = NULL
            WHERE id = ?
            """,
            (user_id,),
        )


def admin_reset_attempts(user_id: int) -> None:
    with db_cursor() as cur:
        cur.execute("UPDATE users SET failed_attempts = 0 WHERE id = ?", (user_id,))


def admin_delete_user(user_id: int) -> None:
    with db_cursor() as cur:
        cur.execute("DELETE FROM users WHERE id = ?", (user_id,))


def update_password(user_id: int, new_password: str) -> None:
    with db_cursor() as cur:
        cur.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (generate_password_hash(new_password), user_id),
        )


def get_all_users() -> list[dict]:
    conn = get_connection()
    try:
        rows = conn.execute("SELECT * FROM users ORDER BY registration_date DESC").fetchall()
        return [User(r).to_dict() for r in rows]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Login log DAO functions
# ---------------------------------------------------------------------------
@dataclass
class LoginLogEntry:
    user_id: Optional[int]
    username: str
    ip_address: str
    browser: str
    login_status: str
    failure_reason: Optional[str]
    session_id: Optional[str]


def insert_login_log(entry: LoginLogEntry) -> None:
    with db_cursor() as cur:
        cur.execute(
            """
            INSERT INTO login_logs
                (user_id, username, ip_address, browser, login_status, failure_reason, session_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entry.user_id,
                entry.username,
                entry.ip_address,
                entry.browser,
                entry.login_status,
                entry.failure_reason,
                entry.session_id,
            ),
        )


def get_logs_for_user(username: str, limit: int = 25) -> list[dict]:
    conn = get_connection()
    try:
        rows = conn.execute(
            """
            SELECT * FROM login_logs
            WHERE username = ?
            ORDER BY login_time DESC
            LIMIT ?
            """,
            (username, limit),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_recent_logs(limit: int = 50) -> list[dict]:
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM login_logs ORDER BY login_time DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def search_logs(
    username: str | None = None,
    status: str | None = None,
    start_date: str | None = None,
    end_date: str | None = None,
) -> list[dict]:
    """Search login logs with optional filters (all parameterized)."""
    query = "SELECT * FROM login_logs WHERE 1=1"
    params: list = []

    if username:
        query += " AND username LIKE ?"
        params.append(f"%{username}%")
    if status:
        query += " AND login_status = ?"
        params.append(status)
    if start_date:
        query += " AND date(login_time) >= date(?)"
        params.append(start_date)
    if end_date:
        query += " AND date(login_time) <= date(?)"
        params.append(end_date)

    query += " ORDER BY login_time DESC"

    conn = get_connection()
    try:
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def delete_all_logs() -> None:
    with db_cursor() as cur:
        cur.execute("DELETE FROM login_logs")


def delete_log(log_id: int) -> None:
    with db_cursor() as cur:
        cur.execute("DELETE FROM login_logs WHERE id = ?", (log_id,))


# ---------------------------------------------------------------------------
# Aggregate statistics used by dashboards
# ---------------------------------------------------------------------------
def get_dashboard_stats() -> dict:
    conn = get_connection()
    try:
        total_users = conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
        active_users = conn.execute(
            "SELECT COUNT(*) c FROM users WHERE account_status = 'active'"
        ).fetchone()["c"]
        locked_users = conn.execute(
            "SELECT COUNT(*) c FROM users WHERE account_status = 'locked'"
        ).fetchone()["c"]
        successful_logins = conn.execute(
            "SELECT COUNT(*) c FROM login_logs WHERE login_status = 'success'"
        ).fetchone()["c"]
        failed_logins = conn.execute(
            "SELECT COUNT(*) c FROM login_logs WHERE login_status = 'failed'"
        ).fetchone()["c"]

        total_attempts = successful_logins + failed_logins
        success_rate = (successful_logins / total_attempts * 100) if total_attempts else 0.0

        top_failed = conn.execute(
            """
            SELECT username, COUNT(*) as failures
            FROM login_logs
            WHERE login_status = 'failed'
            GROUP BY username
            ORDER BY failures DESC
            LIMIT 5
            """
        ).fetchall()

        return {
            "total_users": total_users,
            "active_users": active_users,
            "locked_users": locked_users,
            "successful_logins": successful_logins,
            "failed_logins": failed_logins,
            "success_rate": round(success_rate, 2),
            "top_failed_users": [dict(r) for r in top_failed],
        }
    finally:
        conn.close()
