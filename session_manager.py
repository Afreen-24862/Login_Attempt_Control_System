"""
session_manager.py
-------------------
Helpers for managing user session lifecycle: session id generation,
inactivity timeout enforcement, and "remember me" handling.

Flask's built-in session (signed cookie) is used as the underlying
mechanism; this module adds the security-relevant bookkeeping on top of it
(last-activity timestamp, session UUID, inactivity expiry check).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from flask import session

from config import Config


def start_session(user_id: int, remember: bool = False) -> str:
    """Initialize a new authenticated session and return its session id."""
    session_id = str(uuid.uuid4())
    session["session_id"] = session_id
    session["user_id"] = user_id
    session["last_activity"] = datetime.utcnow().isoformat()
    session["remember"] = bool(remember)
    session.permanent = True
    return session_id


def touch_session() -> None:
    """Update the last-activity timestamp (call on every authenticated request)."""
    session["last_activity"] = datetime.utcnow().isoformat()


def is_session_expired() -> bool:
    """Check whether the session has been inactive longer than the allowed timeout."""
    last_activity = session.get("last_activity")
    if not last_activity:
        return True
    elapsed = (datetime.utcnow() - datetime.fromisoformat(last_activity)).total_seconds()
    return elapsed > Config.PERMANENT_SESSION_LIFETIME.total_seconds()


def end_session() -> None:
    """Clear all session data (used on logout)."""
    session.clear()


def get_current_session_id() -> str | None:
    return session.get("session_id")
