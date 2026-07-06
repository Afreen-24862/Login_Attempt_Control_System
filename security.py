"""
security.py
-----------
Security utility functions:
    - Strong password policy enforcement
    - Password strength scoring (used by the registration UI meter)
    - Simple in-memory sliding-window rate limiter for the login endpoint
    - Basic input sanitation helpers

Note: bcrypt-style hashing is delegated to werkzeug.security
(`generate_password_hash` / `check_password_hash`), which uses PBKDF2-SHA256
under the hood -- a NIST-approved, salted, adaptive hashing scheme
equivalent in purpose to bcrypt for this project's needs.
"""

from __future__ import annotations

import re
import time
from collections import defaultdict, deque
from typing import Deque, Dict

from config import Config

# ---------------------------------------------------------------------------
# Password policy
# ---------------------------------------------------------------------------
_SPECIAL_CHARS = r"""!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~`"""


def validate_password_policy(password: str) -> list[str]:
    """
    Validate a password against the configured policy.
    Returns a list of human-readable violation messages (empty if valid).
    """
    errors: list[str] = []

    if len(password) < Config.PASSWORD_MIN_LENGTH:
        errors.append(f"Password must be at least {Config.PASSWORD_MIN_LENGTH} characters long.")
    if Config.PASSWORD_REQUIRE_UPPERCASE and not re.search(r"[A-Z]", password):
        errors.append("Password must contain at least one uppercase letter.")
    if Config.PASSWORD_REQUIRE_LOWERCASE and not re.search(r"[a-z]", password):
        errors.append("Password must contain at least one lowercase letter.")
    if Config.PASSWORD_REQUIRE_DIGIT and not re.search(r"\d", password):
        errors.append("Password must contain at least one digit.")
    if Config.PASSWORD_REQUIRE_SPECIAL and not re.search(f"[{_SPECIAL_CHARS}]", password):
        errors.append("Password must contain at least one special character.")

    return errors


def password_strength_score(password: str) -> int:
    """
    Return an integer score from 0-100 representing password strength.
    Used purely for UX feedback (the meter); the authoritative check is
    `validate_password_policy`.
    """
    score = 0
    if not password:
        return 0

    length_score = min(len(password) / 16, 1.0) * 40
    score += length_score

    variety = 0
    if re.search(r"[a-z]", password):
        variety += 1
    if re.search(r"[A-Z]", password):
        variety += 1
    if re.search(r"\d", password):
        variety += 1
    if re.search(f"[{_SPECIAL_CHARS}]", password):
        variety += 1
    score += variety * 15

    # Small penalty for common weak patterns
    weak_patterns = ["password", "123456", "qwerty", "letmein", "admin"]
    if any(p in password.lower() for p in weak_patterns):
        score -= 30

    return max(0, min(100, int(score)))


def strength_label(score: int) -> str:
    if score >= 80:
        return "Very Strong"
    if score >= 60:
        return "Strong"
    if score >= 40:
        return "Moderate"
    if score >= 20:
        return "Weak"
    return "Very Weak"


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def is_valid_username(username: str) -> bool:
    return bool(USERNAME_RE.match(username or ""))


def is_valid_email(email: str) -> bool:
    return bool(EMAIL_RE.match(email or ""))


def sanitize_input(value: str) -> str:
    """Strip whitespace and remove characters commonly used in injection attempts."""
    if value is None:
        return ""
    value = value.strip()
    # Parameterized SQL already prevents SQL injection; this is a defense-in-depth
    # layer that strips characters with no legitimate use in usernames/emails.
    value = re.sub(r"[<>;\"'`]", "", value)
    return value


# ---------------------------------------------------------------------------
# Rate limiting (simple in-memory sliding window, keyed by IP address)
# ---------------------------------------------------------------------------
class RateLimiter:
    def __init__(self, max_requests: int, window_seconds: int) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits: Dict[str, Deque[float]] = defaultdict(deque)

    def is_allowed(self, key: str) -> bool:
        now = time.time()
        window = self._hits[key]

        while window and window[0] <= now - self.window_seconds:
            window.popleft()

        if len(window) >= self.max_requests:
            return False

        window.append(now)
        return True

    def seconds_until_next_allowed(self, key: str) -> int:
        window = self._hits[key]
        if not window:
            return 0
        oldest = window[0]
        remaining = self.window_seconds - (time.time() - oldest)
        return max(0, int(remaining))


login_rate_limiter = RateLimiter(
    max_requests=Config.RATE_LIMIT_MAX_REQUESTS,
    window_seconds=Config.RATE_LIMIT_WINDOW_SECONDS,
)
from models import get_user_by_username, get_user_by_email

def username_exists(username: str) -> bool:
    return get_user_by_username(username) is not None

def email_exists(email: str) -> bool:
    return get_user_by_email(email) is not None