"""
auth.py
-------
Core authentication business logic: registration and login, including
brute-force protection (failed attempt tracking, account lockout, and
automatic unlock once the lockout window has elapsed).

This module is intentionally decoupled from Flask request/response objects
where possible so the logic is independently unit-testable.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from config import Config
from logger import audit_logger, app_logger
from models import (
    LoginLogEntry,
    User,
    auto_unlock_if_expired,
    create_user,
    email_exists,
    get_user_by_username,
    insert_login_log,
    record_failed_attempt,
    reset_failed_attempts,
    username_exists,
)
from security import (
    is_valid_email,
    is_valid_username,
    sanitize_input,
    validate_password_policy,
)


@dataclass
class AuthResult:
    success: bool
    message: str
    user: Optional[User] = None
    locked: bool = False
    remaining_attempts: Optional[int] = None
    lock_seconds_remaining: int = 0


@dataclass
class RegistrationResult:
    success: bool
    message: str
    errors: list[str]


def register_user(username: str, email: str, password: str, confirm_password: str) -> RegistrationResult:
    """Validate and create a new user account."""
    username = sanitize_input(username)
    email = sanitize_input(email)
    errors: list[str] = []

    if not is_valid_username(username):
        errors.append("Username must be 3-20 characters (letters, numbers, underscore only).")
    if not is_valid_email(email):
        errors.append("Please enter a valid email address.")
    if password != confirm_password:
        errors.append("Passwords do not match.")

    errors.extend(validate_password_policy(password))

    if not errors and username_exists(username):
        errors.append("This username is already taken.")
    if not errors and email_exists(email):
        errors.append("This email is already registered.")

    if errors:
        return RegistrationResult(success=False, message="Registration failed.", errors=errors)

    user = create_user(username, email, password)
    audit_logger.log_event("user_registered", username=username, email=email, user_id=user.id)
    app_logger.info("New user registered: %s", username)

    return RegistrationResult(success=True, message="Registration successful. You may now log in.", errors=[])


def attempt_login(username: str, password: str, ip_address: str, browser: str, session_id: str) -> AuthResult:
    """
    Attempt to authenticate a user.

    Handles:
        - Unknown username (generic error, no user enumeration)
        - Automatic unlock if lockout window has expired
        - Account currently locked
        - Incorrect password (increments failure counter / may trigger lock)
        - Successful login (resets failure counter)

    All outcomes are written to the login_logs audit table.
    """
    username = sanitize_input(username)
    user = get_user_by_username(username)

    if user is None:
        insert_login_log(
            LoginLogEntry(
                user_id=None,
                username=username,
                ip_address=ip_address,
                browser=browser,
                login_status="failed",
                failure_reason="unknown_username",
                session_id=session_id,
            )
        )
        audit_logger.log_event("login_failed", username=username, reason="unknown_username", ip=ip_address)
        return AuthResult(success=False, message="Invalid username or password.")

    # Auto-unlock if the lockout period has already elapsed.
    user = auto_unlock_if_expired(user)

    if user.is_locked():
        remaining = user.lock_seconds_remaining()
        insert_login_log(
            LoginLogEntry(
                user_id=user.id,
                username=username,
                ip_address=ip_address,
                browser=browser,
                login_status="failed",
                failure_reason="account_locked",
                session_id=session_id,
            )
        )
        audit_logger.log_event("login_blocked_locked", username=username, ip=ip_address, remaining=remaining)
        return AuthResult(
            success=False,
            message=f"Account is locked. Try again in {remaining} seconds.",
            locked=True,
            lock_seconds_remaining=remaining,
        )

    if not user.check_password(password):
        updated_user = record_failed_attempt(user)
        insert_login_log(
            LoginLogEntry(
                user_id=user.id,
                username=username,
                ip_address=ip_address,
                browser=browser,
                login_status="failed",
                failure_reason="invalid_password",
                session_id=session_id,
            )
        )
        remaining_attempts = max(0, Config.MAX_FAILED_ATTEMPTS - updated_user.failed_attempts)

        if updated_user.account_status == "locked":
            audit_logger.log_event(
                "account_locked",
                username=username,
                ip=ip_address,
                failed_attempts=updated_user.failed_attempts,
            )
            return AuthResult(
                success=False,
                message=(
                    "Too many failed attempts. Account locked for "
                    f"{Config.LOCKOUT_DURATION_MINUTES} minutes."
                ),
                locked=True,
                lock_seconds_remaining=updated_user.lock_seconds_remaining(),
            )

        audit_logger.log_event(
            "login_failed",
            username=username,
            reason="invalid_password",
            ip=ip_address,
            remaining_attempts=remaining_attempts,
        )
        return AuthResult(
            success=False,
            message=f"Invalid username or password. {remaining_attempts} attempt(s) remaining.",
            remaining_attempts=remaining_attempts,
        )

    # Successful login
    reset_failed_attempts(user.id)
    insert_login_log(
        LoginLogEntry(
            user_id=user.id,
            username=username,
            ip_address=ip_address,
            browser=browser,
            login_status="success",
            failure_reason=None,
            session_id=session_id,
        )
    )
    audit_logger.log_event("login_success", username=username, ip=ip_address)
    refreshed = get_user_by_username(username)
    return AuthResult(success=True, message="Login successful.", user=refreshed)
