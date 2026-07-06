"""Tests for login, brute-force lockout, and auto-unlock behavior."""

import time

from auth import attempt_login, register_user
from config import Config
from models import get_user_by_username


def _register_test_user():
    register_user("testuser", "testuser@example.com", "Str0ng!Pass1", "Str0ng!Pass1")


def test_successful_login():
    _register_test_user()
    result = attempt_login("testuser", "Str0ng!Pass1", "127.0.0.1", "pytest-agent", "sess-1")
    assert result.success is True
    assert result.user is not None
    assert result.user.username == "testuser"


def test_failed_login_wrong_password():
    _register_test_user()
    result = attempt_login("testuser", "WrongPassword!1", "127.0.0.1", "pytest-agent", "sess-2")
    assert result.success is False
    assert result.locked is False


def test_failed_login_unknown_username():
    result = attempt_login("nobody", "whatever", "127.0.0.1", "pytest-agent", "sess-3")
    assert result.success is False


def test_account_locks_after_max_failed_attempts():
    _register_test_user()
    result = None
    for _ in range(Config.MAX_FAILED_ATTEMPTS):
        result = attempt_login("testuser", "WrongPassword!1", "127.0.0.1", "pytest-agent", "sess-4")

    assert result.locked is True
    user = get_user_by_username("testuser")
    assert user.account_status == "locked"
    assert user.is_locked() is True


def test_login_blocked_while_locked_even_with_correct_password():
    _register_test_user()
    for _ in range(Config.MAX_FAILED_ATTEMPTS):
        attempt_login("testuser", "WrongPassword!1", "127.0.0.1", "pytest-agent", "sess-5")

    # Correct password should still be rejected while locked.
    result = attempt_login("testuser", "Str0ng!Pass1", "127.0.0.1", "pytest-agent", "sess-6")
    assert result.success is False
    assert result.locked is True


def test_account_auto_unlocks_after_lockout_window():
    _register_test_user()
    for _ in range(Config.MAX_FAILED_ATTEMPTS):
        attempt_login("testuser", "WrongPassword!1", "127.0.0.1", "pytest-agent", "sess-7")

    user = get_user_by_username("testuser")
    assert user.is_locked() is True

    # TestingConfig sets a short lockout window (a few seconds) for this scenario.
    time.sleep(Config.LOCKOUT_DURATION_SECONDS + 1)

    result = attempt_login("testuser", "Str0ng!Pass1", "127.0.0.1", "pytest-agent", "sess-8")
    assert result.success is True


def test_password_hash_verification():
    _register_test_user()
    user = get_user_by_username("testuser")
    assert user.check_password("Str0ng!Pass1") is True
    assert user.check_password("wrong-password") is False
