"""Tests for password policy, strength scoring, and injection resistance."""

from auth import attempt_login, register_user
from models import get_user_by_username
from security import (
    is_valid_email,
    is_valid_username,
    password_strength_score,
    validate_password_policy,
)


def test_password_policy_rejects_short_password():
    errors = validate_password_policy("Ab1!")
    assert len(errors) > 0


def test_password_policy_accepts_strong_password():
    errors = validate_password_policy("Str0ng!Passw0rd")
    assert errors == []


def test_password_strength_score_increases_with_complexity():
    weak_score = password_strength_score("password")
    strong_score = password_strength_score("Str0ng!Passw0rd#2025")
    assert strong_score > weak_score


def test_username_validation():
    assert is_valid_username("valid_user1") is True
    assert is_valid_username("no") is False
    assert is_valid_username("has space") is False


def test_email_validation():
    assert is_valid_email("user@example.com") is True
    assert is_valid_email("not-an-email") is False


def test_sql_injection_attempt_in_username_does_not_break_login():
    register_user("safeuser", "safeuser@example.com", "Str0ng!Pass1", "Str0ng!Pass1")

    injection_payload = "safeuser' OR '1'='1"
    result = attempt_login(injection_payload, "anything", "127.0.0.1", "pytest-agent", "sess-inj")

    # The injection payload must not authenticate as any user, and the
    # legitimate account must remain untouched and queryable normally.
    assert result.success is False
    assert get_user_by_username("safeuser") is not None


def test_sql_injection_attempt_in_registration_username_rejected():
    result = register_user(
        "bad'; DROP TABLE users; --", "bad@example.com", "Str0ng!Pass1", "Str0ng!Pass1"
    )
    # Invalid character/format should be rejected by username policy validation.
    assert result.success is False
