"""Tests for user registration behavior."""

from auth import register_user
from models import get_user_by_username


def test_successful_registration():
    result = register_user("alice01", "alice@example.com", "Str0ng!Pass", "Str0ng!Pass")
    assert result.success is True
    assert get_user_by_username("alice01") is not None


def test_registration_password_mismatch():
    result = register_user("bob02", "bob@example.com", "Str0ng!Pass", "Different!1")
    assert result.success is False
    assert any("match" in e.lower() for e in result.errors)


def test_registration_weak_password_rejected():
    result = register_user("carol03", "carol@example.com", "weak", "weak")
    assert result.success is False
    assert len(result.errors) > 0


def test_registration_duplicate_username_rejected():
    register_user("dave04", "dave@example.com", "Str0ng!Pass", "Str0ng!Pass")
    result = register_user("dave04", "dave2@example.com", "Str0ng!Pass", "Str0ng!Pass")
    assert result.success is False
    assert any("username" in e.lower() for e in result.errors)


def test_registration_duplicate_email_rejected():
    register_user("erin05", "erin@example.com", "Str0ng!Pass", "Str0ng!Pass")
    result = register_user("erin06", "erin@example.com", "Str0ng!Pass", "Str0ng!Pass")
    assert result.success is False
    assert any("email" in e.lower() for e in result.errors)


def test_registration_invalid_email_rejected():
    result = register_user("frank06", "not-an-email", "Str0ng!Pass", "Str0ng!Pass")
    assert result.success is False
    assert any("email" in e.lower() for e in result.errors)


def test_registration_invalid_username_rejected():
    result = register_user("a!", "grace@example.com", "Str0ng!Pass", "Str0ng!Pass")
    assert result.success is False
