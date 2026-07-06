"""
conftest.py
-----------
Shared pytest fixtures for the LoginGuard test suite.

Uses a dedicated, isolated SQLite test database (test_app.db) that is
created fresh before each test and removed afterward, so tests never
touch the real application database.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest

from config import Config, TestingConfig

# Point the shared Config at the testing database/lockout values BEFORE
# importing any module that reads Config values at import time.
Config.DATABASE_PATH = TestingConfig.DATABASE_PATH
Config.MAX_FAILED_ATTEMPTS = TestingConfig.MAX_FAILED_ATTEMPTS
Config.LOCKOUT_DURATION_SECONDS = TestingConfig.LOCKOUT_DURATION_SECONDS

from database import init_db  # noqa: E402


@pytest.fixture(autouse=True)
def fresh_test_database():
    """Ensure a clean database before every test function."""
    db_path = TestingConfig.DATABASE_PATH
    if os.path.exists(db_path):
        os.remove(db_path)
    init_db(db_path)
    yield
    if os.path.exists(db_path):
        os.remove(db_path)


@pytest.fixture
def app():
    """Provide a Flask app instance configured for testing."""
    import app as app_module

    app_module.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    yield app_module.app


@pytest.fixture
def client(app):
    return app.test_client()
