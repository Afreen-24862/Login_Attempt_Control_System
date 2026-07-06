"""
config.py
---------
Central configuration module for the Login Attempt Control System.

All tunable security parameters (max failed attempts, lockout duration,
session timeout, etc.) live here so they can be adjusted without
touching business logic elsewhere in the codebase.
"""

import os
import secrets
from datetime import timedelta

# ---------------------------------------------------------------------------
# Base directory
# ---------------------------------------------------------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    """Base configuration shared by all environments."""

    # Flask secret key used for session signing & CSRF tokens.
    # In production this should be set via an environment variable.
    SECRET_KEY: str = os.environ.get("SECRET_KEY", secrets.token_hex(32))

    # ------------------------------------------------------------------
    # Database
    # ------------------------------------------------------------------
    DATABASE_PATH: str = os.path.join(BASE_DIR, "database", "app.db")

    # ------------------------------------------------------------------
    # Brute-force protection / account lockout policy
    # ------------------------------------------------------------------
    MAX_FAILED_ATTEMPTS: int = 5
    LOCKOUT_DURATION_MINUTES: int = 5
    LOCKOUT_DURATION_SECONDS: int = LOCKOUT_DURATION_MINUTES * 60

    # ------------------------------------------------------------------
    # Rate limiting (per IP, sliding window) for the login endpoint
    # ------------------------------------------------------------------
    RATE_LIMIT_WINDOW_SECONDS: int = 60
    RATE_LIMIT_MAX_REQUESTS: int = 10

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------
    PERMANENT_SESSION_LIFETIME: timedelta = timedelta(minutes=30)
    REMEMBER_COOKIE_DURATION: timedelta = timedelta(days=7)
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = "Lax"
    # Secure cookies should be True when served over HTTPS in production.
    SESSION_COOKIE_SECURE: bool = False

    # ------------------------------------------------------------------
    # Password policy
    # ------------------------------------------------------------------
    PASSWORD_MIN_LENGTH: int = 8
    PASSWORD_REQUIRE_UPPERCASE: bool = True
    PASSWORD_REQUIRE_LOWERCASE: bool = True
    PASSWORD_REQUIRE_DIGIT: bool = True
    PASSWORD_REQUIRE_SPECIAL: bool = True

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------
    LOG_DIR: str = os.path.join(BASE_DIR, "logs")
    LOG_FILE: str = os.path.join(LOG_DIR, "app.log")
    AUDIT_LOG_FILE: str = os.path.join(LOG_DIR, "audit.log")

    # ------------------------------------------------------------------
    # Reports
    # ------------------------------------------------------------------
    REPORTS_DIR: str = os.path.join(BASE_DIR, "reports")

    # ------------------------------------------------------------------
    # Application / server
    # ------------------------------------------------------------------
    HOST: str = "127.0.0.1"
    PORT: int = 5000
    DEBUG: bool = True

    # Default administrator account (created automatically on first run)
    DEFAULT_ADMIN_USERNAME: str = "admin"
    DEFAULT_ADMIN_EMAIL: str = "admin@lacs.local"
    DEFAULT_ADMIN_PASSWORD: str = "Admin@12345"


class DevelopmentConfig(Config):
    DEBUG = True


class TestingConfig(Config):
    """Configuration used exclusively by the pytest suite."""

    TESTING = True
    DEBUG = False
    DATABASE_PATH = os.path.join(BASE_DIR, "database", "test_app.db")
    WTF_CSRF_ENABLED = False
    MAX_FAILED_ATTEMPTS = 3
    LOCKOUT_DURATION_SECONDS = 3


class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True


config_map = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
}
