"""
logger.py
---------
Centralized logging configuration for the application.

Provides two loggers:
    - `app_logger`   : general application / error logging.
    - `audit_logger` : dedicated security audit trail (authentication
                       events, lockouts, admin actions, etc.) written as
                       structured JSON lines for easy downstream parsing.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler

from config import Config

os.makedirs(Config.LOG_DIR, exist_ok=True)


def _build_app_logger() -> logging.Logger:
    logger = logging.getLogger("lacs.app")
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        formatter = logging.Formatter(
            "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
        )
        file_handler = RotatingFileHandler(
            Config.LOG_FILE, maxBytes=1_000_000, backupCount=5
        )
        file_handler.setFormatter(formatter)

        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)

        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

    return logger


app_logger = _build_app_logger()


class AuditLogger:
    """
    Writes structured (JSON-lines) audit records for every authentication
    and security-relevant event. Kept separate from the general application
    log so it can be shipped to a SIEM or reviewed independently.
    """

    def __init__(self, path: str) -> None:
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)

    def log_event(self, event_type: str, **details: object) -> None:
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            **details,
        }
        try:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, default=str) + "\n")
        except OSError as exc:  # pragma: no cover - filesystem edge case
            app_logger.error("Failed to write audit log entry: %s", exc)


audit_logger = AuditLogger(Config.AUDIT_LOG_FILE)
