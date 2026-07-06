"""
utils.py
--------
Miscellaneous helper utilities: request metadata extraction (IP/browser),
CSV/PDF report generation, and WTForms form definitions used across the
application.
"""

from __future__ import annotations

import csv
import io
import os
from datetime import datetime

from flask import Request
from flask_wtf import FlaskForm
from wtforms import BooleanField, PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length

from config import Config


# ---------------------------------------------------------------------------
# Request metadata
# ---------------------------------------------------------------------------
def get_client_ip(request: Request) -> str:
    """Return the best-guess client IP, honoring X-Forwarded-For if present."""
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def get_browser_info(request: Request) -> str:
    """Return a concise browser/OS description derived from the User-Agent header."""
    ua = request.user_agent
    browser = ua.browser or "Unknown"
    version = ua.version or ""
    platform = ua.platform or "Unknown"
    return f"{browser.capitalize()} {version} on {platform.capitalize()}"


# ---------------------------------------------------------------------------
# WTForms definitions (CSRF protected automatically via FlaskForm)
# ---------------------------------------------------------------------------
class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=20)])
    password = PasswordField("Password", validators=[DataRequired()])
    remember = BooleanField("Remember Me")
    submit = SubmitField("Login")


class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=20)])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[DataRequired(), EqualTo("password", message="Passwords must match.")],
    )
    submit = SubmitField("Register")


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField("Current Password", validators=[DataRequired()])
    new_password = PasswordField("New Password", validators=[DataRequired(), Length(min=8)])
    confirm_new_password = PasswordField(
        "Confirm New Password",
        validators=[DataRequired(), EqualTo("new_password", message="Passwords must match.")],
    )
    submit = SubmitField("Change Password")


# ---------------------------------------------------------------------------
# CSV export
# ---------------------------------------------------------------------------
def logs_to_csv(logs: list[dict]) -> io.BytesIO:
    """Serialize a list of login-log dict rows to an in-memory CSV file."""
    buffer = io.StringIO()
    fieldnames = [
        "id",
        "user_id",
        "username",
        "login_time",
        "ip_address",
        "browser",
        "login_status",
        "failure_reason",
        "session_id",
    ]
    writer = csv.DictWriter(buffer, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for row in logs:
        writer.writerow(row)

    byte_buffer = io.BytesIO(buffer.getvalue().encode("utf-8"))
    byte_buffer.seek(0)
    return byte_buffer


# ---------------------------------------------------------------------------
# PDF export (lightweight, dependency: reportlab)
# ---------------------------------------------------------------------------
def logs_to_pdf(logs: list[dict]) -> io.BytesIO:
    """Render a list of login-log dict rows into a simple tabular PDF report."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import landscape, A4
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(A4))
    styles = getSampleStyleSheet()

    elements = [
        Paragraph("Login Attempt Control System — Login History Report", styles["Title"]),
        Paragraph(f"Generated: {datetime.utcnow().isoformat()} UTC", styles["Normal"]),
        Spacer(1, 10 * mm),
    ]

    header = ["ID", "Username", "Time", "IP Address", "Browser", "Status", "Reason"]
    data = [header]
    for row in logs:
        data.append(
            [
                row.get("id", ""),
                row.get("username", ""),
                row.get("login_time", ""),
                row.get("ip_address", ""),
                (row.get("browser") or "")[:25],
                row.get("login_status", ""),
                row.get("failure_reason") or "-",
            ]
        )

    table = Table(data, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0d1b2a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f0f4f8")]),
            ]
        )
    )
    elements.append(table)
    doc.build(elements)

    buffer.seek(0)
    return buffer


def ensure_dirs() -> None:
    os.makedirs(Config.REPORTS_DIR, exist_ok=True)
    os.makedirs(Config.LOG_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(Config.DATABASE_PATH), exist_ok=True)
