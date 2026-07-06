"""
app.py
------
Main Flask application entry point for the Login Attempt Control System.

Run with:
    python app.py

The app will automatically open in your default web browser at
http://127.0.0.1:5000
"""

from __future__ import annotations

import os
import threading
import webbrowser
from datetime import datetime
from functools import wraps

from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_wtf.csrf import CSRFProtect

from auth import attempt_login, register_user
from config import Config
from database import init_db
from logger import app_logger, audit_logger
from models import (
    admin_delete_user,
    admin_lock_user,
    admin_reset_attempts,
    admin_unlock_user,
    delete_all_logs,
    delete_log,
    get_all_users,
    get_dashboard_stats,
    get_logs_for_user,
    get_recent_logs,
    get_user_by_id,
    get_user_by_username,
    search_logs,
    update_password,
)
from security import (
    login_rate_limiter,
    password_strength_score,
    strength_label,
    username_exists,
    email_exists,
)
from session_manager import end_session, start_session, touch_session
from utils import (
    ChangePasswordForm,
    LoginForm,
    RegisterForm,
    ensure_dirs,
    get_browser_info,
    get_client_ip,
    logs_to_csv,
    logs_to_pdf,
)

# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------
ensure_dirs()

app = Flask(__name__)
app.config.from_object(Config)
app.config["WTF_CSRF_TIME_LIMIT"] = None

csrf = CSRFProtect(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "warning"

init_db()


@login_manager.user_loader
def load_user(user_id: str):
    return get_user_by_id(int(user_id))


# ---------------------------------------------------------------------------
# Decorators
# ---------------------------------------------------------------------------
def admin_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("Administrator access required.", "danger")
            return redirect(url_for("dashboard"))
        return view_func(*args, **kwargs)

    return wrapper


@app.before_request
def enforce_session_activity():
    """Keep the session-activity timestamp fresh for authenticated users."""
    if current_user.is_authenticated:
        touch_session()


# ---------------------------------------------------------------------------
# Public pages
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    stats = get_dashboard_stats()
    recent_logs = get_recent_logs(limit=6)
    return render_template("index.html", stats=stats, recent_logs=recent_logs)


@app.route("/about")
def about():
    return render_template("about.html")


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    form = RegisterForm()

    if form.validate_on_submit():
        result = register_user(
            form.username.data, form.email.data, form.password.data, form.confirm_password.data
        )
        if result.success:
            flash(result.message, "success")
            return redirect(url_for("login"))
        for error in result.errors:
            flash(error, "danger")

    return render_template("register.html", form=form)


@app.route("/api/check-username")
def api_check_username():
    username = request.args.get("username", "")
    return jsonify({"available": not username_exists(username) if username else False})


@app.route("/api/check-email")
def api_check_email():
    email = request.args.get("email", "")
    return jsonify({"available": not email_exists(email) if email else False})


@app.route("/api/password-strength", methods=["POST"])
def api_password_strength():
    password = request.json.get("password", "") if request.is_json else ""
    score = password_strength_score(password)
    return jsonify({"score": score, "label": strength_label(score)})


# ---------------------------------------------------------------------------
# Login / Logout
# ---------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    form = LoginForm()
    lock_seconds_remaining = 0
    remaining_attempts = None

    if form.validate_on_submit():
        client_ip = get_client_ip(request)

        if not login_rate_limiter.is_allowed(client_ip):
            wait = login_rate_limiter.seconds_until_next_allowed(client_ip)
            flash(f"Too many login requests. Please wait {wait} seconds.", "warning")
            audit_logger.log_event("rate_limited", ip=client_ip)
            return render_template("login.html", form=form)

        result = attempt_login(
            username=form.username.data,
            password=form.password.data,
            ip_address=client_ip,
            browser=get_browser_info(request),
            session_id=session.get("session_id", "n/a"),
        )

        if result.success:
            login_user(result.user, remember=form.remember.data)
            start_session(result.user.id, remember=form.remember.data)
            flash(f"Welcome back, {result.user.username}!", "success")
            return redirect(url_for("admin_dashboard" if result.user.is_admin else "dashboard"))

        flash(result.message, "danger")
        lock_seconds_remaining = result.lock_seconds_remaining
        remaining_attempts = result.remaining_attempts

    return render_template(
        "login.html",
        form=form,
        lock_seconds_remaining=lock_seconds_remaining,
        remaining_attempts=remaining_attempts,
        max_attempts=Config.MAX_FAILED_ATTEMPTS,
    )


@app.route("/logout")
@login_required
def logout():
    username = current_user.username
    end_session()
    logout_user()
    audit_logger.log_event("logout", username=username)
    flash("You have been logged out successfully.", "info")
    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# User dashboard / profile
# ---------------------------------------------------------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    history = get_logs_for_user(current_user.username, limit=15)
    return render_template("dashboard.html", user=current_user, history=history)


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    form = ChangePasswordForm()

    if form.validate_on_submit():
        if not current_user.check_password(form.current_password.data):
            flash("Current password is incorrect.", "danger")
        else:
            from security import validate_password_policy

            errors = validate_password_policy(form.new_password.data)
            if errors:
                for e in errors:
                    flash(e, "danger")
            else:
                update_password(current_user.id, form.new_password.data)
                audit_logger.log_event("password_changed", username=current_user.username)
                flash("Password updated successfully.", "success")
                return redirect(url_for("profile"))

    history = get_logs_for_user(current_user.username, limit=10)
    return render_template("profile.html", user=current_user, history=history, form=form)


# ---------------------------------------------------------------------------
# Admin dashboard
# ---------------------------------------------------------------------------
@app.route("/admin")
@admin_required
@login_required
def admin_dashboard():
    stats = get_dashboard_stats()
    recent_logs = get_recent_logs(limit=20)
    users = get_all_users()
    return render_template("admin_dashboard.html", stats=stats, recent_logs=recent_logs, users=users)


@app.route("/admin/lock/<int:user_id>", methods=["POST"])
@admin_required
@login_required
def admin_lock(user_id: int):
    admin_lock_user(user_id)
    audit_logger.log_event("admin_lock_user", admin=current_user.username, target_id=user_id)
    flash("User account locked.", "info")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/unlock/<int:user_id>", methods=["POST"])
@admin_required
@login_required
def admin_unlock(user_id: int):
    admin_unlock_user(user_id)
    audit_logger.log_event("admin_unlock_user", admin=current_user.username, target_id=user_id)
    flash("User account unlocked.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/reset/<int:user_id>", methods=["POST"])
@admin_required
@login_required
def admin_reset(user_id: int):
    admin_reset_attempts(user_id)
    audit_logger.log_event("admin_reset_attempts", admin=current_user.username, target_id=user_id)
    flash("Failed attempt counter reset.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/delete/<int:user_id>", methods=["POST"])
@admin_required
@login_required
def admin_delete(user_id: int):
    if user_id == current_user.id:
        flash("You cannot delete your own account.", "danger")
        return redirect(url_for("admin_dashboard"))
    admin_delete_user(user_id)
    audit_logger.log_event("admin_delete_user", admin=current_user.username, target_id=user_id)
    flash("User account deleted.", "info")
    return redirect(url_for("admin_dashboard"))


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------
@app.route("/reports")
@login_required
def reports():
    username_filter = request.args.get("username", "").strip() or None
    status_filter = request.args.get("status", "").strip() or None
    start_date = request.args.get("start_date", "").strip() or None
    end_date = request.args.get("end_date", "").strip() or None

    # Non-admins may only view their own history.
    if not current_user.is_admin:
        username_filter = current_user.username

    logs = search_logs(
        username=username_filter, status=status_filter, start_date=start_date, end_date=end_date
    )
    return render_template(
        "reports.html",
        logs=logs,
        username_filter=username_filter or "",
        status_filter=status_filter or "",
        start_date=start_date or "",
        end_date=end_date or "",
    )


@app.route("/reports/export/csv")
@login_required
def export_csv():
    username_filter = request.args.get("username", "").strip() or None
    if not current_user.is_admin:
        username_filter = current_user.username
    logs = search_logs(username=username_filter)
    buffer = logs_to_csv(logs)
    return send_file(
        buffer,
        mimetype="text/csv",
        as_attachment=True,
        download_name=f"login_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv",
    )


@app.route("/reports/export/pdf")
@login_required
def export_pdf():
    username_filter = request.args.get("username", "").strip() or None
    if not current_user.is_admin:
        username_filter = current_user.username
    logs = search_logs(username=username_filter)
    buffer = logs_to_pdf(logs)
    return send_file(
        buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"login_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf",
    )


@app.route("/reports/delete/<int:log_id>", methods=["POST"])
@admin_required
@login_required
def delete_single_log(log_id: int):
    delete_log(log_id)
    flash("Log entry deleted.", "info")
    return redirect(url_for("reports"))


@app.route("/reports/delete-all", methods=["POST"])
@admin_required
@login_required
def delete_logs_all():
    delete_all_logs()
    audit_logger.log_event("admin_delete_all_logs", admin=current_user.username)
    flash("All log entries deleted.", "warning")
    return redirect(url_for("reports"))


# ---------------------------------------------------------------------------
# Chart data API (consumed by Plotly on the dashboards)
# ---------------------------------------------------------------------------
@app.route("/api/chart-data")
@login_required
def chart_data():
    stats = get_dashboard_stats()
    logs = get_recent_logs(limit=500)

    # Successful vs failed pie
    pie = {"labels": ["Successful", "Failed"], "values": [stats["successful_logins"], stats["failed_logins"]]}

    # Daily login counts (last 14 days) from recent logs
    from collections import Counter, OrderedDict

    daily_counter = Counter()
    for log in logs:
        day = log["login_time"][:10]
        daily_counter[day] += 1
    daily_sorted = OrderedDict(sorted(daily_counter.items()))

    status_by_day: dict[str, dict[str, int]] = {}
    for log in logs:
        day = log["login_time"][:10]
        status_by_day.setdefault(day, {"success": 0, "failed": 0})
        status_by_day[day][log["login_status"]] = status_by_day[day].get(log["login_status"], 0) + 1

    heatmap_hours = [0] * 24
    for log in logs:
        if log["login_status"] == "failed":
            try:
                hour = int(log["login_time"][11:13])
                heatmap_hours[hour] += 1
            except (ValueError, IndexError):
                continue

    return jsonify(
        {
            "pie": pie,
            "daily_labels": list(daily_sorted.keys()),
            "daily_values": list(daily_sorted.values()),
            "status_by_day": status_by_day,
            "heatmap_hours": heatmap_hours,
            "success_rate": stats["success_rate"],
            "top_failed_users": stats["top_failed_users"],
            "locked_accounts": stats["locked_users"],
            "active_users": stats["active_users"],
            "total_users": stats["total_users"],
        }
    )


@app.route("/api/lock-status/<username>")
def api_lock_status(username: str):
    """Polled by the login page to update the lockout countdown timer."""
    user = get_user_by_username(username)
    if not user:
        return jsonify({"locked": False})
    from models import auto_unlock_if_expired

    user = auto_unlock_if_expired(user)
    return jsonify({"locked": user.is_locked(), "seconds_remaining": user.lock_seconds_remaining()})


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------
@app.errorhandler(404)
def not_found(_e):
    return render_template("layout.html", content_404=True), 404


@app.errorhandler(500)
def server_error(e):
    app_logger.error("Internal server error: %s", e)
    flash("An unexpected error occurred. Please try again.", "danger")
    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# Browser auto-launch + entry point
# ---------------------------------------------------------------------------
def _open_browser() -> None:
    webbrowser.open(f"http://{Config.HOST}:{Config.PORT}/")


if __name__ == "__main__":
    if not os.environ.get("WERKZEUG_RUN_MAIN"):
        threading.Timer(1.25, _open_browser).start()
    app.run(host=Config.HOST, port=Config.PORT, debug=Config.DEBUG)
