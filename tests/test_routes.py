"""Tests for Flask route access control and session behavior."""

from auth import register_user


def _register(client_username="routeuser"):
    register_user(client_username, f"{client_username}@example.com", "Str0ng!Pass1", "Str0ng!Pass1")


def test_home_page_loads(client):
    response = client.get("/")
    assert response.status_code == 200


def test_about_page_loads(client):
    response = client.get("/about")
    assert response.status_code == 200


def test_login_page_loads(client):
    response = client.get("/login")
    assert response.status_code == 200


def test_register_page_loads(client):
    response = client.get("/register")
    assert response.status_code == 200


def test_dashboard_requires_login_redirects(client):
    response = client.get("/dashboard", follow_redirects=False)
    assert response.status_code in (301, 302)
    assert "/login" in response.headers.get("Location", "")


def test_admin_dashboard_requires_login_redirects(client):
    response = client.get("/admin", follow_redirects=False)
    assert response.status_code in (301, 302)


def test_login_flow_and_dashboard_access(client):
    _register("routeuser")
    login_response = client.post(
        "/login",
        data={"username": "routeuser", "password": "Str0ng!Pass1"},
        follow_redirects=True,
    )
    assert login_response.status_code == 200

    dashboard_response = client.get("/dashboard")
    assert dashboard_response.status_code == 200


def test_non_admin_cannot_access_admin_dashboard(client):
    _register("regularuser")
    client.post(
        "/login",
        data={"username": "regularuser", "password": "Str0ng!Pass1"},
        follow_redirects=True,
    )
    response = client.get("/admin", follow_redirects=True)
    # Non-admins are redirected back to their own dashboard with a flash message.
    assert response.status_code == 200
    assert b"Administrator access required" in response.data or b"Dashboard" in response.data


def test_admin_login_can_access_admin_dashboard(client):
    # The default admin account is seeded automatically by init_db().
    client.post(
        "/login",
        data={"username": "admin", "password": "Admin@12345"},
        follow_redirects=True,
    )
    response = client.get("/admin")
    assert response.status_code == 200


def test_logout_clears_session(client):
    _register("logoutuser")
    client.post(
        "/login",
        data={"username": "logoutuser", "password": "Str0ng!Pass1"},
        follow_redirects=True,
    )
    client.get("/logout")
    response = client.get("/dashboard", follow_redirects=False)
    assert response.status_code in (301, 302)
