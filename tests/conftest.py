from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

import pytest


@pytest.fixture()
def app_module(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    project_root = Path(__file__).resolve().parents[1]
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    # Ensure environment is deterministic for each test run.
    monkeypatch.setenv("FLASK_SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("BACKUPLIFE_APP_KEY", "test-app-key")
    monkeypatch.setenv("BACKUPLIFE_DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("BACKUPLIFE_UPLOAD_DIR", str(tmp_path / "uploads"))
    monkeypatch.setenv("HOST", "127.0.0.1")
    monkeypatch.setenv("PORT", "8001")

    # Reload the module so its global create_app_instance uses our env for encryption/db paths.
    if "app" in sys.modules:
        del sys.modules["app"]
    module = importlib.import_module("app")
    return module


@pytest.fixture()
def app(app_module):
    app = app_module.create_app()
    app.testing = True
    return app


def _get_csrf(client) -> str:
    with client.session_transaction() as sess:
        token = sess.get("_csrf_token")
    assert token, "CSRF token missing from session"
    return str(token)


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def csrf_token(client) -> str:
    # Ensure token exists by doing a GET first.
    client.get("/")
    with client.session_transaction() as sess:
        token = sess.get("_csrf_token")
    assert token
    return str(token)


@pytest.fixture()
def initialized_admin(app, app_module):
    # Create initial admin (system initialized) and mark as verified to avoid lockouts.
    with app.test_request_context("/setup"):
        from flask import g

        g.db = app_module.get_db(app)
        app_module.init_db(app)
        user_id = app_module.create_user_with_profile(
            "Admin",
            "admin@example.com",
            "very-secure-password",
            "admin",
            None,
        )
        g.db.execute(
            "UPDATE users SET email_verified_at = ? WHERE id = ?",
            (app_module.utcnow(), user_id),
        )
        g.db.commit()
        g.db.close()
    return {"email": "admin@example.com", "password": "very-secure-password"}


@pytest.fixture()
def logged_in_admin(client, app, initialized_admin, app_module):
    # GET first so CSRF token is created and stored in the session.
    client.get("/login")
    token = _get_csrf(client)
    resp = client.post(
        "/login",
        data={
            "csrf_token": token,
            "email": initialized_admin["email"],
            "password": initialized_admin["password"],
        },
        follow_redirects=False,
        headers={"X-Forwarded-For": "203.0.113.10"},
    )
    assert resp.status_code in (302, 303)
    return client


@pytest.fixture()
def creator_user(app, app_module):
    with app.test_request_context("/setup"):
        from flask import g

        g.db = app_module.get_db(app)
        app_module.init_db(app)
        user_id = app_module.create_user_with_profile(
            "Creator",
            "creator@example.com",
            "very-secure-password",
            "creator",
            None,
        )
        g.db.execute(
            "UPDATE users SET email_verified_at = ? WHERE id = ?",
            (app_module.utcnow(), user_id),
        )
        profile = g.db.execute("SELECT * FROM profiles WHERE owner_user_id = ?", (user_id,)).fetchone()
        g.db.commit()
        g.db.close()
    assert profile
    return {
        "email": "creator@example.com",
        "password": "very-secure-password",
        "slug": profile["slug"],
    }


@pytest.fixture()
def logged_in_creator(client, creator_user):
    client.get("/login")
    token = _get_csrf(client)
    resp = client.post(
        "/login",
        data={
            "csrf_token": token,
            "email": creator_user["email"],
            "password": creator_user["password"],
        },
        follow_redirects=False,
        headers={"X-Forwarded-For": "203.0.113.11"},
    )
    assert resp.status_code in (302, 303)
    return client
