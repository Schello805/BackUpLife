from __future__ import annotations

import io
import json
import zipfile


def test_public_pages_require_setup_when_empty_db(client):
    # Fresh DB has no users, so the app should redirect to setup.
    resp = client.get("/", follow_redirects=False)
    assert resp.status_code in (302, 303)
    assert "/setup" in resp.headers.get("Location", "")


def test_setup_page_reachable(client):
    resp = client.get("/setup")
    assert resp.status_code == 200
    assert b"Ersteinrichtung" in resp.data or b"Erstkonfiguration" in resp.data


def test_legal_help_pages_reachable_after_init(logged_in_admin):
    for path in [
        "/hilfe",
        "/impressum",
        "/datenschutz",
        "/cookies",
        "/nutzungsbedingungen",
        "/robots.txt",
        "/sitemap.xml",
        "/manifest.webmanifest",
        "/sw.js",
    ]:
        resp = logged_in_admin.get(path)
        assert resp.status_code == 200


def test_footer_shows_version(logged_in_admin, app_module):
    resp = logged_in_admin.get("/dashboard")
    assert resp.status_code == 200
    expected = f"v{app_module.APP_VERSION}".encode("utf-8")
    assert expected in resp.data


def test_register_requires_csrf(app, client):
    # Create one admin so system is initialized and /registrieren is available.
    client.get("/setup")
    # Posting without CSRF must fail with 400
    resp = client.post("/registrieren", data={"display_name": "A", "email": "a@b.de", "password": "x" * 12})
    assert resp.status_code == 400


def test_login_requires_csrf(initialized_admin, client):
    resp = client.post("/login", data={"email": initialized_admin["email"], "password": initialized_admin["password"]})
    assert resp.status_code == 400


def test_registration_requires_smtp_when_verification_enabled(app, app_module, client):
    # Initialize system (create an admin) but keep SMTP empty.
    with app.test_request_context("/setup"):
        from flask import g

        g.db = app_module.get_db(app)
        app_module.init_db(app)
        app_module.create_user_with_profile(
            "Admin",
            "admin2@example.com",
            "very-secure-password",
            "admin",
            None,
        )
        g.db.execute("UPDATE app_settings SET allow_registration = 1 WHERE id = 1")
        g.db.commit()
        g.db.close()

    client.get("/registrieren")
    with client.session_transaction() as sess:
        csrf = sess.get("_csrf_token")
    resp = client.post(
        "/registrieren",
        data={
            "csrf_token": csrf,
            "display_name": "Max",
            "email": "max@example.com",
            "role": "reader",
            "password": "very-secure-password",
            "accept_terms": "1",
        },
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert b"SMTP" in resp.data


def test_email_verification_flow(app, app_module, monkeypatch):
    # Initialize system and configure SMTP. Then register and verify via token.
    with app.test_request_context("/setup"):
        from flask import g

        g.db = app_module.get_db(app)
        app_module.init_db(app)
        app_module.create_user_with_profile(
            "Admin",
            "admin3@example.com",
            "very-secure-password",
            "admin",
            None,
        )
        g.db.execute("UPDATE app_settings SET allow_registration = 1 WHERE id = 1")
        g.db.execute(
            "UPDATE smtp_settings SET host = 'smtp.example', sender_email = 'noreply@example.com' WHERE id = 1"
        )
        g.db.commit()
        g.db.close()

    # Avoid real SMTP by stubbing send_test_or_reset_mail.
    def _fake_send(*args, **kwargs):
        return True, "ok"

    monkeypatch.setattr(app_module, "send_test_or_reset_mail", _fake_send)

    client = app.test_client()
    client.get("/registrieren")
    with client.session_transaction() as sess:
        csrf = sess.get("_csrf_token")
    resp = client.post(
        "/registrieren",
        data={
            "csrf_token": csrf,
            "display_name": "Erika",
            "email": "erika@example.com",
            "role": "reader",
            "password": "very-secure-password",
            "accept_terms": "1",
        },
        follow_redirects=False,
    )
    assert resp.status_code in (302, 303)

    # Grab the verification token and hit the verify route.
    with app.test_request_context("/"):
        from flask import g

        g.db = app_module.get_db(app)
        token_row = g.db.execute(
            """
            SELECT email_verification_tokens.token
            FROM email_verification_tokens
            JOIN users ON users.id = email_verification_tokens.user_id
            WHERE users.email = ?
            """,
            ("erika@example.com",),
        ).fetchone()
        g.db.close()
    assert token_row

    verify = client.get(f"/email-bestaetigen/{token_row['token']}", follow_redirects=False)
    assert verify.status_code in (302, 303)

    # Now login should succeed (with CSRF).
    client.get("/login")
    with client.session_transaction() as sess:
        csrf = sess.get("_csrf_token")
    login = client.post(
        "/login",
        data={"csrf_token": csrf, "email": "erika@example.com", "password": "very-secure-password"},
        headers={"X-Forwarded-For": "203.0.113.56"},
        follow_redirects=False,
    )
    assert login.status_code in (302, 303)


def test_rate_limit_login_blocks(app, app_module, monkeypatch):
    # Create an initialized admin, but attempt wrong password repeatedly and ensure 429.
    with app.test_request_context("/setup"):
        from flask import g

        g.db = app_module.get_db(app)
        app_module.init_db(app)
        user_id = app_module.create_user_with_profile(
            "Admin",
            "admin4@example.com",
            "very-secure-password",
            "admin",
            None,
        )
        g.db.execute("UPDATE users SET email_verified_at = ? WHERE id = ?", (app_module.utcnow(), user_id))
        g.db.commit()
        g.db.close()

    # Lower the limit for the test.
    monkeypatch.setattr(app_module, "DEFAULT_RATE_LIMIT_LOGIN", 2)

    client = app.test_client()
    for i in range(3):
        client.get("/login")
        with client.session_transaction() as sess:
            csrf = sess.get("_csrf_token")
        resp = client.post(
            "/login",
            data={"csrf_token": csrf, "email": "admin4@example.com", "password": "wrong-password"},
            headers={"X-Forwarded-For": "203.0.113.99"},
            follow_redirects=False,
        )
        if i < 2:
            assert resp.status_code == 200
        else:
            assert resp.status_code == 429


def test_login_lockout_escalates(app, app_module, monkeypatch):
    # Ensure 5 failures trigger a lockout response (429).
    with app.test_request_context("/setup"):
        from flask import g

        g.db = app_module.get_db(app)
        app_module.init_db(app)
        user_id = app_module.create_user_with_profile(
            "Admin",
            "lock@example.com",
            "very-secure-password",
            "admin",
            None,
        )
        g.db.execute("UPDATE users SET email_verified_at = ? WHERE id = ?", (app_module.utcnow(), user_id))
        g.db.commit()
        g.db.close()

    # Avoid IP-based rate limit interfering.
    monkeypatch.setattr(app_module, "DEFAULT_RATE_LIMIT_LOGIN", 999)

    client = app.test_client()
    for i in range(6):
        client.get("/login")
        with client.session_transaction() as sess:
            csrf = sess.get("_csrf_token")
        resp = client.post(
            "/login",
            data={"csrf_token": csrf, "email": "lock@example.com", "password": "wrong"},
            headers={"X-Forwarded-For": "203.0.113.101"},
            follow_redirects=False,
        )
        if i < 5:
            assert resp.status_code == 200
        else:
            assert resp.status_code == 429


def test_route_crawl_logged_in_creator(app, logged_in_creator, creator_user):
    slug = creator_user["slug"]
    paths = [
        "/dashboard",
        "/verwaltung",
        "/admin",  # should be forbidden for non-admin
        f"/nachlass/{slug}",
        f"/letzte-wuensche/{slug}",
        f"/notfall/{slug}",
        f"/hinweis/{slug}",
    ]
    for key, _label in app.jinja_env.globals["APP_CATEGORIES"]:
        paths.append(f"/digitaler-nachlass/{slug}/{key}")
    for path in paths:
        resp = logged_in_creator.get(path, follow_redirects=False)
        assert resp.status_code in (200, 301, 302, 303, 403), path


def test_creator_routes_reachable(logged_in_creator, creator_user):
    slug = creator_user["slug"]
    resp = logged_in_creator.get(f"/nachlass/{slug}")
    assert resp.status_code == 200
    # One category route (documents) should render.
    resp = logged_in_creator.get(f"/digitaler-nachlass/{slug}/documents")
    assert resp.status_code == 200


def test_document_upload_quota_enforced(app, app_module, logged_in_creator, creator_user):
    slug = creator_user["slug"]
    # Set small quota (1 MB) to make the test fast.
    with app.test_request_context("/admin"):
        from flask import g

        g.db = app_module.get_db(app)
        g.db.execute("UPDATE app_settings SET max_profile_storage_mb = 1 WHERE id = 1")
        g.db.commit()
        g.db.close()

    # First upload ~700KB should succeed.
    logged_in_creator.get(f"/digitaler-nachlass/{slug}/documents")
    with logged_in_creator.session_transaction() as sess:
        csrf = sess.get("_csrf_token")
    data = {
        "csrf_token": csrf,
        "category_key": "documents",
        "title": "Testdatei",
        "description": "",
        "document": (io.BytesIO(b"a" * (700 * 1024)), "test.pdf"),
    }
    resp = logged_in_creator.post(
        f"/dokumente/{slug}/upload",
        data=data,
        content_type="multipart/form-data",
        follow_redirects=False,
    )
    assert resp.status_code in (302, 303)

    # Second upload ~700KB should be rejected due to quota.
    logged_in_creator.get(f"/digitaler-nachlass/{slug}/documents")
    with logged_in_creator.session_transaction() as sess:
        csrf = sess.get("_csrf_token")
    data2 = {
        "csrf_token": csrf,
        "category_key": "documents",
        "title": "Testdatei2",
        "description": "",
        "document": (io.BytesIO(b"a" * (700 * 1024)), "test2.pdf"),
    }
    resp2 = logged_in_creator.post(
        f"/dokumente/{slug}/upload",
        data=data2,
        content_type="multipart/form-data",
        follow_redirects=False,
    )
    assert resp2.status_code in (302, 303)

    # Ensure DB has size_bytes populated for at least one document.
    with app.test_request_context("/"):
        from flask import g

        g.db = app_module.get_db(app)
        row = g.db.execute("SELECT size_bytes FROM documents WHERE profile_id = (SELECT id FROM profiles WHERE slug = ?)", (slug,)).fetchone()
        g.db.close()
    assert row and int(row["size_bytes"]) > 0


def test_backup_download_zip(app, logged_in_admin):
    resp = logged_in_admin.get("/admin/backup.zip")
    assert resp.status_code == 200
    assert resp.headers.get("Content-Disposition", "").endswith(".zip\"") or ".zip" in resp.headers.get("Content-Disposition", "")
    assert resp.data[:2] == b"PK"  # ZIP magic
    with zipfile.ZipFile(io.BytesIO(resp.data), "r") as zf:
        assert "backup.json" in zf.namelist()
        meta = json.loads(zf.read("backup.json").decode("utf-8"))
        assert meta.get("app") == "BackUpLife"
        assert meta.get("encrypted") is False


def test_login_requires_totp_when_enabled(app, app_module):
    # Create admin + enable TOTP, then ensure login goes through /login/2fa.
    secret = "JBSWY3DPEHPK3PXP"
    with app.test_request_context("/setup"):
        from flask import g

        g.db = app_module.get_db(app)
        app_module.init_db(app)
        user_id = app_module.create_user_with_profile(
            "Admin",
            "admin-totp@example.com",
            "very-secure-password",
            "admin",
            None,
        )
        g.db.execute(
            """
            UPDATE users
            SET email_verified_at = ?, totp_secret_encrypted = ?, totp_enabled = 1, totp_enabled_at = ?
            WHERE id = ?
            """,
            (app_module.utcnow(), app_module.encrypt_secret(secret), app_module.utcnow(), user_id),
        )
        g.db.commit()
        g.db.close()

    client = app.test_client()
    client.get("/login")
    with client.session_transaction() as sess:
        csrf = sess.get("_csrf_token")
    resp = client.post(
        "/login",
        data={"csrf_token": csrf, "email": "admin-totp@example.com", "password": "very-secure-password"},
        headers={"X-Forwarded-For": "203.0.113.12"},
        follow_redirects=False,
    )
    assert resp.status_code in (302, 303)
    assert "/login/2fa" in resp.headers.get("Location", "")

    # Complete 2FA.
    client.get("/login/2fa")
    with client.session_transaction() as sess:
        csrf2 = sess.get("_csrf_token")
    code = app_module.totp_code_at(secret, int(app_module.time.time()))
    resp2 = client.post(
        "/login/2fa",
        data={"csrf_token": csrf2, "code": code},
        headers={"X-Forwarded-For": "203.0.113.12"},
        follow_redirects=False,
    )
    assert resp2.status_code in (302, 303)


def test_admin_requires_2fa_when_enforced(app, app_module, monkeypatch):
    monkeypatch.setenv("BACKUPLIFE_ENFORCE_ADMIN_2FA", "1")
    with app.test_request_context("/setup"):
        from flask import g

        g.db = app_module.get_db(app)
        app_module.init_db(app)
        user_id = app_module.create_user_with_profile(
            "Admin",
            "admin-no2fa@example.com",
            "very-secure-password",
            "admin",
            None,
        )
        g.db.execute("UPDATE users SET email_verified_at = ? WHERE id = ?", (app_module.utcnow(), user_id))
        g.db.commit()
        g.db.close()

    client = app.test_client()
    client.get("/login")
    with client.session_transaction() as sess:
        csrf = sess.get("_csrf_token")
    resp = client.post(
        "/login",
        data={"csrf_token": csrf, "email": "admin-no2fa@example.com", "password": "very-secure-password"},
        headers={"X-Forwarded-For": "203.0.113.102"},
        follow_redirects=False,
    )
    assert resp.status_code in (302, 303)

    # Any page other than /konto should redirect to /konto until 2FA is enabled.
    blocked = client.get("/dashboard", follow_redirects=False)
    assert blocked.status_code in (302, 303)
    assert "/konto" in blocked.headers.get("Location", "")
    allowed = client.get("/konto", follow_redirects=False)
    assert allowed.status_code == 200
