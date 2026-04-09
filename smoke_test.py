from __future__ import annotations

import io
import os
import sqlite3
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path


TMP_DIR = tempfile.TemporaryDirectory()
os.environ["AETERNA_DB_PATH"] = str(Path(TMP_DIR.name) / "smoke.db")
os.environ["AETERNA_UPLOAD_DIR"] = str(Path(TMP_DIR.name) / "uploads")
os.environ["FLASK_SECRET_KEY"] = "smoke-secret"
os.environ["AETERNA_APP_KEY"] = "smoke-app-key"

from app import create_app  # noqa: E402


def get_db_path(app) -> Path:
    return app.config["DB_PATH"]


def fetch_slug(app, email: str) -> str:
    db = sqlite3.connect(get_db_path(app))
    db.row_factory = sqlite3.Row
    row = db.execute(
        """
        SELECT profiles.slug
        FROM profiles
        JOIN users ON users.id = profiles.owner_user_id
        WHERE users.email = ?
        """,
        (email,),
    ).fetchone()
    db.close()
    assert row is not None
    return row["slug"]


def run() -> None:
    app = create_app()
    app.testing = True
    client = app.test_client()

    def get_csrf() -> str:
        with client.session_transaction() as sess:
            token = sess.get("_csrf_token")
        assert token
        return str(token)

    suffix = uuid.uuid4().hex[:8]
    admin_email = f"admin-{suffix}@example.local"
    reader_email = f"eva-{suffix}@example.local"

    client.get("/setup")
    response = client.post(
        "/setup",
        data={
            "csrf_token": get_csrf(),
            "display_name": "Admin Person",
            "email": admin_email,
            "password": "supersecure123",
            "password_confirm": "supersecure123",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert "Dashboard".encode() in response.data

    # Smoke test should stay self-contained: disable email verification requirement.
    db = sqlite3.connect(get_db_path(app))
    db.execute("UPDATE app_settings SET require_email_verification = 0 WHERE id = 1")
    db.commit()
    db.close()

    client.get("/verwaltung")
    response = client.post(
        "/verwaltung/benutzer/neu",
        data={
            "csrf_token": get_csrf(),
            "display_name": "Leserin Eva",
            "email": reader_email,
            "password": "sehrsicher123",
            "role": "reader",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200

    db = sqlite3.connect(get_db_path(app))
    db.execute(
        "UPDATE users SET email_verified_at = ? WHERE email = ?",
        (datetime.now(timezone.utc).isoformat(), reader_email),
    )
    db.commit()
    db.close()

    admin_slug = fetch_slug(app, admin_email)

    client.get(f"/digitaler-nachlass/{admin_slug}/online_accounts")
    response = client.post(
        f"/digitaler-nachlass/{admin_slug}/online_accounts/neu",
        data={
            "csrf_token": get_csrf(),
            "title": "Facebook",
            "provider": "Meta",
            "website": "https://facebook.com",
            "account_username": "admin-account",
            "account_password": "secret-passwort",
            "reference_number": "FB-01",
            "location_info": "Digital",
            "contact_info": "support@example.com",
            "details": "Wichtiger Account",
            "notes": "Bitte prüfen",
            "is_2fa_enabled": "on",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert "Facebook".encode() in response.data

    client.get(f"/digitaler-nachlass/{admin_slug}/documents")
    response = client.post(
        f"/dokumente/{admin_slug}/upload",
        data={
            "csrf_token": get_csrf(),
            "category_key": "documents",
            "title": "Versicherungspolice",
            "description": "Beispieldatei",
            "document": (io.BytesIO(b"pdf-content"), "police.pdf"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert response.status_code == 200

    client.get(f"/letzte-wuensche/{admin_slug}")
    response = client.post(
        f"/letzte-wuensche/{admin_slug}",
        data={
            "csrf_token": get_csrf(),
            "farewell_message": "Alles Liebe.",
            "asset_notes": "Eigentum laut Liste aufteilen.",
            "ceremony_notes": "Kleine Feier im Familienkreis.",
            "important_contacts": "Notar, Familie, Freunde",
            "external_links": "https://www.affilio.de",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200

    db = sqlite3.connect(get_db_path(app))
    db.row_factory = sqlite3.Row
    eva = db.execute("SELECT id FROM users WHERE email = ?", (reader_email,)).fetchone()
    db.close()
    assert eva is not None

    client.get("/verwaltung")
    response = client.post(
        "/verwaltung/freigaben/neu",
        data={"csrf_token": get_csrf(), "grantee_user_id": str(eva["id"]), "category_key": "online_accounts"},
        follow_redirects=True,
    )
    assert response.status_code == 200

    response = client.get(f"/export/{admin_slug}")
    assert response.status_code == 200
    assert "Facebook".encode() in response.data

    client.get("/logout", follow_redirects=True)

    client.get("/login")
    response = client.post(
        "/login",
        data={"csrf_token": get_csrf(), "email": reader_email, "password": "sehrsicher123"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    response = client.get(f"/digitaler-nachlass/{admin_slug}/online_accounts")
    assert response.status_code == 200
    assert "Facebook".encode() in response.data

    response = client.get(f"/digitaler-nachlass/{admin_slug}/contracts")
    assert response.status_code == 403

    print("Smoke-Test erfolgreich.")


if __name__ == "__main__":
    run()
