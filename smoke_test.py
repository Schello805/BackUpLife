from __future__ import annotations

import io
import os
import sqlite3
import tempfile
import uuid
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

    suffix = uuid.uuid4().hex[:8]
    admin_email = f"admin-{suffix}@example.local"
    reader_email = f"eva-{suffix}@example.local"

    response = client.post(
        "/setup",
        data={
            "display_name": "Admin Person",
            "email": admin_email,
            "password": "supersecure123",
            "password_confirm": "supersecure123",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert "Dashboard".encode() in response.data

    response = client.post(
        "/verwaltung/benutzer/neu",
        data={
            "display_name": "Leserin Eva",
            "email": reader_email,
            "password": "sehrsicher123",
            "role": "reader",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200

    admin_slug = fetch_slug(app, admin_email)

    response = client.post(
        f"/digitaler-nachlass/{admin_slug}/online_accounts/neu",
        data={
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

    response = client.post(
        f"/dokumente/{admin_slug}/upload",
        data={
            "category_key": "documents",
            "title": "Versicherungspolice",
            "description": "Beispieldatei",
            "document": (io.BytesIO(b"pdf-content"), "police.pdf"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert response.status_code == 200

    response = client.post(
        f"/letzte-wuensche/{admin_slug}",
        data={
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

    response = client.post(
        "/verwaltung/freigaben/neu",
        data={"grantee_user_id": str(eva["id"]), "category_key": "online_accounts"},
        follow_redirects=True,
    )
    assert response.status_code == 200

    response = client.get(f"/export/{admin_slug}")
    assert response.status_code == 200
    assert "Facebook".encode() in response.data

    client.get("/logout", follow_redirects=True)

    response = client.post(
        "/login",
        data={"email": reader_email, "password": "sehrsicher123"},
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
