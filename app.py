from __future__ import annotations

import base64
import io
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import textwrap
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from flask import (
    Flask,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from email.message import EmailMessage
import smtplib
import qrcode
import qrcode.image.svg


BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
DEFAULT_DB_PATH = INSTANCE_DIR / "aeterna.db"
DEFAULT_UPLOAD_DIR = INSTANCE_DIR / "uploads"

LOCAL_TZ = timezone.utc
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
ALLOWED_DOCUMENT_EXTENSIONS = {
    ".pdf",
    ".png",
    ".jpg",
    ".jpeg",
    ".webp",
    ".txt",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
}
MAX_UPLOAD_SIZE = 20 * 1024 * 1024
APP_CATEGORIES = [
    ("online_accounts", "Onlinekonten"),
    ("devices_media", "Geräte & Datenträger"),
    ("web_domains", "Websites & Domains"),
    ("contracts", "Verträge"),
    ("insurances", "Versicherungen"),
    ("documents", "Dokumente"),
    ("important_items", "Unterlagen & Notgroschen"),
    ("home_network", "Heimnetz & Smarthome"),
]

HELP_PAGE_LINKS = [
    {
        "title": "Digital-Kompass: Anleitung Digitaler Nachlass (PDF)",
        "url": "https://www.digital-kompass.de/sites/default/files/material/files/barrierefrei_anleitung_14_digitaler_nachlass_30092024.pdf",
        "description": "Barrierearme Schritt-für-Schritt-Anleitung mit vielen praktischen Checklisten und Beispielen.",
        "tag": "Grundlagen",
    },
]

PROVIDER_LEGACY_LINKS = [
    {
        "provider": "Apple",
        "title": "Nachlasskontakt (Legacy Contact)",
        "url": "https://support.apple.com/en-us/102631",
        "description": "Apple-ID: Nachlasskontakt festlegen, damit Angehörige später geregelt Zugriff beantragen können.",
    },
    {
        "provider": "Meta / Facebook",
        "title": "Gedenkzustand & Nachlasskontakt",
        "url": "https://www.facebook.com/help/www/1070665206293088",
        "description": "Facebook/Meta: Konto in den Gedenkzustand versetzen und eine Kontaktperson bestimmen.",
    },
    {
        "provider": "Google",
        "title": "Inaktiver-Konto-Manager",
        "url": "https://support.google.com/accounts/answer/3036546",
        "description": "Google-Konto: automatische Regelungen für inaktive Konten festlegen (Benachrichtigung, Datenweitergabe).",
    },
    {
        "provider": "Google",
        "title": "Direkt öffnen: Inaktiver-Konto-Manager",
        "url": "https://myaccount.google.com/inactive",
        "description": "Direkter Link zu den Einstellungen im Google-Konto.",
    },
    {
        "provider": "Microsoft",
        "title": "Zugriff auf Outlook/OneDrive & Co. nach einem Todesfall",
        "url": "https://support.microsoft.com/en-us/account-billing/accessing-outlook-com-onedrive-and-other-microsoft-services-when-someone-has-died-ebbd2860-917e-4b39-9913-212362da6b2f",
        "description": "Microsoft: Informationen zu Konten, Daten und dem Vorgehen für Angehörige.",
    },
]


def slugify(value: str) -> str:
    normalized = (
        value.lower()
        .replace("ä", "ae")
        .replace("ö", "oe")
        .replace("ü", "ue")
        .replace("ß", "ss")
    )
    chars = []
    for char in normalized:
        if char.isalnum():
            chars.append(char)
        elif char in {" ", "-", "_"}:
            chars.append("-")
    base = "".join(chars).strip("-")
    while "--" in base:
        base = base.replace("--", "-")
    return base or "nachlass"


def utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load_env_file() -> None:
    env_path = BASE_DIR / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())


def create_app() -> Flask:
    load_env_file()
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "development-secret")
    app.config["APP_ENCRYPTION_KEY"] = build_fernet_key(
        os.environ.get("AETERNA_APP_KEY", "development-app-key")
    )
    app.config["DB_PATH"] = Path(os.environ.get("AETERNA_DB_PATH", str(DEFAULT_DB_PATH)))
    app.config["UPLOAD_DIR"] = Path(
        os.environ.get("AETERNA_UPLOAD_DIR", str(DEFAULT_UPLOAD_DIR))
    )
    app.config["HOST"] = os.environ.get("HOST", "127.0.0.1")
    app.config["PORT"] = int(os.environ.get("PORT", "8000"))
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_SIZE
    INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
    app.config["UPLOAD_DIR"].mkdir(parents=True, exist_ok=True)
    app.jinja_env.globals["APP_CATEGORIES"] = APP_CATEGORIES
    app.jinja_env.globals["has_category_access"] = has_category_access
    app.jinja_env.globals["category_label"] = category_label
    app.jinja_env.globals["current_user_role"] = current_user_role
    app.jinja_env.globals["decrypt_secret"] = decrypt_secret

    @app.before_request
    def before_request() -> None:
        g.db = get_db(app)
        g.system_initialized = is_system_initialized()
        g.user = get_current_user()
        allowed_endpoints = {"login", "register", "setup", "static", "logo_asset", "profile_hint", "profile_emergency"}
        if (
            not g.system_initialized
            and request.endpoint not in allowed_endpoints
            and not (request.endpoint or "").startswith("static")
        ):
            return redirect(url_for("setup"))

    @app.teardown_request
    def teardown_request(exc: BaseException | None) -> None:
        db = g.pop("db", None)
        if db is not None:
            db.close()

    register_routes(app)
    init_db(app)
    return app


def build_fernet_key(raw_key: str) -> str:
    digest = hashlib.sha256(raw_key.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii")


def get_db(app: Flask) -> sqlite3.Connection:
    db = sqlite3.connect(app.config["DB_PATH"])
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def init_db(app: Flask) -> None:
    schema = """
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        display_name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        is_admin INTEGER NOT NULL DEFAULT 0,
        is_creator INTEGER NOT NULL DEFAULT 0,
        is_reader INTEGER NOT NULL DEFAULT 0,
        active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS profiles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner_user_id INTEGER NOT NULL UNIQUE,
        slug TEXT NOT NULL UNIQUE,
        title TEXT NOT NULL,
        intro_text TEXT NOT NULL DEFAULT '',
        emergency_enabled INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY(owner_user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        profile_id INTEGER NOT NULL,
        category_key TEXT NOT NULL,
        title TEXT NOT NULL,
        provider TEXT NOT NULL DEFAULT '',
        website TEXT NOT NULL DEFAULT '',
        account_username TEXT NOT NULL DEFAULT '',
        secret_encrypted TEXT NOT NULL DEFAULT '',
        reference_number TEXT NOT NULL DEFAULT '',
        location_info TEXT NOT NULL DEFAULT '',
        contact_info TEXT NOT NULL DEFAULT '',
        details TEXT NOT NULL DEFAULT '',
        notes TEXT NOT NULL DEFAULT '',
        is_2fa_enabled INTEGER NOT NULL DEFAULT 0,
        created_by INTEGER NOT NULL,
        updated_by INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY(profile_id) REFERENCES profiles(id) ON DELETE CASCADE,
        FOREIGN KEY(created_by) REFERENCES users(id),
        FOREIGN KEY(updated_by) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS wishes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        profile_id INTEGER NOT NULL UNIQUE,
        farewell_message TEXT NOT NULL DEFAULT '',
        asset_notes TEXT NOT NULL DEFAULT '',
        ceremony_notes TEXT NOT NULL DEFAULT '',
        important_contacts TEXT NOT NULL DEFAULT '',
        external_links TEXT NOT NULL DEFAULT '',
        updated_by INTEGER NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY(profile_id) REFERENCES profiles(id) ON DELETE CASCADE,
        FOREIGN KEY(updated_by) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS documents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        profile_id INTEGER NOT NULL,
        category_key TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        original_name TEXT NOT NULL,
        stored_name TEXT NOT NULL,
        uploaded_by INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(profile_id) REFERENCES profiles(id) ON DELETE CASCADE,
        FOREIGN KEY(uploaded_by) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS grants (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        profile_id INTEGER NOT NULL,
        grantee_user_id INTEGER NOT NULL,
        category_key TEXT,
        can_export INTEGER NOT NULL DEFAULT 1,
        created_by INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(profile_id, grantee_user_id, category_key),
        FOREIGN KEY(profile_id) REFERENCES profiles(id) ON DELETE CASCADE,
        FOREIGN KEY(grantee_user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(created_by) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS smtp_settings (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        host TEXT NOT NULL DEFAULT '',
        port INTEGER NOT NULL DEFAULT 587,
        username TEXT NOT NULL DEFAULT '',
        password_encrypted TEXT NOT NULL DEFAULT '',
        sender_email TEXT NOT NULL DEFAULT '',
        use_tls INTEGER NOT NULL DEFAULT 1,
        use_ssl INTEGER NOT NULL DEFAULT 0,
        updated_by INTEGER,
        updated_at TEXT NOT NULL DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS password_reset_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token TEXT NOT NULL UNIQUE,
        expires_at TEXT NOT NULL,
        used_at TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS activity_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        actor_name TEXT NOT NULL,
        profile_id INTEGER,
        event_type TEXT NOT NULL,
        area TEXT NOT NULL,
        detail TEXT NOT NULL,
        request_path TEXT NOT NULL,
        ip_address TEXT NOT NULL,
        user_agent TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL,
        FOREIGN KEY(profile_id) REFERENCES profiles(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS category_status (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        profile_id INTEGER NOT NULL,
        category_key TEXT NOT NULL,
        is_applicable INTEGER NOT NULL DEFAULT 1,
        is_complete INTEGER NOT NULL DEFAULT 0,
        updated_by INTEGER NOT NULL,
        updated_at TEXT NOT NULL,
        UNIQUE(profile_id, category_key),
        FOREIGN KEY(profile_id) REFERENCES profiles(id) ON DELETE CASCADE,
        FOREIGN KEY(updated_by) REFERENCES users(id)
    );
    """
    db = get_db(app)
    db.executescript(schema)
    db.execute("INSERT OR IGNORE INTO smtp_settings (id, updated_at) VALUES (1, '')")
    db.commit()
    db.close()


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 260000)
    return f"{salt.hex()}${derived.hex()}"


def verify_password(password: str, stored: str) -> bool:
    salt_hex, digest_hex = stored.split("$", 1)
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt_hex),
        260000,
    )
    return hmac.compare_digest(derived.hex(), digest_hex)


def get_cipher() -> Fernet:
    return Fernet(create_app_instance.config["APP_ENCRYPTION_KEY"])


def encrypt_secret(value: str) -> str:
    if not value:
        return ""
    return get_cipher().encrypt(value.encode("utf-8")).decode("utf-8")


def decrypt_secret(value: str) -> str:
    if not value:
        return ""
    try:
        return get_cipher().decrypt(value.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        return "[Entschlüsselung fehlgeschlagen]"


def create_unique_slug(db: sqlite3.Connection, display_name: str) -> str:
    base = slugify(display_name)
    while True:
        slug = f"{base}-{secrets.token_hex(2)}"
        exists = db.execute("SELECT 1 FROM profiles WHERE slug = ?", (slug,)).fetchone()
        if not exists:
            return slug


def category_label(key: str) -> str:
    for category_key, label in APP_CATEGORIES:
        if category_key == key:
            return label
    return key


def is_system_initialized() -> bool:
    row = g.db.execute("SELECT COUNT(*) AS count FROM users").fetchone()
    return row["count"] > 0


def push_toast(message: str, category: str = "info", title: str | None = None) -> None:
    flash(
        {
            "title": title or {
                "success": "Erfolgreich",
                "danger": "Nicht erfolgreich",
                "warning": "Hinweis",
                "info": "Information",
            }.get(category, "Information"),
            "message": message,
        },
        category,
    )


def normalize_email(value: str) -> str:
    return value.strip().lower()


def is_valid_email(value: str) -> bool:
    return bool(EMAIL_RE.match(value))


def create_user_with_profile(
    display_name: str,
    email: str,
    password: str,
    role: str,
    acting_user_id: int | None,
) -> int:
    now = utcnow()
    is_admin = 1 if role == "admin" else 0
    is_creator = 1 if role in {"admin", "creator"} else 0
    is_reader = 1 if role == "reader" else 0
    cursor = g.db.execute(
        """
        INSERT INTO users (
            display_name, email, password_hash, is_admin, is_creator, is_reader, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (display_name, email, hash_password(password), is_admin, is_creator, is_reader, now, now),
    )
    user_id = cursor.lastrowid
    if is_creator:
        slug = create_unique_slug(g.db, display_name)
        g.db.execute(
            """
            INSERT INTO profiles (owner_user_id, slug, title, intro_text, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (user_id, slug, f"Nachlass von {display_name}", "", now, now),
        )
        profile_id = g.db.execute(
            "SELECT id FROM profiles WHERE owner_user_id = ?", (user_id,)
        ).fetchone()["id"]
        g.db.execute(
            "INSERT INTO wishes (profile_id, updated_by, updated_at) VALUES (?, ?, ?)",
            (profile_id, acting_user_id or user_id, now),
        )
    return user_id


def validate_password_fields(password: str, password_confirm: str | None = None) -> list[str]:
    errors = []
    if len(password) < 10:
        errors.append("Das Passwort muss mindestens 10 Zeichen lang sein.")
    if password_confirm is not None and password != password_confirm:
        errors.append("Die Passwörter stimmen nicht überein.")
    return errors


def validate_setup_form(form: Any) -> list[str]:
    display_name = form.get("display_name", "").strip()
    email = normalize_email(form.get("email", ""))
    password = form.get("password", "")
    password_confirm = form.get("password_confirm", "")
    errors = []
    if len(display_name) < 2:
        errors.append("Bitte geben Sie einen Namen mit mindestens 2 Zeichen ein.")
    if not is_valid_email(email):
        errors.append("Bitte geben Sie eine gültige E-Mail-Adresse ein.")
    errors.extend(validate_password_fields(password, password_confirm))
    return errors


def validate_user_form(form: Any) -> tuple[list[str], dict[str, str]]:
    display_name = form.get("display_name", "").strip()
    email = normalize_email(form.get("email", ""))
    password = form.get("password", "").strip()
    role = form.get("role", "reader")
    errors = []
    if len(display_name) < 2:
        errors.append("Bitte geben Sie einen Namen mit mindestens 2 Zeichen ein.")
    if not is_valid_email(email):
        errors.append("Bitte geben Sie eine gültige E-Mail-Adresse ein.")
    errors.extend(validate_password_fields(password))
    if role not in {"reader", "creator", "admin"}:
        errors.append("Die ausgewählte Rolle ist ungültig.")
    return errors, {
        "display_name": display_name,
        "email": email,
        "password": password,
        "role": role,
    }


def validate_record_form(form: Any) -> tuple[list[str], dict[str, Any]]:
    title = form.get("title", "").strip()
    website = form.get("website", "").strip()
    category_key = form.get("category_key", "").strip()
    data = {
        "title": title,
        "provider": form.get("provider", "").strip(),
        "website": website,
        "account_username": form.get("account_username", "").strip(),
        "account_password": form.get("account_password", "").strip(),
        "reference_number": form.get("reference_number", "").strip(),
        "location_info": form.get("location_info", "").strip(),
        "contact_info": form.get("contact_info", "").strip(),
        "details": form.get("details", "").strip(),
        "notes": form.get("notes", "").strip(),
        "is_2fa_enabled": 1 if form.get("is_2fa_enabled") else 0,
        "category_key": category_key,
    }
    errors = []
    if len(title) < 3:
        errors.append("Der Titel muss mindestens 3 Zeichen lang sein.")
    if website and not (website.startswith("http://") or website.startswith("https://")):
        errors.append("Webseiten müssen mit http:// oder https:// beginnen.")
    if data["account_password"] and len(data["account_password"]) < 4:
        errors.append("Gespeicherte Zugangsdaten sollten mindestens 4 Zeichen lang sein.")
    return errors, data


def validate_document(uploaded: Any, title: str) -> list[str]:
    errors = []
    if not uploaded or not uploaded.filename:
        errors.append("Bitte wählen Sie eine Datei aus.")
        return errors
    suffix = Path(uploaded.filename).suffix.lower()
    if suffix not in ALLOWED_DOCUMENT_EXTENSIONS:
        errors.append("Dieses Dateiformat wird aktuell nicht unterstützt.")
    if title and len(title.strip()) < 3:
        errors.append("Der Dokumenttitel muss mindestens 3 Zeichen lang sein.")
    if request.content_length and request.content_length > MAX_UPLOAD_SIZE:
        errors.append("Die Datei ist zu groß. Erlaubt sind maximal 20 MB.")
    return errors


def validate_smtp_form(form: Any) -> list[str]:
    host = form.get("host", "").strip()
    sender_email = form.get("sender_email", "").strip()
    test_recipient = form.get("test_recipient", "").strip()
    errors = []
    if sender_email and not is_valid_email(sender_email):
        errors.append("Bitte geben Sie eine gültige Absender-E-Mail an.")
    if test_recipient and not is_valid_email(test_recipient):
        errors.append("Bitte geben Sie eine gültige Test-E-Mail an.")
    if form.get("send_test_mail") and not test_recipient:
        errors.append("Bitte geben Sie eine Empfängeradresse für die Testmail an.")
    if (form.get("username") or form.get("smtp_password") or sender_email) and not host:
        errors.append("Bitte hinterlegen Sie einen SMTP-Host.")
    return errors


def get_current_user() -> sqlite3.Row | None:
    user_id = session.get("user_id")
    if not user_id:
        return None
    row = g.db.execute("SELECT * FROM users WHERE id = ? AND active = 1", (user_id,)).fetchone()
    return row


def current_user_role() -> str:
    user = getattr(g, "user", None)
    if not user:
        return ""
    if user["is_admin"]:
        return "admin"
    if user["is_creator"]:
        return "creator"
    return "reader"


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not g.user:
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not g.user or not g.user["is_admin"]:
            abort(403)
        return view(*args, **kwargs)

    return wrapped


def creator_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not g.user or not g.user["is_creator"]:
            abort(403)
        return view(*args, **kwargs)

    return wrapped


def log_event(
    event_type: str,
    area: str,
    detail: str,
    profile_id: int | None = None,
    user_id: int | None = None,
) -> None:
    actor = g.user["display_name"] if g.user else "Gast"
    g.db.execute(
        """
        INSERT INTO activity_logs (
            user_id, actor_name, profile_id, event_type, area, detail,
            request_path, ip_address, user_agent, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user_id or (g.user["id"] if g.user else None),
            actor,
            profile_id,
            event_type,
            area,
            detail,
            request.path,
            request.headers.get("X-Forwarded-For", request.remote_addr or ""),
            request.user_agent.string[:500],
            utcnow(),
        ),
    )
    g.db.commit()


def get_profile_by_slug(slug: str) -> sqlite3.Row | None:
    return g.db.execute(
        """
        SELECT profiles.*, users.display_name AS owner_name, users.email AS owner_email
        FROM profiles
        JOIN users ON users.id = profiles.owner_user_id
        WHERE profiles.slug = ?
        """,
        (slug,),
    ).fetchone()


def resolve_profile_by_slug(slug: str) -> tuple[sqlite3.Row | None, str | None]:
    profile = get_profile_by_slug(slug)
    if profile:
        return profile, None
    if "-" not in slug:
        return None, None
    base = slug.split("-", 1)[0]
    matches = g.db.execute(
        """
        SELECT profiles.*, users.display_name AS owner_name, users.email AS owner_email
        FROM profiles
        JOIN users ON users.id = profiles.owner_user_id
        WHERE profiles.slug = ? OR profiles.slug LIKE ?
        ORDER BY profiles.id ASC
        """,
        (base, f"{base}-%"),
    ).fetchall()
    if len(matches) == 1:
        return matches[0], matches[0]["slug"]
    return None, None


def build_emergency_url(slug: str) -> str:
    return f"{request.url_root.rstrip('/')}{url_for('profile_emergency', slug=slug)}"


def build_qr_svg(value: str) -> str:
    image = qrcode.make(value, image_factory=qrcode.image.svg.SvgPathImage, box_size=8, border=2)
    buffer = io.BytesIO()
    image.save(buffer)
    return buffer.getvalue().decode("utf-8")


def get_profile_for_owner(user_id: int) -> sqlite3.Row | None:
    return g.db.execute(
        """
        SELECT profiles.*, users.display_name AS owner_name, users.email AS owner_email
        FROM profiles
        JOIN users ON users.id = profiles.owner_user_id
        WHERE profiles.owner_user_id = ?
        """,
        (user_id,),
    ).fetchone()


def user_can_access_profile(user: sqlite3.Row, profile: sqlite3.Row) -> bool:
    if user["is_admin"] and user["id"] == profile["owner_user_id"]:
        return True
    if user["id"] == profile["owner_user_id"]:
        return True
    grant = g.db.execute(
        "SELECT 1 FROM grants WHERE profile_id = ? AND grantee_user_id = ? LIMIT 1",
        (profile["id"], user["id"]),
    ).fetchone()
    return grant is not None


def has_category_access(user: sqlite3.Row | None, profile_id: int, category_key: str) -> bool:
    if not user:
        return False
    profile = g.db.execute("SELECT * FROM profiles WHERE id = ?", (profile_id,)).fetchone()
    if not profile:
        return False
    if user["id"] == profile["owner_user_id"]:
        return True
    if user["is_admin"] and user["id"] == profile["owner_user_id"]:
        return True
    grant = g.db.execute(
        """
        SELECT 1 FROM grants
        WHERE profile_id = ? AND grantee_user_id = ? AND (category_key IS NULL OR category_key = ?)
        LIMIT 1
        """,
        (profile_id, user["id"], category_key),
    ).fetchone()
    return grant is not None


def ensure_profile_access(profile: sqlite3.Row, category_key: str | None = None) -> None:
    if not user_can_access_profile(g.user, profile):
        abort(403)
    if category_key and not has_category_access(g.user, profile["id"], category_key):
        abort(403)


def get_visible_profiles(user: sqlite3.Row) -> list[sqlite3.Row]:
    if user["is_creator"]:
        own = get_profile_for_owner(user["id"])
        rows = [own] if own else []
    else:
        rows = []
    grants = g.db.execute(
        """
        SELECT DISTINCT profiles.*, users.display_name AS owner_name
        FROM profiles
        JOIN grants ON grants.profile_id = profiles.id
        JOIN users ON users.id = profiles.owner_user_id
        WHERE grants.grantee_user_id = ?
        ORDER BY users.display_name
        """,
        (user["id"],),
    ).fetchall()
    existing = {row["id"] for row in rows if row}
    for grant in grants:
        if grant["id"] not in existing:
            rows.append(grant)
    return [row for row in rows if row]


def get_relevant_logs(user: sqlite3.Row, owned_profile: sqlite3.Row | None = None) -> list[sqlite3.Row]:
    if user["is_admin"]:
        return g.db.execute(
            """
            SELECT activity_logs.*, profiles.slug
            FROM activity_logs
            LEFT JOIN profiles ON profiles.id = activity_logs.profile_id
            ORDER BY activity_logs.id DESC LIMIT 150
            """
        ).fetchall()
    if owned_profile:
        return g.db.execute(
            """
            SELECT activity_logs.*, profiles.slug
            FROM activity_logs
            LEFT JOIN profiles ON profiles.id = activity_logs.profile_id
            WHERE activity_logs.profile_id = ? OR activity_logs.user_id = ?
            ORDER BY activity_logs.id DESC LIMIT 150
            """,
            (owned_profile["id"], user["id"]),
        ).fetchall()
    granted_profile_ids = [
        row["profile_id"]
        for row in g.db.execute(
            "SELECT DISTINCT profile_id FROM grants WHERE grantee_user_id = ?",
            (user["id"],),
        ).fetchall()
    ]
    params: list[Any] = [user["id"]]
    query = """
        SELECT activity_logs.*, profiles.slug
        FROM activity_logs
        LEFT JOIN profiles ON profiles.id = activity_logs.profile_id
        WHERE activity_logs.user_id = ?
    """
    if granted_profile_ids:
        placeholders = ",".join("?" for _ in granted_profile_ids)
        query += f" OR activity_logs.profile_id IN ({placeholders})"
        params.extend(granted_profile_ids)
    query += " ORDER BY activity_logs.id DESC LIMIT 150"
    return g.db.execute(query, params).fetchall()


def get_profile_categories(profile_id: int) -> list[dict[str, Any]]:
    status_rows = g.db.execute(
        "SELECT category_key, is_applicable, is_complete FROM category_status WHERE profile_id = ?",
        (profile_id,),
    ).fetchall()
    status_map = {row["category_key"]: row for row in status_rows}
    data: list[dict[str, Any]] = []
    for key, label in APP_CATEGORIES:
        records_count = g.db.execute(
            "SELECT COUNT(*) AS count FROM records WHERE profile_id = ? AND category_key = ?",
            (profile_id, key),
        ).fetchone()["count"]
        docs_count = g.db.execute(
            "SELECT COUNT(*) AS count FROM documents WHERE profile_id = ? AND category_key = ?",
            (profile_id, key),
        ).fetchone()["count"]
        status = status_map.get(key)
        is_applicable = bool(status["is_applicable"]) if status else True
        is_complete = bool(status["is_complete"]) if status else False
        has_any_content = (records_count + docs_count) > 0
        if not is_applicable:
            status_state = "na"
        elif is_complete:
            status_state = "complete"
        elif has_any_content:
            status_state = "started"
        else:
            status_state = "empty"
        data.append(
            {
                "key": key,
                "label": label,
                "records_count": records_count,
                "documents_count": docs_count,
                "is_applicable": is_applicable,
                "is_complete": is_complete,
                "has_any_content": has_any_content,
                "status_state": status_state,
            }
        )
    return data


def get_category_status(profile_id: int, category_key: str) -> dict[str, Any]:
    row = g.db.execute(
        "SELECT is_applicable, is_complete, updated_at FROM category_status WHERE profile_id = ? AND category_key = ?",
        (profile_id, category_key),
    ).fetchone()
    if row:
        is_applicable = bool(row["is_applicable"])
        is_complete = bool(row["is_complete"])
        updated_at = row["updated_at"]
    else:
        is_applicable = True
        is_complete = False
        updated_at = None
    if not is_applicable:
        state = "na"
        label = "Nicht zutreffend"
    elif is_complete:
        state = "complete"
        label = "Fertig"
    else:
        state = "open"
        label = "Offen"
    return {
        "is_applicable": is_applicable,
        "is_complete": is_complete,
        "state": state,
        "label": label,
        "updated_at": updated_at,
    }


def send_test_or_reset_mail(
    smtp_settings: sqlite3.Row,
    recipient: str,
    subject: str,
    body: str,
    html_body: str | None = None,
) -> tuple[bool, str]:
    host = smtp_settings["host"]
    sender_email = smtp_settings["sender_email"]
    if not host or not sender_email:
        return False, "SMTP ist noch nicht vollständig eingerichtet."
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = sender_email
    message["To"] = recipient
    message.set_content(body)
    if html_body:
        message.add_alternative(html_body, subtype="html")
    password = decrypt_secret(smtp_settings["password_encrypted"])
    try:
        if smtp_settings["use_ssl"]:
            server = smtplib.SMTP_SSL(host, smtp_settings["port"], timeout=15)
        else:
            server = smtplib.SMTP(host, smtp_settings["port"], timeout=15)
        with server:
            if smtp_settings["use_tls"] and not smtp_settings["use_ssl"]:
                server.starttls()
            if smtp_settings["username"]:
                server.login(smtp_settings["username"], password)
            server.send_message(message)
        return True, "E-Mail wurde versendet."
    except Exception as exc:  # pragma: no cover - network dependent
        return False, f"Versand fehlgeschlagen: {exc}"


def render_email_html(
    title: str,
    lead: str,
    body_lines: list[str],
    button_label: str | None = None,
    button_url: str | None = None,
    footer_note: str | None = None,
) -> str:
    logo_url = f"{request.url_root.rstrip('/')}{url_for('logo_asset')}" if request else ""
    lines_html = "".join(
        f"<p style='margin:0 0 14px;color:#39566f;line-height:1.7;font-size:15px;'>{line}</p>"
        for line in body_lines
    )
    button_html = ""
    if button_label and button_url:
        button_html = f"""
        <div style="margin:28px 0 24px;">
          <a href="{button_url}" style="
            display:inline-block;
            padding:14px 24px;
            border-radius:999px;
            background:linear-gradient(135deg,#35bdd0,#206ca6);
            color:#ffffff;
            text-decoration:none;
            font-weight:700;
            font-size:15px;
          ">{button_label}</a>
        </div>
        """
    footer_text = footer_note or "Diese Nachricht wurde von Aeterna erstellt, um digitale Nachlassinformationen nachvollziehbar und sicher zu begleiten."
    return f"""
    <!doctype html>
    <html lang="de">
      <body style="margin:0;padding:32px 16px;background:#eef4f8;font-family:Arial,sans-serif;color:#103654;">
        <div style="max-width:700px;margin:0 auto;background:#ffffff;border-radius:24px;overflow:hidden;box-shadow:0 24px 80px rgba(16,54,84,0.12);">
          <div style="padding:34px 40px;background:linear-gradient(135deg,#103654,#206ca6);color:#ffffff;">
            <img src="{logo_url}" alt="Aeterna" style="width:72px;height:72px;object-fit:contain;display:block;margin-bottom:18px;">
            <div style="letter-spacing:0.22em;text-transform:uppercase;font-size:12px;opacity:0.82;font-weight:700;">Aeterna</div>
            <h1 style="margin:14px 0 10px;font-size:30px;line-height:1.2;">{title}</h1>
            <p style="margin:0;color:rgba(255,255,255,0.84);font-size:16px;line-height:1.7;">{lead}</p>
          </div>
          <div style="padding:36px 40px 28px;">
            {lines_html}
            {button_html}
            <div style="margin-top:28px;padding-top:20px;border-top:1px solid rgba(16,54,84,0.12);font-size:13px;color:#6e8395;line-height:1.7;">
              <p style="margin:0 0 8px;"><strong style="color:#103654;">Aeterna · Digitaler Nachlass</strong></p>
              <p style="margin:0 0 8px;">{footer_text}</p>
              <p style="margin:0;">Falls der Button nicht funktioniert, nutzen Sie bitte diesen Link:<br><span style="word-break:break-all;color:#206ca6;">{button_url or request.url_root.rstrip('/')}</span></p>
            </div>
          </div>
        </div>
      </body>
    </html>
    """


def register_routes(app: Flask) -> None:
    @app.route("/")
    def index():
        if not g.system_initialized:
            return redirect(url_for("setup"))
        if g.user:
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/branding/logo.png")
    def logo_asset():
        return send_from_directory(BASE_DIR, "Logo_aeterna.png")

    @app.route("/setup", methods=["GET", "POST"])
    def setup():
        if g.system_initialized:
            return redirect(url_for("dashboard" if g.user else "login"))
        if request.method == "POST":
            errors = validate_setup_form(request.form)
            if errors:
                for error in errors:
                    push_toast(error, "danger", "Einrichtung unvollständig")
            else:
                try:
                    user_id = create_user_with_profile(
                        request.form.get("display_name", "").strip(),
                        normalize_email(request.form.get("email", "")),
                        request.form.get("password", ""),
                        "admin",
                        None,
                    )
                    g.db.commit()
                    session.clear()
                    session["user_id"] = user_id
                    session["active_profile_slug"] = get_profile_for_owner(user_id)["slug"]
                    log_event("setup_complete", "setup", "System erstmalig eingerichtet", user_id=user_id)
                    push_toast(
                        "Die Erstkonfiguration wurde erfolgreich abgeschlossen. Sie können jetzt mit Ihrem Nachlass starten.",
                        "success",
                        "Aeterna ist bereit",
                    )
                    return redirect(url_for("dashboard"))
                except sqlite3.IntegrityError:
                    push_toast("Diese E-Mail-Adresse ist bereits vorhanden.", "danger", "Einrichtung fehlgeschlagen")
        return render_template("setup.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if not g.system_initialized:
            return redirect(url_for("setup"))
        target_slug = request.args.get("target", "").strip()
        if request.method == "POST":
            email = normalize_email(request.form.get("email", ""))
            password = request.form.get("password", "")
            user = g.db.execute(
                "SELECT * FROM users WHERE lower(email) = ? AND active = 1", (email,)
            ).fetchone()
            if not user or not verify_password(password, user["password_hash"]):
                log_event("login_failed", "auth", f"Fehlgeschlagener Login für {email}")
                push_toast("Bitte prüfen Sie E-Mail-Adresse und Passwort.", "danger", "Anmeldung fehlgeschlagen")
            else:
                session.clear()
                session["user_id"] = user["id"]
                session["active_profile_slug"] = target_slug
                log_event("login_success", "auth", f"Login erfolgreich für {user['display_name']}", user_id=user["id"])
                push_toast(f"Willkommen zurück, {user['display_name']}.", "success", "Anmeldung erfolgreich")
                next_url = request.args.get("next")
                if target_slug:
                    return redirect(url_for("profile_dashboard", slug=target_slug))
                return redirect(next_url or url_for("dashboard"))
        return render_template("login.html", target_slug=target_slug)

    @app.route("/registrieren", methods=["GET", "POST"])
    def register():
        if not g.system_initialized:
            return redirect(url_for("setup"))
        if g.user:
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            errors, data = validate_user_form(request.form)
            role = data["role"]
            if role == "admin":
                role = "reader"
            if role not in {"reader", "creator"}:
                role = "reader"
            if errors:
                for error in errors:
                    push_toast(error, "danger", "Registrierung fehlgeschlagen")
                return render_template("register.html", form_values=data)
            try:
                create_user_with_profile(
                    data["display_name"],
                    data["email"],
                    data["password"],
                    role,
                    None,
                )
                g.db.commit()
                push_toast(
                    "Ihr Konto wurde angelegt. Bitte melden Sie sich jetzt an.",
                    "success",
                    "Registrierung erfolgreich",
                )
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                push_toast("Diese E-Mail-Adresse ist bereits vergeben.", "danger", "Registrierung fehlgeschlagen")
                return render_template("register.html", form_values=data)
        return render_template("register.html", form_values=None)

    @app.route("/logout")
    @login_required
    def logout():
        log_event("logout", "auth", "Benutzer abgemeldet")
        session.clear()
        push_toast("Sie wurden sicher abgemeldet.", "info", "Abmeldung")
        return redirect(url_for("login"))

    @app.route("/passwort-vergessen", methods=["GET", "POST"])
    def forgot_password():
        if request.method == "POST":
            email = normalize_email(request.form.get("email", ""))
            user = g.db.execute("SELECT * FROM users WHERE lower(email) = ?", (email,)).fetchone()
            smtp_settings = g.db.execute("SELECT * FROM smtp_settings WHERE id = 1").fetchone()
            if user:
                token = secrets.token_urlsafe(24)
                expires_at = (datetime.now(timezone.utc) + timedelta(hours=2)).replace(
                    microsecond=0
                ).isoformat()
                g.db.execute(
                    """
                    INSERT INTO password_reset_tokens (user_id, token, expires_at, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (user["id"], token, expires_at, utcnow()),
                )
                g.db.commit()
                reset_url = url_for("reset_password", token=token, _external=True)
                send_test_or_reset_mail(
                    smtp_settings,
                    user["email"],
                    "Aeterna Passwort zurücksetzen",
                    f"Bitte öffnen Sie diesen Link, um Ihr Passwort zurückzusetzen:\n\n{reset_url}\n",
                    render_email_html(
                        "Passwort zurücksetzen",
                        "Sie haben einen Link zum Zurücksetzen Ihres Passworts angefordert.",
                        [
                            "Aus Sicherheitsgründen ist dieser Link nur für kurze Zeit gültig.",
                            "Wenn Sie diese Anfrage nicht selbst ausgelöst haben, können Sie diese E-Mail ignorieren.",
                        ],
                        "Passwort jetzt zurücksetzen",
                        reset_url,
                        "Diese E-Mail wurde versendet, weil für Ihr Aeterna-Konto ein Passwort-Reset angefordert wurde.",
                    ),
                )
                log_event("password_reset_request", "auth", f"Reset angefordert für {email}")
            push_toast("Falls die E-Mail existiert, wurde ein Link versendet.", "info", "Passwort-Reset")
            return redirect(url_for("login"))
        return render_template("forgot_password.html")

    @app.route("/passwort-zuruecksetzen/<token>", methods=["GET", "POST"])
    def reset_password(token: str):
        token_row = g.db.execute(
            """
            SELECT password_reset_tokens.*, users.display_name, users.email
            FROM password_reset_tokens
            JOIN users ON users.id = password_reset_tokens.user_id
            WHERE token = ? AND used_at IS NULL
            """,
            (token,),
        ).fetchone()
        if not token_row:
            abort(404)
        if datetime.fromisoformat(token_row["expires_at"]) < datetime.now(timezone.utc):
            push_toast("Der Link ist abgelaufen.", "danger", "Passwort-Reset")
            return redirect(url_for("login"))
        if request.method == "POST":
            password = request.form.get("password", "")
            password_confirm = request.form.get("password_confirm", "")
            errors = validate_password_fields(password, password_confirm)
            if errors:
                for error in errors:
                    push_toast(error, "danger", "Passwort-Reset")
            else:
                g.db.execute(
                    "UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
                    (hash_password(password), utcnow(), token_row["user_id"]),
                )
                g.db.execute(
                    "UPDATE password_reset_tokens SET used_at = ? WHERE id = ?",
                    (utcnow(), token_row["id"]),
                )
                g.db.commit()
                log_event(
                    "password_reset_complete",
                    "auth",
                    f"Passwort zurückgesetzt für {token_row['email']}",
                    user_id=token_row["user_id"],
                )
                push_toast("Ihr Passwort wurde erfolgreich zurückgesetzt.", "success", "Passwort aktualisiert")
                return redirect(url_for("login"))
        return render_template("reset_password.html", token_row=token_row)

    @app.route("/dashboard")
    @login_required
    def dashboard():
        profiles = get_visible_profiles(g.user)
        if profiles and not session.get("active_profile_slug"):
            session["active_profile_slug"] = profiles[0]["slug"]
        summary = []
        for profile in profiles:
            record_count = g.db.execute(
                "SELECT COUNT(*) AS count FROM records WHERE profile_id = ?", (profile["id"],)
            ).fetchone()["count"]
            document_count = g.db.execute(
                "SELECT COUNT(*) AS count FROM documents WHERE profile_id = ?", (profile["id"],)
            ).fetchone()["count"]
            grant_count = g.db.execute(
                "SELECT COUNT(*) AS count FROM grants WHERE profile_id = ?", (profile["id"],)
            ).fetchone()["count"]
            categories = get_profile_categories(profile["id"])
            completion = None
            if g.user["id"] == profile["owner_user_id"]:
                applicable = [c for c in categories if c["is_applicable"]]
                completed = [c for c in applicable if c["is_complete"]]
                started = [c for c in applicable if c["status_state"] == "started"]
                completion = {
                    "applicable_total": len(applicable),
                    "completed_total": len(completed),
                    "started_total": len(started),
                    "not_applicable_total": len([c for c in categories if not c["is_applicable"]]),
                    "percent": int(round((len(completed) / len(applicable)) * 100)) if applicable else 100,
                }
            summary.append(
                {
                    "profile": profile,
                    "record_count": record_count,
                    "document_count": document_count,
                    "grant_count": grant_count,
                    "categories": categories,
                    "completion": completion,
                    "emergency_url": build_emergency_url(profile["slug"]),
                    "emergency_qr_svg": build_qr_svg(build_emergency_url(profile["slug"])),
                }
            )
        recent_logs = get_relevant_logs(g.user, get_profile_for_owner(g.user["id"]) if g.user["is_creator"] else None)[:12]
        return render_template("dashboard.html", summaries=summary, recent_logs=recent_logs)

    @app.route("/hilfe")
    def help_page():
        if not g.system_initialized:
            return redirect(url_for("setup"))
        log_event("help_view", "help", "Hilfeseite geöffnet")
        return render_template(
            "help.html",
            general_links=HELP_PAGE_LINKS,
            provider_links=PROVIDER_LEGACY_LINKS,
        )

    @app.route("/nachlass/<slug>")
    @login_required
    def profile_dashboard(slug: str):
        profile, canonical_slug = resolve_profile_by_slug(slug)
        if canonical_slug and canonical_slug != slug:
            return redirect(url_for("profile_dashboard", slug=canonical_slug))
        if not profile:
            abort(404)
        ensure_profile_access(profile)
        session["active_profile_slug"] = slug
        categories = get_profile_categories(profile["id"])
        completion = None
        if g.user["id"] == profile["owner_user_id"]:
            applicable = [c for c in categories if c["is_applicable"]]
            completed = [c for c in applicable if c["is_complete"]]
            completion = {
                "applicable_total": len(applicable),
                "completed_total": len(completed),
                "percent": int(round((len(completed) / len(applicable)) * 100)) if applicable else 100,
            }
        wishes = g.db.execute("SELECT * FROM wishes WHERE profile_id = ?", (profile["id"],)).fetchone()
        log_event("profile_view", "profile", f"Profil {profile['slug']} geöffnet", profile["id"])
        return render_template(
            "profile_dashboard.html",
            profile=profile,
            categories=categories,
            completion=completion,
            wishes=wishes,
        )

    @app.route("/digitaler-nachlass/<slug>/<category_key>")
    @login_required
    def category_overview(slug: str, category_key: str):
        profile, canonical_slug = resolve_profile_by_slug(slug)
        if canonical_slug and canonical_slug != slug:
            return redirect(url_for("category_overview", slug=canonical_slug, category_key=category_key))
        if not profile:
            abort(404)
        ensure_profile_access(profile, category_key)
        session["active_profile_slug"] = slug
        records = g.db.execute(
            """
            SELECT records.*, users.display_name AS updated_by_name
            FROM records
            JOIN users ON users.id = records.updated_by
            WHERE profile_id = ? AND category_key = ?
            ORDER BY updated_at DESC, title COLLATE NOCASE
            """,
            (profile["id"], category_key),
        ).fetchall()
        documents = g.db.execute(
            """
            SELECT documents.*, users.display_name AS uploaded_by_name
            FROM documents
            JOIN users ON users.id = documents.uploaded_by
            WHERE profile_id = ? AND category_key = ?
            ORDER BY created_at DESC
            """,
            (profile["id"], category_key),
        ).fetchall()
        log_event("category_view", "records", f"Kategorie {category_key} geöffnet", profile["id"])
        return render_template(
            "category_overview.html",
            profile=profile,
            category_key=category_key,
            records=records,
            documents=documents,
            category_status=get_category_status(profile["id"], category_key),
            provider_links=PROVIDER_LEGACY_LINKS if category_key == "online_accounts" else [],
        )

    @app.route("/digitaler-nachlass/<slug>/<category_key>/status", methods=["POST"])
    @login_required
    def update_category_status(slug: str, category_key: str):
        profile, canonical_slug = resolve_profile_by_slug(slug)
        if canonical_slug and canonical_slug != slug:
            return redirect(url_for("update_category_status", slug=canonical_slug, category_key=category_key))
        if not profile:
            abort(404)
        if category_key not in {key for key, _ in APP_CATEGORIES}:
            abort(404)
        if g.user["id"] != profile["owner_user_id"]:
            abort(403)
        action = (request.form.get("action") or "").strip()
        if action not in {"na", "applicable", "complete", "open"}:
            abort(400)
        if action == "na":
            is_applicable = 0
            is_complete = 0
            toast = "Kategorie als nicht zutreffend markiert."
        elif action == "applicable":
            is_applicable = 1
            is_complete = 0
            toast = "Kategorie wieder als relevant markiert."
        elif action == "complete":
            is_applicable = 1
            is_complete = 1
            toast = "Kategorie als fertig markiert."
        else:
            is_applicable = 1
            is_complete = 0
            toast = "Kategorie als offen markiert."
        g.db.execute(
            """
            INSERT INTO category_status (profile_id, category_key, is_applicable, is_complete, updated_by, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(profile_id, category_key) DO UPDATE SET
              is_applicable = excluded.is_applicable,
              is_complete = excluded.is_complete,
              updated_by = excluded.updated_by,
              updated_at = excluded.updated_at
            """,
            (profile["id"], category_key, is_applicable, is_complete, g.user["id"], utcnow()),
        )
        g.db.commit()
        log_event("category_status_update", "status", f"Status {category_key}: {action}", profile["id"])
        push_toast(toast, "success", "Status aktualisiert")
        return redirect(url_for("category_overview", slug=slug, category_key=category_key))

    @app.route("/digitaler-nachlass/<slug>/<category_key>/neu", methods=["GET", "POST"])
    @login_required
    def record_create(slug: str, category_key: str):
        profile, canonical_slug = resolve_profile_by_slug(slug)
        if canonical_slug and canonical_slug != slug:
            return redirect(url_for("record_create", slug=canonical_slug, category_key=category_key))
        if not profile:
            abort(404)
        if g.user["id"] != profile["owner_user_id"]:
            abort(403)
        if request.method == "POST":
            errors, data = validate_record_form({**request.form, "category_key": category_key})
            if errors:
                for error in errors:
                    push_toast(error, "danger", "Eintrag nicht gespeichert")
                return render_template(
                    "record_form.html",
                    profile=profile,
                    category_key=category_key,
                    record=None,
                    secret_value=data["account_password"],
                    form_values=data,
                )
            now = utcnow()
            g.db.execute(
                """
                INSERT INTO records (
                    profile_id, category_key, title, provider, website, account_username,
                    secret_encrypted, reference_number, location_info, contact_info,
                    details, notes, is_2fa_enabled, created_by, updated_by, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    profile["id"],
                    category_key,
                    data["title"],
                    data["provider"],
                    data["website"],
                    data["account_username"],
                    encrypt_secret(data["account_password"]),
                    data["reference_number"],
                    data["location_info"],
                    data["contact_info"],
                    data["details"],
                    data["notes"],
                    data["is_2fa_enabled"],
                    g.user["id"],
                    g.user["id"],
                    now,
                    now,
                ),
            )
            g.db.commit()
            log_event("record_create", "records", f"Eintrag in {category_key} erstellt", profile["id"])
            push_toast("Der Eintrag wurde erfolgreich gespeichert.", "success", "Eintrag gespeichert")
            return redirect(url_for("category_overview", slug=slug, category_key=category_key))
        return render_template(
            "record_form.html",
            profile=profile,
            category_key=category_key,
            record=None,
            secret_value="",
            form_values=None,
        )

    @app.route("/digitaler-nachlass/<slug>/<category_key>/<int:record_id>/bearbeiten", methods=["GET", "POST"])
    @login_required
    def record_edit(slug: str, category_key: str, record_id: int):
        profile, canonical_slug = resolve_profile_by_slug(slug)
        if canonical_slug and canonical_slug != slug:
            return redirect(url_for("record_edit", slug=canonical_slug, category_key=category_key, record_id=record_id))
        if not profile or g.user["id"] != profile["owner_user_id"]:
            abort(403)
        record = g.db.execute(
            "SELECT * FROM records WHERE id = ? AND profile_id = ? AND category_key = ?",
            (record_id, profile["id"], category_key),
        ).fetchone()
        if not record:
            abort(404)
        if request.method == "POST":
            errors, data = validate_record_form({**request.form, "category_key": category_key})
            if errors:
                for error in errors:
                    push_toast(error, "danger", "Eintrag nicht aktualisiert")
                return render_template(
                    "record_form.html",
                    profile=profile,
                    category_key=category_key,
                    record=record,
                    secret_value=data["account_password"],
                    form_values=data,
                )
            g.db.execute(
                """
                UPDATE records SET
                    title = ?, provider = ?, website = ?, account_username = ?, secret_encrypted = ?,
                    reference_number = ?, location_info = ?, contact_info = ?, details = ?, notes = ?,
                    is_2fa_enabled = ?, updated_by = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    data["title"],
                    data["provider"],
                    data["website"],
                    data["account_username"],
                    encrypt_secret(data["account_password"]),
                    data["reference_number"],
                    data["location_info"],
                    data["contact_info"],
                    data["details"],
                    data["notes"],
                    data["is_2fa_enabled"],
                    g.user["id"],
                    utcnow(),
                    record_id,
                ),
            )
            g.db.commit()
            log_event("record_update", "records", f"Eintrag {record_id} aktualisiert", profile["id"])
            push_toast("Der Eintrag wurde aktualisiert.", "success", "Änderungen gespeichert")
            return redirect(url_for("category_overview", slug=slug, category_key=category_key))
        return render_template(
            "record_form.html",
            profile=profile,
            category_key=category_key,
            record=record,
            secret_value=decrypt_secret(record["secret_encrypted"]),
            form_values=None,
        )

    @app.route("/digitaler-nachlass/<slug>/<category_key>/<int:record_id>/loeschen", methods=["POST"])
    @login_required
    def record_delete(slug: str, category_key: str, record_id: int):
        profile, canonical_slug = resolve_profile_by_slug(slug)
        if canonical_slug and canonical_slug != slug:
            return redirect(url_for("record_delete", slug=canonical_slug, category_key=category_key, record_id=record_id))
        if not profile or g.user["id"] != profile["owner_user_id"]:
            abort(403)
        g.db.execute("DELETE FROM records WHERE id = ? AND profile_id = ?", (record_id, profile["id"]))
        g.db.commit()
        log_event("record_delete", "records", f"Eintrag {record_id} gelöscht", profile["id"])
        push_toast("Der Eintrag wurde gelöscht.", "info", "Eintrag entfernt")
        return redirect(url_for("category_overview", slug=slug, category_key=category_key))

    @app.route("/digitaler-nachlass/<slug>/<category_key>/<int:record_id>/passwort")
    @login_required
    def reveal_secret(slug: str, category_key: str, record_id: int):
        profile, canonical_slug = resolve_profile_by_slug(slug)
        if canonical_slug and canonical_slug != slug:
            return redirect(url_for("reveal_secret", slug=canonical_slug, category_key=category_key, record_id=record_id))
        if not profile:
            abort(404)
        ensure_profile_access(profile, category_key)
        record = g.db.execute(
            "SELECT * FROM records WHERE id = ? AND profile_id = ?",
            (record_id, profile["id"]),
        ).fetchone()
        if not record:
            abort(404)
        secret = decrypt_secret(record["secret_encrypted"])
        log_event("secret_view", "records", f"Passwort für Eintrag {record_id} angezeigt", profile["id"])
        return render_template(
            "secret_view.html",
            profile=profile,
            category_key=category_key,
            record=record,
            secret=secret,
        )

    @app.route("/dokumente/<slug>/upload", methods=["POST"])
    @login_required
    def upload_document(slug: str):
        profile, canonical_slug = resolve_profile_by_slug(slug)
        if canonical_slug and canonical_slug != slug:
            return redirect(url_for("upload_document", slug=canonical_slug))
        if not profile or g.user["id"] != profile["owner_user_id"]:
            abort(403)
        uploaded = request.files.get("document")
        category_key = request.form.get("category_key", "documents")
        errors = validate_document(uploaded, request.form.get("title", "").strip())
        if errors:
            for error in errors:
                push_toast(error, "danger", "Upload fehlgeschlagen")
            return redirect(url_for("category_overview", slug=slug, category_key=category_key))
        stored_name = f"{uuid.uuid4().hex}_{slugify(uploaded.filename)}"
        target_path = app.config["UPLOAD_DIR"] / stored_name
        uploaded.save(target_path)
        g.db.execute(
            """
            INSERT INTO documents (
                profile_id, category_key, title, description, original_name,
                stored_name, uploaded_by, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                profile["id"],
                category_key,
                request.form.get("title", "").strip() or uploaded.filename,
                request.form.get("description", "").strip(),
                uploaded.filename,
                stored_name,
                g.user["id"],
                utcnow(),
            ),
        )
        g.db.commit()
        log_event("document_upload", "documents", f"Dokument für {category_key} hochgeladen", profile["id"])
        push_toast("Das Dokument wurde hochgeladen.", "success", "Upload erfolgreich")
        return redirect(url_for("category_overview", slug=slug, category_key=category_key))

    @app.route("/dokumente/<slug>/<int:document_id>")
    @login_required
    def download_document(slug: str, document_id: int):
        profile, canonical_slug = resolve_profile_by_slug(slug)
        if canonical_slug and canonical_slug != slug:
            return redirect(url_for("download_document", slug=canonical_slug, document_id=document_id))
        if not profile:
            abort(404)
        document = g.db.execute(
            "SELECT * FROM documents WHERE id = ? AND profile_id = ?",
            (document_id, profile["id"]),
        ).fetchone()
        if not document:
            abort(404)
        ensure_profile_access(profile, document["category_key"])
        log_event("document_download", "documents", f"Dokument {document_id} heruntergeladen", profile["id"])
        return send_from_directory(
            app.config["UPLOAD_DIR"],
            document["stored_name"],
            as_attachment=True,
            download_name=document["original_name"],
        )

    @app.route("/dokumente/<slug>/<int:document_id>/loeschen", methods=["POST"])
    @login_required
    def delete_document(slug: str, document_id: int):
        profile, canonical_slug = resolve_profile_by_slug(slug)
        if canonical_slug and canonical_slug != slug:
            return redirect(url_for("delete_document", slug=canonical_slug, document_id=document_id))
        if not profile or g.user["id"] != profile["owner_user_id"]:
            abort(403)
        document = g.db.execute(
            "SELECT * FROM documents WHERE id = ? AND profile_id = ?",
            (document_id, profile["id"]),
        ).fetchone()
        if not document:
            abort(404)
        path = app.config["UPLOAD_DIR"] / document["stored_name"]
        if path.exists():
            path.unlink()
        g.db.execute("DELETE FROM documents WHERE id = ?", (document_id,))
        g.db.commit()
        log_event("document_delete", "documents", f"Dokument {document_id} gelöscht", profile["id"])
        push_toast("Das Dokument wurde gelöscht.", "info", "Dokument entfernt")
        return redirect(url_for("category_overview", slug=slug, category_key=document["category_key"]))

    @app.route("/letzte-wuensche/<slug>", methods=["GET", "POST"])
    @login_required
    def wishes_page(slug: str):
        profile, canonical_slug = resolve_profile_by_slug(slug)
        if canonical_slug and canonical_slug != slug:
            return redirect(url_for("wishes_page", slug=canonical_slug))
        if not profile:
            abort(404)
        ensure_profile_access(profile)
        session["active_profile_slug"] = slug
        wishes = g.db.execute("SELECT * FROM wishes WHERE profile_id = ?", (profile["id"],)).fetchone()
        if request.method == "POST":
            if g.user["id"] != profile["owner_user_id"]:
                abort(403)
            g.db.execute(
                """
                UPDATE wishes SET
                    farewell_message = ?, asset_notes = ?, ceremony_notes = ?,
                    important_contacts = ?, external_links = ?, updated_by = ?, updated_at = ?
                WHERE profile_id = ?
                """,
                (
                    request.form.get("farewell_message", "").strip(),
                    request.form.get("asset_notes", "").strip(),
                    request.form.get("ceremony_notes", "").strip(),
                    request.form.get("important_contacts", "").strip(),
                    request.form.get("external_links", "").strip(),
                    g.user["id"],
                    utcnow(),
                    profile["id"],
                ),
            )
            g.db.commit()
            log_event("wishes_update", "wishes", "Letzte Wünsche aktualisiert", profile["id"])
            push_toast("Die letzten Wünsche wurden gespeichert.", "success", "Änderungen gespeichert")
            return redirect(url_for("wishes_page", slug=slug))
        log_event("wishes_view", "wishes", "Letzte Wünsche geöffnet", profile["id"])
        return render_template("wishes.html", profile=profile, wishes=wishes)

    @app.route("/verwaltung")
    @login_required
    def management():
        owned_profile = get_profile_for_owner(g.user["id"]) if g.user["is_creator"] else None
        users = []
        grants = []
        if owned_profile:
            users = g.db.execute(
                """
                SELECT id, display_name, email, is_admin, is_creator, is_reader, active
                FROM users ORDER BY display_name COLLATE NOCASE
                """
            ).fetchall()
            grants = g.db.execute(
                """
                SELECT grants.*, users.display_name AS grantee_name, users.email AS grantee_email
                FROM grants
                JOIN users ON users.id = grants.grantee_user_id
                WHERE grants.profile_id = ?
                ORDER BY users.display_name, grants.category_key
                """,
                (owned_profile["id"],),
            ).fetchall()
        log_scope = owned_profile["id"] if owned_profile else None
        logs = get_relevant_logs(g.user, owned_profile)[:100]
        return render_template(
            "management.html",
            owned_profile=owned_profile,
            users=users,
            grants=grants,
            logs=logs,
        )

    @app.route("/verwaltung/benutzer/neu", methods=["POST"])
    @login_required
    @creator_required
    def create_user():
        errors, data = validate_user_form(request.form)
        role = data["role"]
        if role in {"creator", "admin"} and not g.user["is_admin"]:
            abort(403)
        if errors:
            for error in errors:
                push_toast(error, "danger", "Benutzer nicht erstellt")
            return redirect(url_for("management"))
        try:
            create_user_with_profile(
                data["display_name"],
                data["email"],
                data["password"],
                role,
                g.user["id"],
            )
            g.db.commit()
            log_event("user_create", "users", f"Benutzer {data['display_name']} angelegt")
            push_toast("Der Benutzer wurde angelegt.", "success", "Benutzer erstellt")
        except sqlite3.IntegrityError:
            push_toast("Diese E-Mail-Adresse ist bereits vergeben.", "danger", "Benutzer nicht erstellt")
        return redirect(url_for("management"))

    @app.route("/verwaltung/benutzer/<int:user_id>/status", methods=["POST"])
    @login_required
    @creator_required
    def toggle_user_status(user_id: int):
        user = g.db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user:
            abort(404)
        if not g.user["is_admin"] and user["is_creator"]:
            abort(403)
        new_status = 0 if user["active"] else 1
        g.db.execute(
            "UPDATE users SET active = ?, updated_at = ? WHERE id = ?",
            (new_status, utcnow(), user_id),
        )
        g.db.commit()
        log_event("user_toggle", "users", f"Benutzer {user['display_name']} Status geändert")
        push_toast("Der Benutzerstatus wurde aktualisiert.", "success", "Status geändert")
        return redirect(url_for("management"))

    @app.route("/verwaltung/freigaben/neu", methods=["POST"])
    @login_required
    @creator_required
    def create_grant():
        profile = get_profile_for_owner(g.user["id"])
        if not profile:
            abort(404)
        grantee_id = int(request.form.get("grantee_user_id", "0"))
        category_key = request.form.get("category_key") or None
        grantee = g.db.execute("SELECT * FROM users WHERE id = ? AND active = 1", (grantee_id,)).fetchone()
        if not grantee or grantee["id"] == g.user["id"]:
            push_toast("Bitte wählen Sie einen anderen aktiven Benutzer für die Freigabe aus.", "danger", "Freigabe nicht erstellt")
            return redirect(url_for("management"))
        if category_key and category_key not in {key for key, _ in APP_CATEGORIES}:
            push_toast("Die gewählte Kategorie ist ungültig.", "danger", "Freigabe nicht erstellt")
            return redirect(url_for("management"))
        try:
            g.db.execute(
                """
                INSERT INTO grants (profile_id, grantee_user_id, category_key, can_export, created_by, created_at)
                VALUES (?, ?, ?, 1, ?, ?)
                """,
                (profile["id"], grantee_id, category_key, g.user["id"], utcnow()),
            )
            g.db.commit()
            smtp_settings = g.db.execute("SELECT * FROM smtp_settings WHERE id = 1").fetchone()
            send_test_or_reset_mail(
                smtp_settings,
                grantee["email"],
                "Aeterna Freigabe",
                f"Ihnen wurde Zugriff auf {profile['title']} gewährt.",
                render_email_html(
                    "Neue Freigabe erhalten",
                    f"Für Sie wurde ein neuer Zugriff in Aeterna freigegeben: {profile['title']}.",
                    [
                        f"Freigabeumfang: {category_label(category_key) if category_key else 'Gesamter Nachlass'}",
                        "Melden Sie sich mit Ihrem Benutzerkonto an, um den freigegebenen Bereich zu öffnen.",
                    ],
                    "Zur Anmeldung",
                    url_for("login", _external=True),
                    "Sie erhalten diese Nachricht, weil Ihnen ein Aeterna-Nachlassbereich freigegeben wurde.",
                ),
            )
            log_event(
                "grant_create",
                "grants",
                f"Freigabe für {grantee['display_name']} erstellt ({category_key or 'gesamt'})",
                profile["id"],
            )
            push_toast("Die Freigabe wurde gespeichert.", "success", "Freigabe erstellt")
        except sqlite3.IntegrityError:
            push_toast("Diese Freigabe existiert bereits.", "warning", "Keine Änderung")
        return redirect(url_for("management"))

    @app.route("/verwaltung/freigaben/<int:grant_id>/loeschen", methods=["POST"])
    @login_required
    @creator_required
    def delete_grant(grant_id: int):
        profile = get_profile_for_owner(g.user["id"])
        grant = g.db.execute(
            "SELECT * FROM grants WHERE id = ? AND profile_id = ?",
            (grant_id, profile["id"] if profile else 0),
        ).fetchone()
        if not grant:
            abort(404)
        g.db.execute("DELETE FROM grants WHERE id = ?", (grant_id,))
        g.db.commit()
        log_event("grant_delete", "grants", f"Freigabe {grant_id} entfernt", profile["id"])
        push_toast("Die Freigabe wurde entfernt.", "info", "Freigabe gelöscht")
        return redirect(url_for("management"))

    @app.route("/export/<slug>")
    @login_required
    def export_profile(slug: str):
        profile, canonical_slug = resolve_profile_by_slug(slug)
        if canonical_slug and canonical_slug != slug:
            return redirect(url_for("export_profile", slug=canonical_slug))
        if not profile:
            abort(404)
        ensure_profile_access(profile)
        categories = []
        for key, label in APP_CATEGORIES:
            if not has_category_access(g.user, profile["id"], key):
                continue
            records = g.db.execute(
                "SELECT * FROM records WHERE profile_id = ? AND category_key = ? ORDER BY title COLLATE NOCASE",
                (profile["id"], key),
            ).fetchall()
            docs = g.db.execute(
                "SELECT * FROM documents WHERE profile_id = ? AND category_key = ? ORDER BY title COLLATE NOCASE",
                (profile["id"], key),
            ).fetchall()
            categories.append({"key": key, "label": label, "records": records, "documents": docs})
        wishes = g.db.execute("SELECT * FROM wishes WHERE profile_id = ?", (profile["id"],)).fetchone()
        log_event("export", "export", "Druckexport geöffnet", profile["id"])
        return render_template("export.html", profile=profile, categories=categories, wishes=wishes)

    @app.route("/hinweis/<slug>")
    def profile_hint(slug: str):
        return redirect(url_for("profile_emergency", slug=slug), code=301)

    @app.route("/notfall/<slug>")
    def profile_emergency(slug: str):
        profile, canonical_slug = resolve_profile_by_slug(slug)
        if canonical_slug and canonical_slug != slug:
            return redirect(url_for("profile_emergency", slug=canonical_slug))
        if not profile:
            abort(404)
        return render_template(
            "profile_hint.html",
            profile=profile,
            emergency_url=build_emergency_url(profile["slug"]),
            emergency_qr_svg=build_qr_svg(build_emergency_url(profile["slug"])),
        )

    @app.route("/admin", methods=["GET", "POST"])
    @login_required
    @admin_required
    def admin():
        smtp_settings = g.db.execute("SELECT * FROM smtp_settings WHERE id = 1").fetchone()
        if request.method == "POST":
            errors = validate_smtp_form(request.form)
            if errors:
                for error in errors:
                    push_toast(error, "danger", "Admin-Einstellungen")
                return redirect(url_for("admin"))
            password = request.form.get("smtp_password", "").strip()
            encrypted = smtp_settings["password_encrypted"]
            if password:
                encrypted = encrypt_secret(password)
            g.db.execute(
                """
                UPDATE smtp_settings SET
                    host = ?, port = ?, username = ?, password_encrypted = ?, sender_email = ?,
                    use_tls = ?, use_ssl = ?, updated_by = ?, updated_at = ?
                WHERE id = 1
                """,
                (
                    request.form.get("host", "").strip(),
                    int(request.form.get("port", "587")),
                    request.form.get("username", "").strip(),
                    encrypted,
                    request.form.get("sender_email", "").strip(),
                    1 if request.form.get("use_tls") else 0,
                    1 if request.form.get("use_ssl") else 0,
                    g.user["id"],
                    utcnow(),
                ),
            )
            g.db.commit()
            log_event("smtp_update", "admin", "SMTP-Einstellungen aktualisiert")
            if request.form.get("test_recipient"):
                refreshed = g.db.execute("SELECT * FROM smtp_settings WHERE id = 1").fetchone()
                success, message = send_test_or_reset_mail(
                    refreshed,
                    request.form.get("test_recipient", "").strip(),
                    "Aeterna Test-E-Mail",
                    "Die SMTP-Konfiguration funktioniert.",
                    render_email_html(
                        "SMTP-Test erfolgreich",
                        "Diese Testnachricht bestätigt, dass Ihre SMTP-Konfiguration in Aeterna grundsätzlich funktioniert.",
                        [
                            "Sie können jetzt Passwort-Reset-Mails und Freigabebenachrichtigungen im selben Design versenden.",
                            "Bitte prüfen Sie auch Spam-Ordner und Absenderdarstellung Ihres Mail-Providers.",
                        ],
                        "Aeterna öffnen",
                        url_for("admin", _external=True),
                        "Diese Testmail wurde manuell im Adminbereich von Aeterna ausgelöst.",
                    ),
                )
                push_toast(message, "success" if success else "danger", "SMTP-Test")
            else:
                push_toast("Die Admin-Einstellungen wurden gespeichert.", "success", "Admin gespeichert")
            return redirect(url_for("admin"))
        stats = {
            "users": g.db.execute("SELECT COUNT(*) AS count FROM users").fetchone()["count"],
            "profiles": g.db.execute("SELECT COUNT(*) AS count FROM profiles").fetchone()["count"],
            "records": g.db.execute("SELECT COUNT(*) AS count FROM records").fetchone()["count"],
            "documents": g.db.execute("SELECT COUNT(*) AS count FROM documents").fetchone()["count"],
        }
        return render_template("admin.html", smtp_settings=smtp_settings, stats=stats)

    @app.context_processor
    def inject_context() -> dict[str, Any]:
        active_profile = None
        visible_profiles = []
        if g.user:
            visible_profiles = get_visible_profiles(g.user)
            if session.get("active_profile_slug"):
                active_profile, canonical_slug = resolve_profile_by_slug(session["active_profile_slug"])
                if canonical_slug and canonical_slug != session.get("active_profile_slug"):
                    session["active_profile_slug"] = canonical_slug
            if not active_profile and visible_profiles:
                active_profile = visible_profiles[0]
                session["active_profile_slug"] = active_profile["slug"]
        return {
            "active_profile": active_profile,
            "visible_profiles": visible_profiles,
            "system_initialized": getattr(g, "system_initialized", False),
        }

    @app.errorhandler(403)
    def forbidden(error):
        return render_template(
            "error.html",
            title="Zugriff nicht erlaubt",
            message="Dieser Bereich ist für Ihr Konto nicht freigegeben oder nur für den Eigentümer bearbeitbar.",
        ), 403

    @app.errorhandler(404)
    def not_found(error):
        return render_template(
            "error.html",
            title="Seite nicht gefunden",
            message="Der angeforderte Inhalt existiert nicht oder wurde entfernt.",
        ), 404


create_app_instance = create_app()


if __name__ == "__main__":
    create_app_instance.run(
        host=create_app_instance.config["HOST"],
        port=create_app_instance.config["PORT"],
        debug=False,
    )
