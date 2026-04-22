# BackUpLife

BackUpLife ist eine kostenlose, deutschsprachige **WebApp (Nachlass App)** für **digitalen Nachlass**: Zugangsdaten, Unterlagen, Geräte, Verträge und persönliche Worte so hinterlassen, dass Angehörige im Notfall schneller Orientierung finden. Die App ist für den Selbstbetrieb gedacht, zum Beispiel auf einem **Raspberry Pi**, NAS oder in einer **VM** (lokal, im Heimnetz oder auf einem Debian‑Server hinter Reverse Proxy).

Slogan: **Alles Wichtige an einem Ort. Für alle Fälle.**

Wichtig: BackUpLife ersetzt kein Testament und ist keine rechtlich verbindliche Verfügung. Es ist eine strukturierte Möglichkeit, Gedanken, Wünsche und praktische Informationen zu hinterlassen. Siehe auch die Seite **/nutzungsbedingungen**.

## Features

- Rollenmodell mit klarer Trennung:
  - **Admin**: genau **ein** Admin (immer der erste Benutzer), verwaltet System/SMTP/Sicherheit
  - **Ersteller**: pflegt den eigenen Nachlass (eigene URL)
  - **Leser**: sieht nur explizit freigegebene Inhalte
- Persönliche Notfall‑URL je Ersteller: `/notfall/<slug>`
- Druckbare **Notfallkarte** (Scheckkartengröße): `/notfall/<slug>/karte`
- Freigaben: gesamter Nachlass oder pro Kategorie
- Kategorie‑Übersicht mit Karten, reduzierte Navigation (4 Hauptpunkte): Dashboard, Digitaler Nachlass, Letzte Wünsche, Verwaltung
- Onlinekonten mit Presets (E‑Mail, Google, Microsoft, Apple, Amazon, eBay, PayPal, Passwortmanager, …)
- Dokumente/Uploads je Kategorie (Quota pro Nachlass, Standard: **100 MB nur für Dokumente/Uploads**)
- E‑Mail‑Verifikation (optional, empfohlen für öffentlich erreichbare Instanzen)
- Passwort‑Reset via SMTP
- Druckexport (neuer Tab)
- Audit‑Logs (Zeit, Benutzer, Aktion, IP, Pfad)
- Security:
  - CSRF‑Schutz für Formulare
  - Rate‑Limit und **gestaffelter Login‑Lockout** (5/10/15 Fehlversuche)
  - **TOTP‑2FA** (optional) und **Admin‑2FA Pflicht** (Default)
- Admin‑Backup‑Download als Archiv (`.zip`)
- Debug/Verifikation: `/version` zeigt Version/Build‑SHA/Build‑Datum (standardmäßig nur lokal erreichbar)

## Kategorien (Digitaler Nachlass)

- Onlinekonten
- Geräte & Datenträger
- Websites & Domains
- Verträge
- Versicherungen
- Nachlassdokumente
- Allgemeines
- Heimnetz & Smarthome

## Tech‑Stack

- Python `Flask`
- `SQLite`
- `Bootstrap 5`
- `cryptography` (Verschlüsselung gespeicherter Zugangsdaten)
- `gunicorn` + `nginx` (Deployment)

## Lokaler Start (CLI)

```bash
cd BackUpLife
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
./scripts/init_env.sh
python3 app.py
```

Danach: `http://127.0.0.1:8000` (beim ersten Aufruf kommt die Ersteinrichtung; keine Demo‑User/Testdaten).

## Debian 13 / Proxmox LXC (Systemd + Nginx)

```bash
sudo bash install_debian13.sh
```

Das Skript installiert Abhängigkeiten, deployed nach `/opt/backuplife`, erzeugt eine sichere `/opt/backuplife/.env` (inkl. zufälliger Keys) und startet den Systemd‑Service.

### Update (Debian 13)

```bash
git pull --ff-only
sudo bash update_debian13.sh
```

Das Update überschreibt **nicht** `instance/` und startet den Service neu. Build‑Infos werden in der `.env` aktualisiert, damit du über `/version` sicher siehst, welcher Stand läuft.

## Sicherheit (Passwörter & Keys)

- Benutzerpasswörter: sicher gehasht gespeichert (kein Klartext).
- Hinterlegte Zugangsdaten: **verschlüsselt** gespeichert (Key: `BACKUPLIFE_APP_KEY`).
- Wichtig: Schütze die `.env` (enthält `BACKUPLIFE_APP_KEY`) und sichere sie separat. Wenn der Key verloren geht, sind gespeicherte Geheimnisse nicht mehr entschlüsselbar.
- Uploads: Dateityp‑Whitelist, max. 20 MB pro Datei; Speicherlimit pro Nachlass (Standard 100 MB, gilt nur für Dokumente/Uploads).

## Wichtige Umgebungsvariablen (Auszug)

- `FLASK_SECRET_KEY`
- `BACKUPLIFE_APP_KEY` (Fallback: `AETERNA_APP_KEY`)
- `BACKUPLIFE_DB_PATH` (Fallback: `AETERNA_DB_PATH`)
- `BACKUPLIFE_UPLOAD_DIR` (Fallback: `AETERNA_UPLOAD_DIR`)
- `BACKUPLIFE_TRUST_PROXY=1` (Reverse‑Proxy Header vertrauen)
- `BACKUPLIFE_COOKIE_SECURE=1` (Secure Cookies für HTTPS; für reines HTTP lokal `0`)
- `BACKUPLIFE_SESSION_LIFETIME_MINUTES=120`
- `BACKUPLIFE_ENFORCE_ADMIN_2FA=1`
- `BACKUPLIFE_ENABLE_2FA=1` (2FA-Features aktivieren; für lokale Tests optional `0`)

## Tests

```bash
source .venv/bin/activate
pytest
```

Die Test‑Suite nutzt eine temporäre DB und hinterlässt keine Testdaten.

## Lizenz

Dieses Projekt steht unter der **PolyForm Noncommercial License** (nicht‑kommerziell). Siehe [LICENSE](./LICENSE).

## Repository‑Dokumente

- [LICENSE](./LICENSE)
- [CONTRIBUTING.md](./CONTRIBUTING.md)
- [SECURITY.md](./SECURITY.md)
- [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md)

<img width="1374" height="781" alt="Bildschirmfoto 2026-04-09 um 18 57 59" src="https://github.com/user-attachments/assets/f4be33ee-3cbb-47e4-af82-27f8a63ec783" />
