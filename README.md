# BackUpLife

BackUpLife ist eine seriöse, deutschsprachige WebApp, um wichtige Informationen für alle Fälle geordnet zu hinterlassen. Die Anwendung trennt Admin, Ersteller und Leser sauber, bietet persönliche URLs pro Ersteller, Freigaben bis auf Kategorie-Ebene, verschlüsselte Speicherung sensibler Zugangsdaten, Audit-Logs und Druckexporte.

Slogan: **Alles Wichtige an einem Ort. Für alle Fälle.**

## Funktionsumfang

- Passwort-Login für `Admin`, `Ersteller` und `Leser`
- Ersteinrichtung ohne Demo- oder Testdaten
- Eigene Notfall-URL pro Ersteller über `/notfall/<slug>` (für Geldbörse/Notfallmappe)
- Navigation mit nur vier Hauptpunkten:
  - `Dashboard`
  - `Digitaler Nachlass`
  - `Letzte Wünsche`
  - `Verwaltung`
- Kategorien im digitalen Nachlass:
  - Onlinekonten
  - Verträge
  - Versicherungen
  - Unterlagen & Notgroschen
  - Heimnetz & Smarthome
  - Dokumente
- Freigaben für den gesamten Nachlass oder nur für einzelne Kategorien
- Dokumentenupload
- E-Mail-Verifikation (Bestätigung vor Login, für öffentliche Instanzen empfohlen)
- Passwort-Reset über SMTP
- Druckansicht / Export
- Audit-Logs mit Zeit, Benutzer, Aktion, Pfad und IP
- Toasts für Erfolg, Warnungen und Fehler
  - Verschlüsseltes Backup (`.zip.enc`) im Adminbereich

## Stack

- `Flask`
- `SQLite`
- `Bootstrap 5`
- `cryptography` für die Verschlüsselung sensibler Fremd-Passwörter
- `gunicorn` für Debian-Deployment

## Lokaler Start

```bash
	cd /backuplife
	python3 -m venv .venv
	source .venv/bin/activate
	pip install -r requirements.txt
	./scripts/init_env.sh
	python3 app.py
	```

Danach ist die App unter [http://127.0.0.1:8000](http://127.0.0.1:8000) erreichbar.

Beim ersten Aufruf erscheint automatisch die Ersteinrichtung. Es werden keine Demo-Benutzer angelegt.

## Validierung und Sicherheit

- Benutzerpasswörter werden gehasht gespeichert
- hinterlegte Zugangsdaten für Fremdkonten werden verschlüsselt gespeichert
- Dateiuploads sind auf erlaubte Formate und 20 MB begrenzt
- Upload-Speicher ist pro Nachlass konfigurierbar (Standard: 100 MB)
- CSRF-Schutz für alle Formulare
- Rate-Limiting für Login/Registrierung/Passwort-Reset
- Formulare prüfen zentrale Eingaben serverseitig
- jede wichtige Aktion erzeugt einen Audit-Log-Eintrag

## Umgebungsvariablen (Auszug)

- `BACKUPLIFE_APP_KEY`: App-Key für Verschlüsselung (fallback: `AETERNA_APP_KEY`)
- `BACKUPLIFE_DB_PATH`: DB-Pfad (fallback: `AETERNA_DB_PATH`)
- `BACKUPLIFE_UPLOAD_DIR`: Upload-Verzeichnis (fallback: `AETERNA_UPLOAD_DIR`)
- `BACKUPLIFE_TRUST_PROXY=1`: X-Forwarded-* Header vertrauen (Reverse Proxy)
- `BACKUPLIFE_COOKIE_SECURE=1`: Secure-Cookies erzwingen (für HTTPS-Betrieb)

## Tests

```bash
source .venv/bin/activate
pytest
```

Die Test-Suite nutzt eine temporäre Datenbank und hinterlässt keine Testdaten im Projekt.

## Debian 13 / Proxmox LXC

```bash
sudo bash install_debian13.sh
```

Das Skript installiert Python, venv, Gunicorn, Nginx und richtet einen Systemd-Service ein. Zusätzlich wird automatisch eine `.env` unter `/opt/backuplife/.env` erzeugt (inkl. zufälliger Secrets), sodass die Instanz direkt startklar ist.

## Repository-Dokumente

- [LICENSE](./LICENSE)
- [CONTRIBUTING.md](./CONTRIBUTING.md)
- [SECURITY.md](./SECURITY.md)
- [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md)
