# Aeterna

Aeterna ist eine seriöse, deutschsprachige WebApp zur Verwaltung eines digitalen Nachlasses für Familien. Die Anwendung trennt Admin, Ersteller und Leser sauber, bietet persönliche Nachlass-URLs pro Ersteller, echte Freigaben bis auf Kategorie-Ebene, verschlüsselte Speicherung sensibler Zugangsdaten, Audit-Logs und Druckexporte.

![Aeterna Logo](./Logo_aeterna.png)

## Funktionsumfang

- Passwort-Login für `Admin`, `Ersteller` und `Leser`
- Ersteinrichtung ohne Demo- oder Testdaten
- Eigene Nachlass-URL pro Ersteller über `/hinweis/<slug>`
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
- Passwort-Reset über SMTP
- Druckansicht / Export
- Audit-Logs mit Zeit, Benutzer, Aktion, Pfad und IP
- Toasts für Erfolg, Warnungen und Fehler

## Stack

- `Flask`
- `SQLite`
- `Bootstrap 5`
- `cryptography` für die Verschlüsselung sensibler Fremd-Passwörter
- `gunicorn` für Debian-Deployment

## Lokaler Start

```bash
cd /Users/michael/Programmerierung/Aeterna
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python3 app.py
```

Danach ist die App unter [http://127.0.0.1:8000](http://127.0.0.1:8000) erreichbar.

Beim ersten Aufruf erscheint automatisch die Ersteinrichtung. Es werden keine Demo-Benutzer angelegt.

## Validierung und Sicherheit

- Benutzerpasswörter werden gehasht gespeichert
- hinterlegte Zugangsdaten für Fremdkonten werden verschlüsselt gespeichert
- Dateiuploads sind auf erlaubte Formate und 20 MB begrenzt
- Formulare prüfen zentrale Eingaben serverseitig
- jede wichtige Aktion erzeugt einen Audit-Log-Eintrag

## Tests

```bash
source .venv/bin/activate
python3 smoke_test.py
```

Der Smoke-Test nutzt eine temporäre Datenbank und hinterlässt keine Testdaten im Projekt.

## Debian 13 / Proxmox LXC

```bash
sudo bash install_debian13.sh
```

Das Skript installiert Python, venv, Gunicorn, Nginx und richtet einen Systemd-Service ein.

## Repository-Dokumente

- [LICENSE](./LICENSE)
- [CONTRIBUTING.md](./CONTRIBUTING.md)
- [SECURITY.md](./SECURITY.md)
- [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md)
