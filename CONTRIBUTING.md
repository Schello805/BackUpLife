# Contributing

Vielen Dank für Ihr Interesse an Aeterna.

## Grundsätze

- Bitte halten Sie die Nutzerführung ruhig, seriös und klar.
- Neue Funktionen sollten die kleine Hauptnavigation nicht aufblähen.
- Sicherheitsrelevante Änderungen müssen nachvollziehbar dokumentiert werden.
- Keine Demo-Daten oder Beispielzugänge im ausgelieferten System hinterlassen.

## Lokale Entwicklung

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 smoke_test.py
python3 app.py
```

## Pull Requests

- Bitte beschreiben Sie fachliche Auswirkungen klar.
- Bitte nennen Sie die durchgeführten Tests.
- UI-Änderungen sollten möglichst Screenshots enthalten.
