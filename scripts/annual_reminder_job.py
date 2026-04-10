#!/usr/bin/env python3
from __future__ import annotations

import sys


def main() -> int:
    try:
        import app as app_module
    except Exception as exc:  # pragma: no cover
        print(f"Could not import app module: {exc}", file=sys.stderr)
        return 2

    flask_app = app_module.create_app_instance()
    with flask_app.app_context():
        result = app_module.run_annual_reminder_job()
    sent = int(result.get("sent") or 0)
    skipped = int(result.get("skipped") or 0)
    reason = result.get("reason") or ""
    print(f"annual_reminder_job: sent={sent} skipped={skipped} reason={reason}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

