"""API-key handling for the shared secret between the Gmail Add-on and this backend.

Goal: security that needs no manual setup on each run.

* The key lives in ``backend/.env`` (git-ignored) and is read on every start.
* If the file has no key, one is created once: seeded from the ``LIGHTHOUSE_API_KEY`` environment
  variable if set, otherwise randomly generated. The key itself is never printed to the logs.
"""
from __future__ import annotations

import logging
import os
import secrets
from pathlib import Path
from typing import Optional

logger = logging.getLogger("malicious_email_scorer")

API_KEY_ENV = "LIGHTHOUSE_API_KEY"
DEFAULT_ENV_FILE = Path(__file__).resolve().parent / ".env"


def _clean(value: str) -> str:
    """Strip whitespace and accidental surrounding quotes (a common copy-paste slip)."""
    return value.strip().strip("\"'").strip()


def _read_key_from_file(path: Path) -> str:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return ""
    for line in text.splitlines():
        name, sep, value = line.partition("=")
        if sep and name.strip() == API_KEY_ENV:
            return _clean(value)
    return ""


def load_api_key(env_file: Optional[Path] = None) -> str:
    """Return the shared secret. ``backend/.env`` is the single source of truth.

    If the file has no key yet, one is created: seeded from the ``LIGHTHOUSE_API_KEY``
    environment variable when that is set, otherwise freshly generated.
    """
    path = Path(env_file) if env_file else DEFAULT_ENV_FILE
    from_file = _read_key_from_file(path)
    if from_file:
        return from_file

    key = _clean(os.environ.get(API_KEY_ENV, "")) or secrets.token_urlsafe(32)
    path.write_text(f"{API_KEY_ENV}={key}\n", encoding="utf-8")
    logger.warning(
        "API key saved to %s. Open that file and copy the value into "
        "Apps Script -> Project Settings -> Script Properties as BACKEND_API_KEY.",
        path,
    )
    print(f"\n>>> API key saved to {path}\n>>> Copy the value into Apps Script -> Script Properties -> BACKEND_API_KEY\n", flush=True)
    return key
