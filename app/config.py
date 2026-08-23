"""Configuration read from environment variables.

Every secret comes from the environment - nothing sensitive lives in the
repository. See .env.example for the full list.
"""

import os
import secrets
from pathlib import Path
from typing import Optional

BASE_DIR = Path(__file__).resolve().parent.parent


def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    return value


def _flag(name: str, default: bool = False) -> bool:
    raw = _env(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


# --- Paths -------------------------------------------------------------------

DATA_DIR = Path(_env("STL_DATA_DIR", str(BASE_DIR / "data"))).resolve()
STORAGE_DIR = Path(_env("STL_STORAGE_DIR", str(DATA_DIR / "storage"))).resolve()
DB_PATH = Path(_env("STL_DB_PATH", str(DATA_DIR / "library.db"))).resolve()
STATIC_DIR = BASE_DIR / "static"

# --- Secrets -----------------------------------------------------------------

# Signs session cookies and download tokens (HMAC-SHA256). In production this
# MUST be set to a fixed value; otherwise a restart signs everyone out and
# invalidates every issued link.
SECRET_KEY = _env("STL_SECRET_KEY")
SECRET_KEY_IS_EPHEMERAL = SECRET_KEY is None
if SECRET_KEY is None:
    SECRET_KEY = secrets.token_hex(32)

# Ed25519 public key (hex, 32 bytes) - used to VERIFY signatures. The server
# needs only this one. Required in production.
SIGNING_PUBLIC_KEY_HEX = _env("STL_SIGNING_PUBLIC_KEY")

# Ed25519 private key (hex, 32 bytes) - used to CREATE signatures.
# ONLINE mode:  the server holds it and signs files on upload (convenient, but
#               a server compromise means an attacker can sign a swapped file).
# OFFLINE mode (recommended): do not set this on the server. Uploads sit in the
#               "pending" state and you sign them from a separate machine with
#               tools/sign_pending.py.
SIGNING_PRIVATE_KEY_HEX = _env("STL_SIGNING_PRIVATE_KEY")

ONLINE_SIGNING = SIGNING_PRIVATE_KEY_HEX is not None

# --- Behaviour ---------------------------------------------------------------

# Publisher name written into every manifest - part of the signed data.
PUBLISHER = _env("STL_PUBLISHER", "stl-library")

# First administrator account, created on startup if it does not exist yet.
ADMIN_EMAIL = _env("STL_ADMIN_EMAIL")
ADMIN_PASSWORD = _env("STL_ADMIN_PASSWORD")

# Lifetime of a session and of a single download link.
SESSION_TTL_SECONDS = int(_env("STL_SESSION_TTL", str(14 * 24 * 3600)))
DOWNLOAD_TOKEN_TTL_SECONDS = int(_env("STL_DOWNLOAD_TTL", "300"))

# Upload size limit.
MAX_UPLOAD_BYTES = int(_env("STL_MAX_UPLOAD_MB", "256")) * 1024 * 1024

# Failed sign-ins allowed per (e-mail, IP) within the window.
LOGIN_MAX_ATTEMPTS = int(_env("STL_LOGIN_MAX_ATTEMPTS", "10"))
LOGIN_WINDOW_SECONDS = int(_env("STL_LOGIN_WINDOW", "900"))

# Session cookie with the Secure flag (requires HTTPS). Turn off on localhost.
COOKIE_SECURE = _flag("STL_COOKIE_SECURE", True)

# Whether visitors may create their own accounts.
ALLOW_REGISTRATION = _flag("STL_ALLOW_REGISTRATION", True)

# Interface language used when the visitor has expressed no preference.
DEFAULT_LANGUAGE = _env("STL_DEFAULT_LANGUAGE", "en")
