"""Konfiguracja czytana ze zmiennych srodowiskowych.

Wszystkie sekrety pochodza z env - nic wrazliwego nie siedzi w repozytorium.
Plik .env.example opisuje komplet zmiennych.
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


# --- Sciezki -----------------------------------------------------------------

DATA_DIR = Path(_env("STL_DATA_DIR", str(BASE_DIR / "data"))).resolve()
STORAGE_DIR = Path(_env("STL_STORAGE_DIR", str(DATA_DIR / "storage"))).resolve()
DB_PATH = Path(_env("STL_DB_PATH", str(DATA_DIR / "library.db"))).resolve()
STATIC_DIR = BASE_DIR / "static"

# --- Sekrety -----------------------------------------------------------------

# Klucz do podpisywania ciasteczek sesji i tokenow pobrania (HMAC-SHA256).
# W produkcji MUSI byc ustawiony na stala wartosc, inaczej restart serwera
# wylogowuje wszystkich i uniewaznia wystawione linki.
SECRET_KEY = _env("STL_SECRET_KEY")
SECRET_KEY_IS_EPHEMERAL = SECRET_KEY is None
if SECRET_KEY is None:
    SECRET_KEY = secrets.token_hex(32)

# Klucz publiczny Ed25519 (hex, 32 bajty) - sluzy do WERYFIKACJI podpisow.
# Serwer potrzebuje wylacznie jego. Musi byc ustawiony w produkcji.
SIGNING_PUBLIC_KEY_HEX = _env("STL_SIGNING_PUBLIC_KEY")

# Klucz prywatny Ed25519 (hex, 32 bajty) - sluzy do SKLADANIA podpisow.
# Tryb ONLINE: serwer go zna i podpisuje pliki od razu przy wgraniu (wygodne,
#              ale wlamanie na serwer = mozliwosc podpisania podmienionego pliku).
# Tryb OFFLINE (zalecany): tego zmiennej NIE ustawiasz na serwerze. Pliki laduja
#              w stanie "pending", a podpisy skladasz na osobnej maszynie
#              narzedziem tools/sign_pending.py.
SIGNING_PRIVATE_KEY_HEX = _env("STL_SIGNING_PRIVATE_KEY")

ONLINE_SIGNING = SIGNING_PRIVATE_KEY_HEX is not None

# --- Zachowanie aplikacji ----------------------------------------------------

# Nazwa wydawcy wpisywana do manifestu - czesc podpisywanych danych.
PUBLISHER = _env("STL_PUBLISHER", "stl-library")

# E-mail pierwszego administratora. Konto zakladane przy starcie, jesli
# nie istnieje, z haslem z STL_ADMIN_PASSWORD.
ADMIN_EMAIL = _env("STL_ADMIN_EMAIL")
ADMIN_PASSWORD = _env("STL_ADMIN_PASSWORD")

# Czas zycia sesji i jednorazowego linku do pobrania.
SESSION_TTL_SECONDS = int(_env("STL_SESSION_TTL", str(14 * 24 * 3600)))
DOWNLOAD_TOKEN_TTL_SECONDS = int(_env("STL_DOWNLOAD_TTL", "300"))

# Limit rozmiaru wgrywanego pliku.
MAX_UPLOAD_BYTES = int(_env("STL_MAX_UPLOAD_MB", "256")) * 1024 * 1024

# Ile nieudanych logowan na (e-mail, IP) w oknie czasowym.
LOGIN_MAX_ATTEMPTS = int(_env("STL_LOGIN_MAX_ATTEMPTS", "10"))
LOGIN_WINDOW_SECONDS = int(_env("STL_LOGIN_WINDOW", "900"))

# Ciasteczko sesji z flaga Secure (wymaga HTTPS). Wylacz tylko na localhoscie.
COOKIE_SECURE = _flag("STL_COOKIE_SECURE", True)

# Czy pozwalac na samodzielna rejestracje kont.
ALLOW_REGISTRATION = _flag("STL_ALLOW_REGISTRATION", True)
