"""Kryptografia biblioteki.

Trzy niezalezne warstwy - kazda odpowiada za co innego:

1. SHA-256 pliku            -> INTEGRALNOSC. Wykrywa kazda zmiane bajtow.
2. Podpis Ed25519 manifestu -> AUTENTYCZNOSC. Wykrywa podmiane, ktorej
                               towarzyszy podmiana hasha w bazie danych.
                               Klucz prywatny moze (i powinien) lezec poza
                               serwerem, wiec wlamywacz nie podrobi podpisu.
3. Token HMAC-SHA256        -> KONTROLA DOSTEPU. Ogranicza, kto i jak dlugo
                               moze pobrac dany plik.

Sam token z punktu 3 NIE chroni przed podmiana pliku - robia to punkty 1 i 2.
"""

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Any, Dict, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from . import config

MANIFEST_SCHEMA = "stl-library/manifest/v1"
PBKDF2_ITERATIONS = 260_000


# --- Kodowanie ---------------------------------------------------------------


def b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64d(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


# --- Hasla -------------------------------------------------------------------


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return "pbkdf2_sha256${}${}${}".format(PBKDF2_ITERATIONS, b64e(salt), b64e(dk))


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iterations, salt_b64, hash_b64 = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), b64d(salt_b64), int(iterations)
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(dk, b64d(hash_b64))


# --- Podpisane tokeny (sesja, link do pobrania) -------------------------------


def _sign_hmac(payload: bytes, purpose: str) -> bytes:
    key = hmac.new(
        config.SECRET_KEY.encode("utf-8"), purpose.encode("utf-8"), hashlib.sha256
    ).digest()
    return hmac.new(key, payload, hashlib.sha256).digest()


def make_token(data: Dict[str, Any], ttl_seconds: int, purpose: str) -> str:
    """Token = base64(json) . base64(HMAC). Nieszyfrowany, ale niepodrabialny."""
    body = dict(data)
    body["exp"] = int(time.time()) + ttl_seconds
    payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "{}.{}".format(b64e(payload), b64e(_sign_hmac(payload, purpose)))


def read_token(token: str, purpose: str) -> Optional[Dict[str, Any]]:
    """Zwraca zawartosc tokenu albo None, jesli podpis lub termin sie nie zgadza."""
    try:
        payload_b64, signature_b64 = token.split(".", 1)
        payload = b64d(payload_b64)
        signature = b64d(signature_b64)
    except (ValueError, TypeError):
        return None

    if not hmac.compare_digest(signature, _sign_hmac(payload, purpose)):
        return None

    try:
        body = json.loads(payload.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None

    if not isinstance(body, dict) or int(body.get("exp", 0)) < int(time.time()):
        return None
    return body


# --- Ed25519: manifest i podpis pliku ----------------------------------------


def load_private_key() -> Optional[Ed25519PrivateKey]:
    if not config.SIGNING_PRIVATE_KEY_HEX:
        return None
    return Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(config.SIGNING_PRIVATE_KEY_HEX)
    )


def load_public_key() -> Optional[Ed25519PublicKey]:
    if config.SIGNING_PUBLIC_KEY_HEX:
        return Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(config.SIGNING_PUBLIC_KEY_HEX)
        )
    private = load_private_key()
    if private is not None:
        return private.public_key()
    return None


def public_key_hex() -> Optional[str]:
    key = load_public_key()
    if key is None:
        return None
    return key.public_bytes_raw().hex()


def key_id(public_hex: str) -> str:
    """Krotki identyfikator klucza - trafia do manifestu i naglowkow HTTP."""
    return hashlib.sha256(bytes.fromhex(public_hex)).hexdigest()[:16]


def build_manifest(
    model_slug: str,
    filename: str,
    size: int,
    sha256_hex: str,
    uploaded_at: int,
    key_id_hex: str,
) -> Dict[str, Any]:
    return {
        "schema": MANIFEST_SCHEMA,
        "publisher": config.PUBLISHER,
        "model": model_slug,
        "filename": filename,
        "size": size,
        "sha256": sha256_hex,
        "uploaded_at": uploaded_at,
        "key_id": key_id_hex,
    }


def canonical(manifest: Dict[str, Any]) -> bytes:
    """Jedna, deterministyczna reprezentacja bajtowa manifestu.

    Podpis dotyczy dokladnie tych bajtow, wiec kanonikalizacja musi byc
    identyczna po stronie serwera, narzedzia podpisujacego i weryfikatora.
    """
    return json.dumps(
        manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sign_manifest(manifest: Dict[str, Any], private: Ed25519PrivateKey) -> str:
    return private.sign(canonical(manifest)).hex()


def verify_manifest(
    manifest: Dict[str, Any], signature_hex: str, public: Ed25519PublicKey
) -> bool:
    try:
        public.verify(bytes.fromhex(signature_hex), canonical(manifest))
        return True
    except (InvalidSignature, ValueError):
        return False


# --- Hash pliku --------------------------------------------------------------


def sha256_file(path, chunk_size: int = 1024 * 1024) -> Tuple[str, int]:
    """Zwraca (sha256 hex, rozmiar w bajtach). Czyta strumieniowo."""
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size
