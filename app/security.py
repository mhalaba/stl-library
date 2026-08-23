"""The library's cryptography.

Three independent layers, each answering a different question:

1. SHA-256 of the file      -> INTEGRITY. Catches any change to the bytes.
2. Ed25519 manifest signature -> AUTHENTICITY. Catches a swap that comes with a
                               matching edit to the digest in the database. The
                               private key can (and should) live off the server,
                               so an intruder cannot forge a signature.
3. HMAC-SHA256 token        -> ACCESS CONTROL. Limits who may download a file,
                               and for how long.

The token in layer 3 does NOT protect against a swapped file. Layers 1 and 2 do.
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


# --- Encoding ----------------------------------------------------------------


def b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64d(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


# --- Passwords ---------------------------------------------------------------


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


# --- Signed tokens (session, download link) ----------------------------------


def _sign_hmac(payload: bytes, purpose: str) -> bytes:
    key = hmac.new(
        config.SECRET_KEY.encode("utf-8"), purpose.encode("utf-8"), hashlib.sha256
    ).digest()
    return hmac.new(key, payload, hashlib.sha256).digest()


def make_token(data: Dict[str, Any], ttl_seconds: int, purpose: str) -> str:
    """Token = base64(json) . base64(HMAC). Readable, but not forgeable.

    `purpose` is mixed into the key, so a session token cannot be replayed as a
    download token or vice versa.
    """
    body = dict(data)
    body["exp"] = int(time.time()) + ttl_seconds
    payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "{}.{}".format(b64e(payload), b64e(_sign_hmac(payload, purpose)))


def read_token(token: str, purpose: str) -> Optional[Dict[str, Any]]:
    """Return the token body, or None if the signature or the deadline fails."""
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


# --- Ed25519: manifest and file signature ------------------------------------


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
    """Short identifier for a key - goes into the manifest and HTTP headers."""
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
    """One deterministic byte representation of a manifest.

    The signature covers exactly these bytes, so canonicalisation has to be
    identical on the server, in the signing tool and in the verifier.
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


# --- File digest -------------------------------------------------------------


def sha256_file(path, chunk_size: int = 1024 * 1024) -> Tuple[str, int]:
    """Return (sha256 hex, size in bytes). Reads in chunks."""
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
