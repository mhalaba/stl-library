"""The check a file goes through before it is handed to anyone.

Every download runs check_file(). The order is deliberate — cheapest first —
but nothing is skipped:

  1. the database status must be 'signed'
  2. the manifest must agree with the catalogue row (name, size, digest)
  3. the Ed25519 signature over the manifest must verify against the server's
     public key
  4. the SHA-256 of the file on disk must match the one inside the signed
     manifest

Step 4 is what actually catches a swapped file. Step 3 catches the case where
an intruder swapped the file *and* corrected the digest in the database —
without the private key they cannot produce a matching signature.
"""

import json
import time
from typing import Any, Dict, Optional, Tuple

from . import config, db, messages, security, storage


class IntegrityError(Exception):
    """Carries a message key so the reason can be shown in either language."""

    def __init__(self, key: str, **params: Any):
        super().__init__(key)
        self.key = key
        self.params = params

    def reason(self, lang: Optional[str] = None) -> str:
        return messages.t(self.key, lang, **self.params)


def parse_manifest(file_row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    raw = file_row.get("manifest")
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None


def check_file(file_row: Dict[str, Any], deep: bool = True) -> None:
    """Raise IntegrityError if anything does not add up.

    deep=False skips re-hashing the whole file. Used where the content is not
    being served anyway — issuing a download link, listing a catalogue page.
    """
    if file_row["status"] == "quarantined":
        raise IntegrityError("integrity.quarantined")
    if file_row["status"] != "signed":
        raise IntegrityError("integrity.unsigned")

    manifest = parse_manifest(file_row)
    if manifest is None:
        raise IntegrityError("integrity.manifest_missing")

    if manifest.get("schema") != security.MANIFEST_SCHEMA:
        raise IntegrityError("integrity.schema_unknown")

    # Manifest against the database row. A divergence means someone edited the
    # database.
    if (
        manifest.get("sha256") != file_row["sha256"]
        or manifest.get("filename") != file_row["filename"]
        or int(manifest.get("size", -1)) != int(file_row["size"])
    ):
        raise IntegrityError("integrity.catalog_mismatch")

    public = security.load_public_key()
    if public is None:
        raise IntegrityError("integrity.no_public_key")

    if manifest.get("key_id") != security.key_id(security.public_key_hex()):
        raise IntegrityError("integrity.key_mismatch")

    if not file_row.get("signature"):
        raise IntegrityError("integrity.signature_missing")

    if not security.verify_manifest(manifest, file_row["signature"], public):
        raise IntegrityError("integrity.signature_invalid")

    if deep:
        ok, problem = storage.verify_stored_file(file_row["storage_path"], manifest["sha256"])
        if not ok:
            key, params = problem
            raise IntegrityError("integrity.disk_mismatch", reason=messages.t(key, None, **params))


def quarantine(file_id: int, reason: str) -> None:
    db.execute("UPDATE files SET status = 'quarantined' WHERE id = ?", (file_id,))
    db.audit("file.quarantined", None, "file_id={} reason={}".format(file_id, reason))


def guard_download(file_row: Dict[str, Any]) -> None:
    """check_file, quarantining the file automatically when the check fails."""
    try:
        check_file(file_row, deep=True)
    except IntegrityError as exc:
        if file_row["status"] != "quarantined":
            quarantine(file_row["id"], exc.reason("en"))
        raise


def sign_file_row(file_row: Dict[str, Any], model_slug: str) -> Tuple[bool, str]:
    """Sign a file with the private key from the configuration (online mode).

    Returns (signed, note). The note is internal, English only.
    """
    private = security.load_private_key()
    if private is None:
        return False, "no private key on the server (offline mode)"

    public_hex = private.public_key().public_bytes_raw().hex()
    if config.SIGNING_PUBLIC_KEY_HEX and config.SIGNING_PUBLIC_KEY_HEX != public_hex:
        return False, "the private key does not match the configured public key"

    manifest = security.build_manifest(
        model_slug=model_slug,
        filename=file_row["filename"],
        size=int(file_row["size"]),
        sha256_hex=file_row["sha256"],
        uploaded_at=int(file_row["uploaded_at"]),
        key_id_hex=security.key_id(public_hex),
    )
    signature = security.sign_manifest(manifest, private)

    db.execute(
        "UPDATE files SET manifest = ?, signature = ?, key_id = ?, signed_at = ?, "
        "status = 'signed' WHERE id = ?",
        (
            json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
            signature,
            manifest["key_id"],
            int(time.time()),
            file_row["id"],
        ),
    )
    return True, "signed"


def sidecar(file_row: Dict[str, Any]) -> Dict[str, Any]:
    """The .sig.json document handed out alongside a file, so the download can
    be verified offline without trusting this server."""
    return {
        "manifest": parse_manifest(file_row),
        "signature": file_row.get("signature"),
        "algorithm": "Ed25519",
        "public_key": security.public_key_hex(),
        "key_id": file_row.get("key_id"),
        "how_to_verify": "python3 tools/verify_stl.py <file.stl> <file.stl.sig.json>",
    }
