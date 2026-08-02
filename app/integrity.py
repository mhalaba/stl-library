"""Weryfikacja pliku przed wydaniem go uzytkownikowi.

Kazde pobranie przechodzi przez check_file(). Kolejnosc kontroli jest celowa -
od najtanszej do najdrozszej, ale zadna nie jest pomijana:

  1. status w bazie musi byc 'signed'
  2. manifest musi zgadzac sie z rekordem w bazie (nazwa, rozmiar, hash)
  3. podpis Ed25519 manifestu musi byc poprawny dla klucza publicznego serwera
  4. SHA-256 pliku na dysku musi zgadzac sie z tym z podpisanego manifestu

Punkt 4 jest tym, ktory faktycznie lapie podmieniony plik. Punkt 3 lapie
sytuacje, w ktorej wlamywacz podmienil plik ORAZ poprawil hash w bazie - bez
klucza prywatnego nie zlozy pasujacego podpisu.
"""

import json
import time
from typing import Any, Dict, Optional, Tuple

from . import config, db, security, storage


class IntegrityError(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


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
    """Rzuca IntegrityError, jesli cokolwiek sie nie zgadza.

    deep=False pomija ponowne liczenie SHA-256 calego pliku (uzywane tam, gdzie
    tresc pliku i tak nie jest wydawana - np. na listingu katalogu).
    """
    if file_row["status"] == "quarantined":
        raise IntegrityError("plik jest w kwarantannie po nieudanej weryfikacji")
    if file_row["status"] != "signed":
        raise IntegrityError("plik nie ma jeszcze zlozonego podpisu")

    manifest = parse_manifest(file_row)
    if manifest is None:
        raise IntegrityError("brak manifestu albo manifest jest uszkodzony")

    if manifest.get("schema") != security.MANIFEST_SCHEMA:
        raise IntegrityError("nieznana wersja manifestu")

    # Manifest kontra rekord w bazie. Rozjazd oznacza, ze ktos ruszal baze.
    if (
        manifest.get("sha256") != file_row["sha256"]
        or manifest.get("filename") != file_row["filename"]
        or int(manifest.get("size", -1)) != int(file_row["size"])
    ):
        raise IntegrityError("podpisany manifest nie zgadza sie z wpisem w katalogu")

    public = security.load_public_key()
    if public is None:
        raise IntegrityError("serwer nie ma skonfigurowanego klucza publicznego")

    if manifest.get("key_id") != security.key_id(security.public_key_hex()):
        raise IntegrityError("manifest podpisany innym kluczem niz aktualny")

    if not file_row.get("signature"):
        raise IntegrityError("brak podpisu")

    if not security.verify_manifest(manifest, file_row["signature"], public):
        raise IntegrityError("podpis Ed25519 jest nieprawidlowy")

    if deep:
        ok, problem = storage.verify_stored_file(
            file_row["storage_path"], manifest["sha256"]
        )
        if not ok:
            raise IntegrityError("plik na dysku nie zgadza sie z podpisem: {}".format(problem))


def quarantine(file_id: int, reason: str) -> None:
    db.execute("UPDATE files SET status = 'quarantined' WHERE id = ?", (file_id,))
    db.audit("file.quarantined", None, "file_id={} powod={}".format(file_id, reason))


def guard_download(file_row: Dict[str, Any]) -> None:
    """check_file z automatyczna kwarantanna, gdy weryfikacja padnie."""
    try:
        check_file(file_row, deep=True)
    except IntegrityError as exc:
        if file_row["status"] != "quarantined":
            quarantine(file_row["id"], exc.reason)
        raise


def sign_file_row(file_row: Dict[str, Any], model_slug: str) -> Tuple[bool, str]:
    """Podpisuje plik kluczem prywatnym z konfiguracji (tryb online).

    Zwraca (czy_podpisano, komunikat).
    """
    private = security.load_private_key()
    if private is None:
        return False, "brak klucza prywatnego na serwerze (tryb offline)"

    public_hex = private.public_key().public_bytes_raw().hex()
    if config.SIGNING_PUBLIC_KEY_HEX and config.SIGNING_PUBLIC_KEY_HEX != public_hex:
        return False, "klucz prywatny nie pasuje do skonfigurowanego klucza publicznego"

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
    return True, "podpisano"


def sidecar(file_row: Dict[str, Any]) -> Dict[str, Any]:
    """Dokument .sig.json wydawany razem z plikiem - pozwala zweryfikowac
    pobrany plik offline, bez zaufania do serwera."""
    return {
        "manifest": parse_manifest(file_row),
        "signature": file_row.get("signature"),
        "algorithm": "Ed25519",
        "public_key": security.public_key_hex(),
        "key_id": file_row.get("key_id"),
        "how_to_verify": "python3 tools/verify_stl.py <plik.stl> <plik.stl.sig.json>",
    }
