#!/usr/bin/env python3
"""Podpisuje pliki czekajace w bibliotece - z maszyny OFFLINE.

Ten skrypt uruchamiasz na komputerze, na ktorym trzymasz klucz prywatny.
Serwer nigdy tego klucza nie widzi.

    export STL_SIGNING_PRIVATE_KEY=<hex klucza prywatnego>
    python3 tools/sign_pending.py --url https://twoja-biblioteka.pl \\
                                  --email admin@example.com

Skrypt loguje sie jako administrator, pobiera liste plikow bez podpisu,
odtwarza dla kazdego manifest, podpisuje go i odsyla sam podpis.
"""

import argparse
import getpass
import hashlib
import http.cookiejar
import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

MANIFEST_SCHEMA = "stl-library/manifest/v1"


class Client:
    def __init__(self, base_url: str):
        self.base = base_url.rstrip("/")
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar)
        )
        self.csrf: Optional[str] = None

    def request(self, method: str, path: str, body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        data = None
        headers = {"Accept": "application/json"}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if self.csrf:
            headers["X-CSRF-Token"] = self.csrf

        req = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with self.opener.open(req, timeout=60) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")
            raise SystemExit("Blad {} przy {} {}: {}".format(exc.code, method, path, detail))

    def login(self, email: str, password: str) -> None:
        result = self.request("POST", "/api/auth/login", {"email": email, "password": password})
        if not result.get("is_admin"):
            raise SystemExit("To konto nie ma uprawnien administratora.")
        self.csrf = result.get("csrf")


def canonical(manifest: Dict[str, Any]) -> bytes:
    return json.dumps(
        manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Podpisywanie plikow STL offline")
    parser.add_argument("--url", required=True, help="adres biblioteki, np. https://biblioteka.pl")
    parser.add_argument("--email", required=True, help="e-mail konta administratora")
    parser.add_argument("--dry-run", action="store_true", help="pokaz, co zostaloby podpisane")
    args = parser.parse_args()

    private_hex = os.environ.get("STL_SIGNING_PRIVATE_KEY")
    if not private_hex:
        print("Ustaw STL_SIGNING_PRIVATE_KEY przed uruchomieniem.", file=sys.stderr)
        return 2

    private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_hex))
    public_raw = private.public_key().public_bytes_raw()
    local_key_id = hashlib.sha256(public_raw).hexdigest()[:16]

    client = Client(args.url)
    client.login(args.email, getpass.getpass("Haslo administratora: "))

    listing = client.request("GET", "/api/admin/pending")
    server_key_id = listing.get("key_id")
    if server_key_id and server_key_id != local_key_id:
        raise SystemExit(
            "Klucz prywatny ({}) nie pasuje do klucza publicznego serwera ({}).".format(
                local_key_id, server_key_id
            )
        )

    pending = listing.get("pending", [])
    if not pending:
        print("Nie ma nic do podpisania.")
        return 0

    publisher = listing.get("publisher", "stl-library")
    signed = 0
    for item in pending:
        manifest = {
            "schema": MANIFEST_SCHEMA,
            "publisher": publisher,
            "model": item["model_slug"],
            "filename": item["filename"],
            "size": int(item["size"]),
            "sha256": item["sha256"],
            "uploaded_at": int(item["uploaded_at"]),
            "key_id": local_key_id,
        }
        print("{}  {}  {}".format(item["filename"], item["sha256"][:16], item["model_slug"]))
        if args.dry_run:
            continue

        signature = private.sign(canonical(manifest)).hex()
        client.request(
            "POST",
            "/api/admin/signatures",
            {"file_id": item["id"], "manifest": manifest, "signature": signature},
        )
        signed += 1

    print("\nPodpisano plikow: {}".format(signed))
    return 0


if __name__ == "__main__":
    sys.exit(main())
