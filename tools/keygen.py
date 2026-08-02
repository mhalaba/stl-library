#!/usr/bin/env python3
"""Generuje pare kluczy Ed25519 dla biblioteki.

    python3 tools/keygen.py

Klucz PUBLICZNY (STL_SIGNING_PUBLIC_KEY) idzie na serwer - sluzy do sprawdzania
podpisow i jest jawny.

Klucz PRYWATNY (STL_SIGNING_PRIVATE_KEY) sluzy do skladania podpisow. Trzymaj go
poza serwerem: na osobnym komputerze, kluczu sprzetowym albo w menedzerze hasel.
Jesli wgrasz go na serwer, wlamanie na serwer wystarczy, zeby podmienic plik
i zlozyc do niego poprawny podpis - a to jest dokladnie to, przed czym ten
mechanizm ma chronic.
"""

import hashlib
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def main() -> int:
    private = Ed25519PrivateKey.generate()
    private_hex = private.private_bytes_raw().hex()
    public_raw = private.public_key().public_bytes_raw()
    public_hex = public_raw.hex()
    key_id = hashlib.sha256(public_raw).hexdigest()[:16]

    print("Wygenerowano pare kluczy Ed25519.")
    print("Identyfikator klucza (key_id): {}\n".format(key_id))
    print("--- NA SERWER (plik .env) ------------------------------------------")
    print("STL_SIGNING_PUBLIC_KEY={}".format(public_hex))
    print()
    print("--- TYLKO NA MASZYNIE PODPISUJACEJ - NIE WGRYWAJ NA SERWER ---------")
    print("STL_SIGNING_PRIVATE_KEY={}".format(private_hex))
    print()
    print("Zgubienie klucza prywatnego oznacza koniecznosc podpisania calej")
    print("biblioteki od nowa nowym kluczem. Zrob kopie zapasowa offline.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
