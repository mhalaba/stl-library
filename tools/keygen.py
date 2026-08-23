#!/usr/bin/env python3
"""Generate an Ed25519 key pair for the library.

    python3 tools/keygen.py

The PUBLIC key (STL_SIGNING_PUBLIC_KEY) goes on the server. It verifies
signatures and is meant to be public.

The PRIVATE key (STL_SIGNING_PRIVATE_KEY) creates signatures. Keep it off the
server: on a separate machine, a hardware key, or in a password manager. If you
put it on the server, then breaking into the server is enough to swap a file
and produce a valid signature for it - which is exactly what this mechanism
exists to prevent.
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

    print("Ed25519 key pair generated.")
    print("Key identifier (key_id): {}\n".format(key_id))
    print("--- FOR THE SERVER (.env) ------------------------------------------")
    print("STL_SIGNING_PUBLIC_KEY={}".format(public_hex))
    print()
    print("--- SIGNING MACHINE ONLY - DO NOT PUT THIS ON THE SERVER -----------")
    print("STL_SIGNING_PRIVATE_KEY={}".format(private_hex))
    print()
    print("Losing the private key means re-signing the whole library with a new")
    print("one. Keep an offline backup.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
