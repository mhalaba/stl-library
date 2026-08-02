#!/usr/bin/env python3
"""Sprawdza, czy pobrany plik STL jest tym, ktory wydala biblioteka.

    python3 verify_stl.py model.stl model.stl.sig.json

Skrypt nie laczy sie z siecia i nie ma zadnych zaleznosci - dziala na samym
Pythonie 3. Jesli w systemie jest biblioteka `cryptography`, uzyje jej;
w przeciwnym razie skorzysta z wbudowanej implementacji Ed25519 (RFC 8032).

Opcjonalnie mozna podac oczekiwany klucz publiczny, zeby nie ufac temu, ktory
przyszedl razem z plikiem:

    python3 verify_stl.py model.stl model.stl.sig.json --pubkey <hex>
"""

import argparse
import hashlib
import json
import sys
from typing import Any, Dict, Optional

# --- Ed25519 (RFC 8032, tylko weryfikacja) -----------------------------------

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _recover_x(y: int, sign: int) -> Optional[int]:
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_GY = 4 * pow(5, _P - 2, _P) % _P
_GX = _recover_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)


def _add(p_point, q_point):
    a = (p_point[1] - p_point[0]) * (q_point[1] - q_point[0]) % _P
    b = (p_point[1] + p_point[0]) * (q_point[1] + q_point[0]) % _P
    c = 2 * p_point[3] * q_point[3] * _D % _P
    d = 2 * p_point[2] * q_point[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(scalar: int, point):
    result = (0, 1, 1, 0)
    while scalar > 0:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


def _equal(p_point, q_point) -> bool:
    if (p_point[0] * q_point[2] - q_point[0] * p_point[2]) % _P != 0:
        return False
    return (p_point[1] * q_point[2] - q_point[1] * p_point[2]) % _P == 0


def _decompress(data: bytes):
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _P)


def ed25519_verify_pure(public_key: bytes, message: bytes, signature: bytes) -> bool:
    if len(public_key) != 32 or len(signature) != 64:
        return False
    point_a = _decompress(public_key)
    if point_a is None:
        return False
    point_r = _decompress(signature[:32])
    if point_r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    h = int.from_bytes(
        hashlib.sha512(signature[:32] + public_key + message).digest(), "little"
    ) % _L
    return _equal(_mul(s, _G), _add(point_r, _mul(h, point_a)))


def ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
            return True
        except (InvalidSignature, ValueError):
            return False
    except ImportError:
        return ed25519_verify_pure(public_key, message, signature)


# --- Weryfikacja -------------------------------------------------------------


def canonical(manifest: Dict[str, Any]) -> bytes:
    return json.dumps(
        manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Weryfikacja pliku STL z biblioteki")
    parser.add_argument("stl", help="pobrany plik .stl")
    parser.add_argument("sidecar", help="towarzyszacy plik .sig.json")
    parser.add_argument("--pubkey", help="oczekiwany klucz publiczny (hex)", default=None)
    args = parser.parse_args()

    with open(args.sidecar, "r", encoding="utf-8") as handle:
        sidecar = json.load(handle)

    manifest = sidecar.get("manifest")
    signature_hex = sidecar.get("signature")
    public_hex = args.pubkey or sidecar.get("public_key")

    if not manifest or not signature_hex or not public_hex:
        print("BLAD: plik .sig.json jest niekompletny.")
        return 2

    if args.pubkey and sidecar.get("public_key") and args.pubkey != sidecar["public_key"]:
        print("BLAD: klucz w pliku .sig.json rozni sie od podanego przez Ciebie.")
        print("      To znak, ze plik moze pochodzic z podstawionego serwera.")
        return 1

    # 1. Podpis manifestu.
    if not ed25519_verify(
        bytes.fromhex(public_hex), canonical(manifest), bytes.fromhex(signature_hex)
    ):
        print("BLAD: podpis manifestu jest nieprawidlowy. NIE UZYWAJ tego pliku.")
        return 1

    # 2. Zawartosc pliku kontra podpisany manifest.
    actual = sha256_file(args.stl)
    if actual != manifest.get("sha256"):
        print("BLAD: plik nie zgadza sie z podpisem.")
        print("  w podpisie: {}".format(manifest.get("sha256")))
        print("  na dysku:   {}".format(actual))
        print("NIE UZYWAJ tego pliku - zostal zmieniony po podpisaniu.")
        return 1

    key_id = hashlib.sha256(bytes.fromhex(public_hex)).hexdigest()[:16]
    print("OK - plik jest autentyczny.")
    print("  nazwa:    {}".format(manifest.get("filename")))
    print("  model:    {}".format(manifest.get("model")))
    print("  wydawca:  {}".format(manifest.get("publisher")))
    print("  rozmiar:  {} B".format(manifest.get("size")))
    print("  sha256:   {}".format(actual))
    print("  key_id:   {}".format(key_id))
    return 0


if __name__ == "__main__":
    sys.exit(main())
