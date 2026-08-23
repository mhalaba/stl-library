#!/usr/bin/env python3
"""Unit tests for the crypto layer and the storage layer.

    ./.venv/bin/python tests/unit.py

These do not start a server - they exercise the functions e2e.py relies on.
This is where the things that are awkward to trigger over HTTP get caught: a
token signed for a different purpose, a manifest with reordered keys, a path
that escapes the storage directory.
"""

import os
import shutil
import sys
import tempfile
from io import BytesIO
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Configuration is read at import time, so it has to be in place first.
WORKDIR = tempfile.mkdtemp(prefix="stl-unit-")
os.environ["STL_DATA_DIR"] = WORKDIR
os.environ["STL_SECRET_KEY"] = "unit-test-secret"
os.environ.pop("STL_SIGNING_PRIVATE_KEY", None)
os.environ.pop("STL_SIGNING_PUBLIC_KEY", None)

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from app import config, integrity, security, storage  # noqa: E402

passed = 0
failed = 0


def check(condition, label):
    global passed, failed
    if condition:
        passed += 1
        print("  OK   {}".format(label))
    else:
        failed += 1
        print("  FAIL {}".format(label))


def raises(exc_type, fn, label):
    try:
        fn()
    except exc_type:
        check(True, label)
        return
    except Exception as exc:  # noqa: BLE001
        check(False, "{} (raised {}: {})".format(label, type(exc).__name__, exc))
        return
    check(False, "{} (nothing was raised)".format(label))


# --- Fixtures ----------------------------------------------------------------


def binary_stl(count=2, filler=1.0):
    import struct

    out = bytearray(b"\0" * 80)
    out += struct.pack("<I", count)
    for i in range(count):
        out += struct.pack("<fff", 0.0, 0.0, 1.0)
        for v in range(3):
            out += struct.pack("<fff", float(i), float(v), filler)
        out += struct.pack("<H", 0)
    return bytes(out)


ASCII_STL = b"""solid rectangle
  facet normal 0 0 1
    outer loop
      vertex 0 0 0
      vertex 1 0 0
      vertex 1 1 0
    endloop
  endfacet
  facet normal 0 0 1
    outer loop
      vertex 0 0 0
      vertex 1 1 0
      vertex 0 1 0
    endloop
  endfacet
endsolid rectangle
"""


# --- Passwords ---------------------------------------------------------------


def test_passwords():
    print("\n[1] Passwords")
    stored = security.hash_password("a-correct-test-password")
    check(security.verify_password("a-correct-test-password", stored), "correct password passes")
    check(not security.verify_password("another-password", stored), "wrong password rejected")
    check(not security.verify_password("", stored), "empty password rejected")

    other = security.hash_password("a-correct-test-password")
    check(stored != other, "same phrase gives a different hash (random salt)")
    check(security.verify_password("a-correct-test-password", other), "both hashes verify")

    check(not security.verify_password("anything", "garbage"), "damaged record does not crash")
    check(not security.verify_password("anything", "md5$1$a$b"), "unsupported algorithm rejected")
    check(stored.startswith("pbkdf2_sha256$260000$"), "PBKDF2-SHA256 with 260,000 iterations")


# --- HMAC tokens -------------------------------------------------------------


def test_tokens():
    print("\n[2] HMAC tokens")
    token = security.make_token({"uid": 7}, 3600, "session")
    body = security.read_token(token, "session")
    check(body is not None and body["uid"] == 7, "token reads back correctly")

    check(security.read_token(token, "download") is None,
          "a session token does not work as a download token")

    expired = security.make_token({"uid": 7}, -10, "session")
    check(security.read_token(expired, "session") is None, "expired token rejected")

    payload, signature = token.split(".", 1)
    forged = security.b64e(b'{"exp":9999999999,"uid":1}') + "." + signature
    check(security.read_token(forged, "session") is None,
          "swapped payload with the old signature rejected")

    check(security.read_token(payload + ".AAAA", "session") is None, "made-up signature rejected")
    check(security.read_token("no-separator", "session") is None, "token without a dot does not crash")
    check(security.read_token("", "session") is None, "empty token rejected")
    check(security.read_token("!!!.!!!", "session") is None, "base64 garbage does not crash")

    download = security.make_token({"fid": 5, "uid": 1, "sha": "abc"}, 300, "download")
    parsed = security.read_token(download, "download")
    check(parsed["fid"] == 5 and parsed["sha"] == "abc", "download token carries file and digest")


# --- Manifest and signature --------------------------------------------------


def test_manifest():
    print("\n[3] Manifest and Ed25519 signature")
    private = Ed25519PrivateKey.generate()
    public = private.public_key()
    pub_hex = public.public_bytes_raw().hex()

    manifest = security.build_manifest("wall-hook", "wall-hook.stl", 1848, "a" * 64,
                                       1754136000, security.key_id(pub_hex))

    # Canonicalisation must not depend on insertion order.
    shuffled = {}
    for key in reversed(list(manifest.keys())):
        shuffled[key] = manifest[key]
    check(security.canonical(manifest) == security.canonical(shuffled),
          "canonical JSON is independent of key order")
    check(b" " not in security.canonical(manifest), "canonical JSON contains no spaces")

    signature = security.sign_manifest(manifest, private)
    check(security.verify_manifest(manifest, signature, public), "a valid signature passes")

    tampered = dict(manifest, sha256="b" * 64)
    check(not security.verify_manifest(tampered, signature, public),
          "changing sha256 invalidates the signature")

    renamed = dict(manifest, filename="something-else.stl")
    check(not security.verify_manifest(renamed, signature, public),
          "changing the filename invalidates the signature")

    intruder = Ed25519PrivateKey.generate().public_key()
    check(not security.verify_manifest(manifest, signature, intruder),
          "a foreign key does not confirm the signature")

    check(not security.verify_manifest(manifest, "not-hex", public),
          "a non-hex signature does not crash")
    check(not security.verify_manifest(manifest, "ab" * 32, public),
          "a signature of the wrong length is rejected")

    # Non-ASCII characters have to survive the round trip.
    polish = security.build_manifest("zabka", "żółć-ćma.stl", 10, "c" * 64, 1, "0" * 16)
    polish_sig = security.sign_manifest(polish, private)
    check(security.verify_manifest(polish, polish_sig, public),
          "non-ASCII characters in a filename work")

    check(len(security.key_id(pub_hex)) == 16, "key_id is 16 characters")
    check(security.key_id(pub_hex) == security.key_id(pub_hex), "key_id is stable")


# --- STL detection -----------------------------------------------------------


def test_stl_detection():
    print("\n[4] STL validation")
    tmp = Path(WORKDIR) / "samples"
    tmp.mkdir(exist_ok=True)

    binary = tmp / "bin.stl"
    binary.write_bytes(binary_stl(4))
    check(storage.inspect_stl(binary) == 4, "binary STL: 4 triangles counted")

    ascii_file = tmp / "ascii.stl"
    ascii_file.write_bytes(ASCII_STL)
    check(storage.inspect_stl(ascii_file) == 2, "ASCII STL: 2 facets counted")

    junk = tmp / "junk.stl"
    junk.write_bytes(b"this is not an STL, just plain text longer than 84 bytes" * 3)
    raises(storage.InvalidSTL, lambda: storage.inspect_stl(junk), "junk rejected")

    tiny = tmp / "tiny.stl"
    tiny.write_bytes(b"solid")
    raises(storage.InvalidSTL, lambda: storage.inspect_stl(tiny), "file too small rejected")

    # The header promises 100 triangles, the file does not have them.
    truncated = tmp / "truncated.stl"
    data = bytearray(binary_stl(4))
    data[80:84] = (100).to_bytes(4, "little")
    truncated.write_bytes(bytes(data))
    raises(storage.InvalidSTL, lambda: storage.inspect_stl(truncated),
           "binary STL with an inflated triangle count rejected")

    empty_ascii = tmp / "empty.stl"
    empty_ascii.write_bytes(b"solid nothing\nendsolid nothing\n" + b" " * 100)
    raises(storage.InvalidSTL, lambda: storage.inspect_stl(empty_ascii),
           "ASCII STL without a single facet rejected")

    try:
        storage.inspect_stl(junk)
    except storage.InvalidSTL as exc:
        check(exc.key == "upload.unknown_format", "the exception carries a message key")


# --- Storage -----------------------------------------------------------------


def test_storage():
    print("\n[5] Content-addressed storage")
    content = binary_stl(6, filler=3.5)
    sha, size, triangles, relative, duplicate = storage.store_upload(BytesIO(content), 10 * 1024 * 1024)

    check(triangles == 6, "triangle count recorded")
    check(size == len(content), "size matches")
    check(duplicate is False, "first upload is not a duplicate")
    check(relative.startswith("{}/{}/".format(sha[0:2], sha[2:4])),
          "path derived from the digest: {}".format(relative))
    check(storage.absolute_path(relative).exists(), "the file really is on disk")

    sha2, _, _, relative2, duplicate2 = storage.store_upload(BytesIO(content), 10 * 1024 * 1024)
    check(duplicate2 is True and sha2 == sha and relative2 == relative,
          "identical content recognised as a duplicate")

    ok, problem = storage.verify_stored_file(relative, sha)
    check(ok and problem is None, "an untouched file verifies")

    ok, problem = storage.verify_stored_file(relative, "f" * 64)
    check(not ok and problem[0] == "storage.hash_mismatch", "digest mismatch detected")

    ok, problem = storage.verify_stored_file("aa/bb/no-such-file.stl", sha)
    check(not ok and problem[0] == "storage.missing", "missing file reported, not raised")

    # Swap the content under an existing path.
    target = storage.absolute_path(relative)
    os.chmod(str(target), 0o644)
    target.write_bytes(binary_stl(6, filler=99.0))
    ok, problem = storage.verify_stored_file(relative, sha)
    check(not ok, "swapped content under the same path detected")

    raises(storage.InvalidSTL,
           lambda: storage.store_upload(BytesIO(binary_stl(200)), 100),
           "exceeding the size limit is rejected")
    raises(storage.InvalidSTL, lambda: storage.store_upload(BytesIO(b""), 1000),
           "empty stream rejected")

    leftovers = list(config.STORAGE_DIR.glob("*.part"))
    check(not leftovers, "a failed upload leaves no temporary files behind")


def test_path_traversal():
    print("\n[6] Paths outside the storage directory")
    for evil in ["../../../../etc/passwd", "..", "aa/../../../../tmp/x", "/etc/passwd"]:
        raises(ValueError, lambda e=evil: storage.absolute_path(e),
               "rejected path: {}".format(evil))

    ok, problem = storage.verify_stored_file("../../../../etc/hosts", "a" * 64)
    check(not ok and problem[0] == "storage.path_outside",
          "verify_stored_file reports an escaping path instead of reading it")

    inside = storage.relative_path_for("d" * 64)
    check(str(storage.absolute_path(inside)).startswith(str(config.STORAGE_DIR)),
          "a valid path inside the storage directory passes")


# --- The check before a file is released -------------------------------------


def test_integrity():
    print("\n[7] The check before a file is released")
    import json

    private = Ed25519PrivateKey.generate()
    pub_hex = private.public_key().public_bytes_raw().hex()
    config.SIGNING_PUBLIC_KEY_HEX = pub_hex  # stand in as the server key for this test

    content = binary_stl(3, filler=7.0)
    sha, size, _, relative, _ = storage.store_upload(BytesIO(content), 10 * 1024 * 1024)

    manifest = security.build_manifest("model", "file.stl", size, sha, 1700000000,
                                       security.key_id(pub_hex))
    signature = security.sign_manifest(manifest, private)

    def row(**overrides):
        base = {
            "id": 1, "status": "signed", "filename": "file.stl", "size": size,
            "sha256": sha, "storage_path": relative, "signature": signature,
            "key_id": manifest["key_id"],
            "manifest": json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
        }
        base.update(overrides)
        return base

    try:
        integrity.check_file(row(), deep=True)
        check(True, "a sound file passes the full check")
    except integrity.IntegrityError as exc:
        check(False, "a sound file passes the full check ({})".format(exc.key))

    def expect_key(expected, file_row, label, deep=True):
        try:
            integrity.check_file(file_row, deep=deep)
        except integrity.IntegrityError as exc:
            check(exc.key == expected, "{} [{}]".format(label, exc.key))
            return
        check(False, "{} (nothing was raised)".format(label))

    expect_key("integrity.unsigned", row(status="pending"), "an unsigned file does not pass")
    expect_key("integrity.quarantined", row(status="quarantined"), "a quarantined file does not pass")
    expect_key("integrity.manifest_missing", row(manifest=None), "missing manifest detected")
    expect_key("integrity.manifest_missing", row(manifest="{broken json"),
               "damaged manifest does not crash the server")
    expect_key("integrity.catalog_mismatch", row(sha256="e" * 64),
               "manifest/database divergence detected (digest edited in the database)")
    expect_key("integrity.catalog_mismatch", row(filename="substituted.stl"),
               "filename divergence detected")
    expect_key("integrity.catalog_mismatch", row(size=size + 1), "size divergence detected")
    expect_key("integrity.signature_missing", row(signature=None), "missing signature detected")
    expect_key(
        "integrity.signature_invalid",
        row(signature=Ed25519PrivateKey.generate().sign(security.canonical(manifest)).hex()),
        "signature from a foreign key rejected",
    )

    other_schema = dict(manifest, schema="stl-library/manifest/v999")
    expect_key(
        "integrity.schema_unknown",
        row(manifest=json.dumps(other_schema, sort_keys=True, separators=(",", ":"))),
        "unknown manifest version rejected",
    )

    # A manifest signed with a key the server no longer uses.
    config.SIGNING_PUBLIC_KEY_HEX = Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
    expect_key("integrity.key_mismatch", row(), "manifest with a stale key_id rejected")
    config.SIGNING_PUBLIC_KEY_HEX = pub_hex

    # A file swapped on disk - only the deep check catches this.
    target = storage.absolute_path(relative)
    os.chmod(str(target), 0o644)
    target.write_bytes(binary_stl(3, filler=123.0))
    try:
        integrity.check_file(row(), deep=False)
        check(True, "the shallow check does not touch the disk")
    except integrity.IntegrityError:
        check(False, "the shallow check does not touch the disk")
    expect_key("integrity.disk_mismatch", row(), "the deep check catches a file swapped on disk")

    # The reason has to render in both languages.
    try:
        integrity.check_file(row(), deep=True)
    except integrity.IntegrityError as exc:
        check(exc.reason("en") != exc.reason("pl"), "the reason renders in both languages")
        check("SHA-256" in exc.reason("en"), "the English reason names the digest")

    check(integrity.sidecar(row())["public_key"] == pub_hex,
          "the .sig.json sidecar carries the public key")


# --- Slugs -------------------------------------------------------------------


def test_slug():
    print("\n[8] Model addresses")
    from app.main import slugify

    check(slugify("Uchwyt na słuchawki") == "uchwyt-na-sluchawki", "Polish letters folded to ASCII")
    check(slugify("Koło zębate M2 / z14") == "kolo-zebate-m2-z14", "special characters collapse to a dash")
    check(slugify("  ---  ").startswith("model-"), "a separator-only title gets a fallback name")
    check("/" not in slugify("a/b/../c"), "a slug never carries a path separator")
    check(slugify("ŻÓŁĆ") == "zolc", "uppercase and diacritics")
    check(slugify("Straße Ø") == "strasse-o", "German and Nordic letters handled too")


# --- Message catalogue -------------------------------------------------------


def test_messages():
    print("\n[9] Message catalogue")
    from app import messages

    check(messages.t("auth.required", "en") != messages.t("auth.required", "pl"),
          "both languages are present")
    check(messages.t("no.such.key", "en") == "no.such.key", "an unknown key returns the key itself")
    check("5" in messages.t("upload.too_large", "en", limit=5), "parameters get substituted")
    check(messages.t("upload.too_large", "en") != "", "a missing parameter does not crash")

    missing = [
        key for key, entry in messages.CATALOG.items()
        if not all(lang in entry and entry[lang] for lang in messages.SUPPORTED)
    ]
    check(not missing, "every key is translated into every language ({})".format(missing[:3]))


def main():
    try:
        test_passwords()
        test_tokens()
        test_manifest()
        test_stl_detection()
        test_storage()
        test_path_traversal()
        test_integrity()
        test_slug()
        test_messages()
    finally:
        shutil.rmtree(WORKDIR, ignore_errors=True)

    print("\n{}\nPassed: {}   Failed: {}".format("-" * 50, passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
