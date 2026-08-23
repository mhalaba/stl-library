#!/usr/bin/env python3
"""Testy jednostkowe warstwy kryptograficznej i magazynu plikow.

    ./.venv/bin/python tests/unit.py

Nie podnosza serwera - sprawdzaja same funkcje, ktorym e2e.py ufa. Tutaj lapie
sie rzeczy, ktore przez HTTP sa trudne do wywolania: token podpisany do innego
celu, manifest z przestawionymi kluczami, sciezka wychodzaca poza magazyn.
"""

import os
import shutil
import sys
import tempfile
from io import BytesIO
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Konfiguracja czytana jest przy imporcie, wiec musi byc gotowa wczesniej.
WORKDIR = tempfile.mkdtemp(prefix="stl-unit-")
os.environ["STL_DATA_DIR"] = WORKDIR
os.environ["STL_SECRET_KEY"] = "sekret-do-testow-jednostkowych"
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
        check(False, "{} (poleciał {}: {})".format(label, type(exc).__name__, exc))
        return
    check(False, "{} (nie poleciał żaden wyjątek)".format(label))


# --- Materialy testowe -------------------------------------------------------


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


ASCII_STL = b"""solid prostokat
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
endsolid prostokat
"""


# --- Hasla -------------------------------------------------------------------


def test_passwords():
    print("\n[1] Hasla")
    stored = security.hash_password("poprawne-haslo-testowe")
    check(security.verify_password("poprawne-haslo-testowe", stored), "poprawne haslo przechodzi")
    check(not security.verify_password("inne-haslo", stored), "bledne haslo odrzucone")
    check(not security.verify_password("", stored), "puste haslo odrzucone")

    other = security.hash_password("poprawne-haslo-testowe")
    check(stored != other, "ta sama fraza daje inny hash (losowa sol)")
    check(security.verify_password("poprawne-haslo-testowe", other), "obie wersje weryfikuja sie poprawnie")

    check(not security.verify_password("cokolwiek", "smieci"), "uszkodzony rekord nie wywala funkcji")
    check(not security.verify_password("cokolwiek", "md5$1$a$b"), "nieobslugiwany algorytm odrzucony")
    check(stored.startswith("pbkdf2_sha256$260000$"), "uzyty PBKDF2-SHA256 z 260 000 iteracji")


# --- Tokeny HMAC -------------------------------------------------------------


def test_tokens():
    print("\n[2] Tokeny HMAC")
    token = security.make_token({"uid": 7}, 3600, "session")
    body = security.read_token(token, "session")
    check(body is not None and body["uid"] == 7, "token odczytany poprawnie")

    check(security.read_token(token, "download") is None,
          "token sesji nie dziala jako token pobrania")

    expired = security.make_token({"uid": 7}, -10, "session")
    check(security.read_token(expired, "session") is None, "token po terminie odrzucony")

    payload, signature = token.split(".", 1)
    forged = security.b64e(b'{"exp":9999999999,"uid":1}') + "." + signature
    check(security.read_token(forged, "session") is None, "podmieniona tresc przy starym podpisie odrzucona")

    check(security.read_token(payload + ".AAAA", "session") is None, "zmyslony podpis odrzucony")
    check(security.read_token("bez-kropki", "session") is None, "token bez separatora nie wywala funkcji")
    check(security.read_token("", "session") is None, "pusty token odrzucony")
    check(security.read_token("!!!.!!!", "session") is None, "smieci base64 nie wywalaja funkcji")

    # Token musi byc zwiazany z konkretnym plikiem.
    download = security.make_token({"fid": 5, "uid": 1, "sha": "abc"}, 300, "download")
    parsed = security.read_token(download, "download")
    check(parsed["fid"] == 5 and parsed["sha"] == "abc", "token pobrania niesie plik i hash")


# --- Manifest i podpis -------------------------------------------------------


def test_manifest():
    print("\n[3] Manifest i podpis Ed25519")
    private = Ed25519PrivateKey.generate()
    public = private.public_key()
    pub_hex = public.public_bytes_raw().hex()

    manifest = security.build_manifest("wieszak", "wieszak.stl", 1848, "a" * 64, 1754136000,
                                       security.key_id(pub_hex))

    # Kanonikalizacja nie moze zalezec od kolejnosci wstawiania kluczy.
    shuffled = {}
    for key in reversed(list(manifest.keys())):
        shuffled[key] = manifest[key]
    check(security.canonical(manifest) == security.canonical(shuffled),
          "kanoniczny JSON nie zalezy od kolejnosci kluczy")
    check(b" " not in security.canonical(manifest), "kanoniczny JSON nie ma spacji")

    signature = security.sign_manifest(manifest, private)
    check(security.verify_manifest(manifest, signature, public), "poprawny podpis przechodzi")

    tampered = dict(manifest, sha256="b" * 64)
    check(not security.verify_manifest(tampered, signature, public),
          "zmiana sha256 w manifescie uniewaznia podpis")

    renamed = dict(manifest, filename="cos-innego.stl")
    check(not security.verify_manifest(renamed, signature, public),
          "zmiana nazwy pliku uniewaznia podpis")

    intruder = Ed25519PrivateKey.generate().public_key()
    check(not security.verify_manifest(manifest, signature, intruder),
          "obcy klucz nie potwierdza podpisu")

    check(not security.verify_manifest(manifest, "nie-hex", public),
          "podpis nie bedacy hexem nie wywala funkcji")
    check(not security.verify_manifest(manifest, "ab" * 32, public),
          "podpis o zlej dlugosci odrzucony")

    # Znaki spoza ASCII musza przetrwac droge tam i z powrotem.
    polish = security.build_manifest("zabka", "żółć-ćma.stl", 10, "c" * 64, 1, "0" * 16)
    polish_sig = security.sign_manifest(polish, private)
    check(security.verify_manifest(polish, polish_sig, public), "polskie znaki w nazwie pliku dzialaja")

    check(len(security.key_id(pub_hex)) == 16, "key_id ma 16 znakow")
    check(security.key_id(pub_hex) == security.key_id(pub_hex), "key_id jest stabilne")


# --- Rozpoznawanie STL -------------------------------------------------------


def test_stl_detection():
    print("\n[4] Walidacja plikow STL")
    tmp = Path(WORKDIR) / "probki"
    tmp.mkdir(exist_ok=True)

    binary = tmp / "bin.stl"
    binary.write_bytes(binary_stl(4))
    check(storage.inspect_stl(binary) == 4, "binarny STL: policzone 4 trojkaty")

    ascii_file = tmp / "ascii.stl"
    ascii_file.write_bytes(ASCII_STL)
    check(storage.inspect_stl(ascii_file) == 2, "ASCII STL: policzone 2 sciany")

    junk = tmp / "junk.stl"
    junk.write_bytes(b"to nie jest STL, tylko zwykly tekst o dlugosci ponad 84 bajty" * 3)
    raises(storage.InvalidSTL, lambda: storage.inspect_stl(junk), "smieci odrzucone")

    tiny = tmp / "tiny.stl"
    tiny.write_bytes(b"solid")
    raises(storage.InvalidSTL, lambda: storage.inspect_stl(tiny), "plik za maly odrzucony")

    # Naglowek obiecuje 100 trojkatow, a plik ich nie ma.
    truncated = tmp / "truncated.stl"
    data = bytearray(binary_stl(4))
    data[80:84] = (100).to_bytes(4, "little")
    truncated.write_bytes(bytes(data))
    raises(storage.InvalidSTL, lambda: storage.inspect_stl(truncated),
           "binarny STL z zawyzona liczba trojkatow odrzucony")

    empty_ascii = tmp / "pusty.stl"
    empty_ascii.write_bytes(b"solid nic\nendsolid nic\n" + b" " * 100)
    raises(storage.InvalidSTL, lambda: storage.inspect_stl(empty_ascii),
           "ASCII bez ani jednej sciany odrzucony")


# --- Magazyn -----------------------------------------------------------------


def test_storage():
    print("\n[5] Magazyn adresowany trescia")
    content = binary_stl(6, filler=3.5)
    sha, size, triangles, relative, duplicate = storage.store_upload(BytesIO(content), 10 * 1024 * 1024)

    check(triangles == 6, "liczba trojkatow zapisana")
    check(size == len(content), "rozmiar sie zgadza")
    check(duplicate is False, "pierwsze wgranie nie jest duplikatem")
    check(relative.startswith("{}/{}/".format(sha[0:2], sha[2:4])),
          "sciezka wyprowadzona z hasha: {}".format(relative))
    check(storage.absolute_path(relative).exists(), "plik faktycznie lezy na dysku")

    sha2, _, _, relative2, duplicate2 = storage.store_upload(BytesIO(content), 10 * 1024 * 1024)
    check(duplicate2 is True and sha2 == sha and relative2 == relative,
          "ta sama tresc rozpoznana jako duplikat")

    ok, problem = storage.verify_stored_file(relative, sha)
    check(ok and problem is None, "weryfikacja nietknietego pliku przechodzi")

    ok, problem = storage.verify_stored_file(relative, "f" * 64)
    check(not ok and "SHA-256" in problem, "niezgodny hash wykryty")

    ok, problem = storage.verify_stored_file("aa/bb/nie-ma-takiego.stl", sha)
    check(not ok and "nie istnieje" in problem, "brak pliku zglaszany, nie wyjatek")

    # Podmiana pliku pod istniejaca sciezka.
    target = storage.absolute_path(relative)
    os.chmod(str(target), 0o644)
    target.write_bytes(binary_stl(6, filler=99.0))
    ok, problem = storage.verify_stored_file(relative, sha)
    check(not ok, "podmieniona tresc pod ta sama sciezka wykryta")

    raises(storage.InvalidSTL,
           lambda: storage.store_upload(BytesIO(binary_stl(200)), 100),
           "przekroczony limit rozmiaru odrzucony")
    raises(storage.InvalidSTL, lambda: storage.store_upload(BytesIO(b""), 1000),
           "pusty strumien odrzucony")

    leftovers = list(config.STORAGE_DIR.glob("*.part"))
    check(not leftovers, "po nieudanym wgraniu nie zostaja pliki tymczasowe")


def test_path_traversal():
    print("\n[6] Sciezki poza magazynem")
    for evil in ["../../../../etc/passwd", "..", "aa/../../../../tmp/x", "/etc/passwd"]:
        raises(ValueError, lambda e=evil: storage.absolute_path(e),
               "odrzucona sciezka: {}".format(evil))

    inside = storage.relative_path_for("d" * 64)
    check(storage.absolute_path(inside).is_relative_to(config.STORAGE_DIR)
          if hasattr(Path, "is_relative_to")
          else str(storage.absolute_path(inside)).startswith(str(config.STORAGE_DIR)),
          "poprawna sciezka wewnatrz magazynu przechodzi")


# --- Weryfikacja przed wydaniem pliku ----------------------------------------


def test_integrity():
    print("\n[7] Kontrola przed wydaniem pliku")
    import json

    private = Ed25519PrivateKey.generate()
    pub_hex = private.public_key().public_bytes_raw().hex()
    config.SIGNING_PUBLIC_KEY_HEX = pub_hex  # podmiana klucza serwera na czas testu

    content = binary_stl(3, filler=7.0)
    sha, size, _, relative, _ = storage.store_upload(BytesIO(content), 10 * 1024 * 1024)

    manifest = security.build_manifest("model", "plik.stl", size, sha, 1700000000,
                                       security.key_id(pub_hex))
    signature = security.sign_manifest(manifest, private)

    def row(**overrides):
        base = {
            "id": 1, "status": "signed", "filename": "plik.stl", "size": size,
            "sha256": sha, "storage_path": relative, "signature": signature,
            "key_id": manifest["key_id"],
            "manifest": json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
        }
        base.update(overrides)
        return base

    try:
        integrity.check_file(row(), deep=True)
        check(True, "poprawny plik przechodzi pelna kontrole")
    except integrity.IntegrityError as exc:
        check(False, "poprawny plik przechodzi pelna kontrole ({})".format(exc.reason))

    raises(integrity.IntegrityError, lambda: integrity.check_file(row(status="pending")),
           "plik bez podpisu nie przechodzi")
    raises(integrity.IntegrityError, lambda: integrity.check_file(row(status="quarantined")),
           "plik w kwarantannie nie przechodzi")
    raises(integrity.IntegrityError, lambda: integrity.check_file(row(manifest=None)),
           "brak manifestu wykryty")
    raises(integrity.IntegrityError, lambda: integrity.check_file(row(manifest="{niepoprawny json")),
           "uszkodzony manifest nie wywala serwera")
    raises(integrity.IntegrityError, lambda: integrity.check_file(row(sha256="e" * 64)),
           "rozjazd manifestu z baza wykryty (podmieniony hash w bazie)")
    raises(integrity.IntegrityError, lambda: integrity.check_file(row(filename="podstawiony.stl")),
           "rozjazd nazwy pliku wykryty")
    raises(integrity.IntegrityError, lambda: integrity.check_file(row(size=size + 1)),
           "rozjazd rozmiaru wykryty")
    raises(integrity.IntegrityError, lambda: integrity.check_file(row(signature=None)),
           "brak podpisu wykryty")
    raises(integrity.IntegrityError,
           lambda: integrity.check_file(row(signature=Ed25519PrivateKey.generate()
                                            .sign(security.canonical(manifest)).hex())),
           "podpis obcym kluczem odrzucony")

    other_schema = dict(manifest, schema="stl-library/manifest/v999")
    raises(integrity.IntegrityError,
           lambda: integrity.check_file(row(manifest=json.dumps(other_schema, sort_keys=True,
                                                                separators=(",", ":")))),
           "nieznana wersja manifestu odrzucona")

    # Manifest podpisany kluczem, ktorego serwer juz nie uzywa.
    config.SIGNING_PUBLIC_KEY_HEX = Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
    raises(integrity.IntegrityError, lambda: integrity.check_file(row()),
           "manifest z nieaktualnym key_id odrzucony")
    config.SIGNING_PUBLIC_KEY_HEX = pub_hex

    # Plik podmieniony na dysku - lapie to dopiero kontrola gleboka.
    target = storage.absolute_path(relative)
    os.chmod(str(target), 0o644)
    target.write_bytes(binary_stl(3, filler=123.0))
    try:
        integrity.check_file(row(), deep=False)
        check(True, "kontrola plytka nie rusza dysku")
    except integrity.IntegrityError:
        check(False, "kontrola plytka nie rusza dysku")
    raises(integrity.IntegrityError, lambda: integrity.check_file(row(), deep=True),
           "kontrola gleboka lapie podmiane pliku na dysku")

    check(integrity.sidecar(row())["public_key"] == pub_hex,
          "sidecar .sig.json niesie klucz publiczny")


# --- Slug --------------------------------------------------------------------


def test_slug():
    print("\n[8] Adresy modeli")
    from app.main import slugify

    check(slugify("Uchwyt na słuchawki") == "uchwyt-na-sluchawki", "polskie znaki zamienione na ASCII")
    check(slugify("Koło zębate M2 / z14") == "kolo-zebate-m2-z14", "znaki specjalne zwiniete do myslnika")
    check(slugify("  ---  ").startswith("model-"), "sam separator daje zapasowa nazwe")
    check("/" not in slugify("a/b/../c"), "slug nie przenosi separatora sciezki")
    check(slugify("ŻÓŁĆ") == "zolc", "wielkie litery i ogonki")


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
    finally:
        shutil.rmtree(WORKDIR, ignore_errors=True)

    print("\n{}\nZdane: {}   Niezdane: {}".format("-" * 50, passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
