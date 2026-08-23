#!/usr/bin/env python3
"""Test end-to-end: sprawdza, czy podmiana pliku faktycznie jest wykrywana.

    ./.venv/bin/python tests/e2e.py

Test uruchamia prawdziwy serwer w trybie OFFLINE (bez klucza prywatnego),
podpisuje pliki tak, jak robi to tools/sign_pending.py, a potem odgrywa rolę
napastnika: podmienia plik na dysku, a następnie podmienia plik RAZEM z
poprawieniem sumy kontrolnej w bazie danych. Oba ataki muszą zostać zatrzymane.
"""

import hashlib
import http.cookiejar
import json
import os
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Ten sam sekret dostanie serwer w podprocesie. Dzieki temu test moze sam
# zlozyc poprawny token pobrania i sprawdzic, jak serwer traktuje termin waznosci.
SECRET = "0" * 64
os.environ["STL_SECRET_KEY"] = SECRET

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from app import security as app_security  # noqa: E402

ADMIN_EMAIL = "admin@example.com"
ADMIN_PASSWORD = "bardzo-dlugie-haslo-testowe"
PORT = 8731
BASE = "http://127.0.0.1:{}".format(PORT)

ASCII_STL = b"""solid plytka
  facet normal 0 0 1
    outer loop
      vertex 0 0 0
      vertex 10 0 0
      vertex 10 10 0
    endloop
  endfacet
  facet normal 0 0 1
    outer loop
      vertex 0 0 0
      vertex 10 10 0
      vertex 0 10 0
    endloop
  endfacet
endsolid plytka
"""

passed = 0
failed = 0


def check(condition: bool, label: str) -> None:
    global passed, failed
    if condition:
        passed += 1
        print("  OK   {}".format(label))
    else:
        failed += 1
        print("  FAIL {}".format(label))


def cube_stl(scale: float = 10.0) -> bytes:
    """Minimalny, poprawny binarny STL - sześcian z 12 trójkątów."""
    v = [
        (0, 0, 0), (scale, 0, 0), (scale, scale, 0), (0, scale, 0),
        (0, 0, scale), (scale, 0, scale), (scale, scale, scale), (0, scale, scale),
    ]
    faces = [
        (0, 3, 2), (0, 2, 1), (4, 5, 6), (4, 6, 7),
        (0, 1, 5), (0, 5, 4), (1, 2, 6), (1, 6, 5),
        (2, 3, 7), (2, 7, 6), (3, 0, 4), (3, 4, 7),
    ]
    out = bytearray(b"\0" * 80)
    out += struct.pack("<I", len(faces))
    for a, b, c in faces:
        out += struct.pack("<fff", 0.0, 0.0, 1.0)
        for index in (a, b, c):
            out += struct.pack("<fff", *v[index])
        out += struct.pack("<H", 0)
    return bytes(out)


class Client:
    def __init__(self, base: str):
        self.base = base
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.csrf = None

    def _headers(self, extra=None):
        headers = {"Accept": "application/json"}
        if self.csrf:
            headers["X-CSRF-Token"] = self.csrf
        headers.update(extra or {})
        return headers

    def call(self, method, path, body=None, raw=False):
        """Zwraca (kod_http, dane)."""
        data = None
        headers = self._headers()
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with self.opener.open(req, timeout=30) as response:
                payload = response.read()
                if raw:
                    # response.headers to obiekt Message - szuka nazw bez wzgledu
                    # na wielkosc liter, a serwer wysyla je malymi.
                    return response.status, payload, response.headers
                return response.status, json.loads(payload.decode())
        except urllib.error.HTTPError as exc:
            payload = exc.read()
            try:
                parsed = json.loads(payload.decode())
            except ValueError:
                parsed = {"detail": payload.decode("utf-8", "replace")}
            return (exc.code, payload, {}) if raw else (exc.code, parsed)

    def upload(self, slug, filename, content):
        boundary = "----" + uuid.uuid4().hex
        body = (
            "--{}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{}\"\r\n"
            "Content-Type: application/octet-stream\r\n\r\n".format(boundary, filename)
        ).encode() + content + "\r\n--{}--\r\n".format(boundary).encode()

        req = urllib.request.Request(
            "{}/api/admin/models/{}/files".format(self.base, slug),
            data=body,
            headers=self._headers({"Content-Type": "multipart/form-data; boundary=" + boundary}),
            method="POST",
        )
        try:
            with self.opener.open(req, timeout=60) as response:
                return response.status, json.loads(response.read().decode())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode())

    def login(self, email, password):
        status, data = self.call("POST", "/api/auth/login", {"email": email, "password": password})
        self.csrf = data.get("csrf")
        return status, data

    def register(self, email, password):
        status, data = self.call("POST", "/api/auth/register", {"email": email, "password": password})
        self.csrf = data.get("csrf")
        return status, data


def canonical(manifest):
    return json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sign_all_pending(client, private, key_id, publisher):
    status, listing = client.call("GET", "/api/admin/pending")
    signed = 0
    for item in listing["pending"]:
        manifest = {
            "schema": "stl-library/manifest/v1",
            "publisher": publisher,
            "model": item["model_slug"],
            "filename": item["filename"],
            "size": int(item["size"]),
            "sha256": item["sha256"],
            "uploaded_at": int(item["uploaded_at"]),
            "key_id": key_id,
        }
        code, _ = client.call(
            "POST",
            "/api/admin/signatures",
            {"file_id": item["id"], "manifest": manifest, "signature": private.sign(canonical(manifest)).hex()},
        )
        if code == 200:
            signed += 1
    return signed


def main() -> int:
    workdir = Path(tempfile.mkdtemp(prefix="stl-e2e-"))
    private = Ed25519PrivateKey.generate()
    public_raw = private.public_key().public_bytes_raw()
    key_id = hashlib.sha256(public_raw).hexdigest()[:16]

    env = dict(os.environ)
    env.update({
        "STL_DATA_DIR": str(workdir / "data"),
        "STL_SECRET_KEY": "0" * 64,
        "STL_SIGNING_PUBLIC_KEY": public_raw.hex(),   # tryb offline: bez klucza prywatnego
        "STL_PUBLISHER": "test-biblioteka",
        "STL_ADMIN_EMAIL": ADMIN_EMAIL,
        "STL_ADMIN_PASSWORD": ADMIN_PASSWORD,
        "STL_COOKIE_SECURE": "false",
        "PYTHONPATH": str(ROOT),
    })
    env.pop("STL_SIGNING_PRIVATE_KEY", None)

    server = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(PORT)],
        cwd=str(ROOT), env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )

    try:
        for _ in range(120):
            try:
                urllib.request.urlopen(BASE + "/api/pubkey", timeout=2).read()
                break
            except Exception:
                if server.poll() is not None:
                    print(server.stdout.read().decode())
                    return 1
                time.sleep(0.25)
        else:
            print("Serwer nie wstal.")
            return 1

        admin = Client(BASE)

        print("\n[1] Konta i uprawnienia")
        status, _ = admin.login(ADMIN_EMAIL, ADMIN_PASSWORD)
        check(status == 200, "administrator loguje sie")
        status, _ = Client(BASE).login(ADMIN_EMAIL, "zle-haslo-zupelnie")
        check(status == 401, "bledne haslo odrzucone")

        anon = Client(BASE)
        status, _ = anon.call("POST", "/api/admin/models", {"title": "Proba przejecia"})
        check(status == 401, "anonim nie utworzy modelu")

        user = Client(BASE)
        status, _ = user.register("user@example.com", "inne-dlugie-haslo-uzytkownika")
        check(status == 200, "zwykly uzytkownik sie rejestruje")
        status, _ = user.call("POST", "/api/admin/models", {"title": "Proba przejecia"})
        check(status == 403, "zwykly uzytkownik nie ma dostepu do panelu admina")

        # CSRF: żądanie z ciasteczkiem sesji, ale bez nagłówka.
        no_csrf = Client(BASE)
        no_csrf.login(ADMIN_EMAIL, ADMIN_PASSWORD)
        no_csrf.csrf = None
        status, _ = no_csrf.call("POST", "/api/admin/models", {"title": "Bez CSRF"})
        check(status == 403, "zadanie bez tokenu CSRF odrzucone")

        print("\n[2] Model i wgrywanie plikow")
        status, model = admin.call("POST", "/api/admin/models", {
            "title": "Testowy szescian", "description": "opis", "category": "test", "license": "CC0"
        })
        check(status == 200, "model utworzony")
        slug = model["slug"]

        status, upload = admin.upload(slug, "szescian.stl", cube_stl())
        check(status == 200 and upload["status"] == "pending", "plik wgrany, czeka na podpis (tryb offline)")
        file_id = upload["file_id"]
        original_sha = upload["sha256"]

        status, second = admin.upload(slug, "szescian2.stl", cube_stl(12.0))
        check(status == 200, "drugi plik wgrany")
        second_id = second["file_id"]

        status, bad = admin.upload(slug, "smieci.stl", b"to nie jest zaden STL, tylko tekst")
        check(status == 400, "plik nie bedacy STL-em odrzucony")

        print("\n[3] Pobieranie bez podpisu")
        status, _ = user.call("POST", "/api/files/{}/grant".format(file_id))
        check(status == 409, "niepodpisany plik nie da sie pobrac")

        print("\n[4] Podpisywanie z maszyny offline")
        signed_count = sign_all_pending(admin, private, key_id, "test-biblioteka")
        check(signed_count == 2, "podpisano oba pliki ({})".format(signed_count))

        # Serwer musi odrzucić podpis złożony obcym kluczem.
        intruder = Ed25519PrivateKey.generate()
        status, third = admin.upload(slug, "trzeci.stl", cube_stl(7.0))
        third_id = third["file_id"]
        manifest = {
            "schema": "stl-library/manifest/v1", "publisher": "test-biblioteka", "model": slug,
            "filename": "trzeci.stl", "size": third["size"], "sha256": third["sha256"],
            "uploaded_at": int(time.time()), "key_id": key_id,
        }
        status, _ = admin.call("POST", "/api/admin/signatures", {
            "file_id": third_id, "manifest": manifest, "signature": intruder.sign(canonical(manifest)).hex()
        })
        check(status == 400, "podpis obcym kluczem odrzucony")

        print("\n[5] Uczciwe pobranie")
        status, grant = user.call("POST", "/api/files/{}/grant".format(file_id))
        check(status == 200, "uzytkownik dostaje link do pobrania")

        status, payload, headers = user.call("GET", grant["url"], raw=True)
        check(status == 200, "plik pobrany")
        check(hashlib.sha256(payload).hexdigest() == original_sha, "tresc zgadza sie z suma kontrolna")
        check(headers.get("X-STL-Key-Id") == key_id, "naglowek X-STL-Key-Id niesie identyfikator klucza")

        status, anon_grant = anon.call("POST", "/api/files/{}/grant".format(file_id))
        check(status == 401, "anonim nie dostanie linku")

        status, _, _ = user.call("GET", "/api/download/{}?token=podrobka".format(file_id), raw=True)
        check(status == 403, "zmyslony token odrzucony")

        # Ten sam token przeklejony pod inny plik.
        token = grant["url"].split("token=")[1]
        status, _, _ = user.call("GET", "/api/download/{}?token={}".format(second_id, token), raw=True)
        check(status == 403, "token przypisany do jednego pliku nie dziala na innym")

        print("\n[6] Weryfikacja offline narzedziem verify_stl.py")
        status, sidecar = user.call("GET", "/api/files/{}/signature".format(file_id))
        stl_path = workdir / "pobrany.stl"
        sig_path = workdir / "pobrany.stl.sig.json"
        stl_path.write_bytes(payload)
        sig_path.write_text(json.dumps(sidecar), encoding="utf-8")

        result = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "verify_stl.py"), str(stl_path), str(sig_path)],
            capture_output=True, text=True,
        )
        check(result.returncode == 0, "verify_stl.py potwierdza autentycznosc")

        # Ta sama weryfikacja bez biblioteki `cryptography` - czysty Python.
        pure_env = dict(os.environ, PYTHONPATH="")
        pure = subprocess.run(
            [sys.executable, "-c",
             "import sys; sys.modules['cryptography']=None; "
             "sys.argv=['v', {!r}, {!r}]; exec(open({!r}).read())".format(
                 str(stl_path), str(sig_path), str(ROOT / "tools" / "verify_stl.py"))],
            capture_output=True, text=True, env=pure_env,
        )
        check("OK" in pure.stdout, "wbudowana implementacja Ed25519 (bez zaleznosci) tez potwierdza")

        tampered_copy = workdir / "podmieniony.stl"
        tampered_copy.write_bytes(cube_stl(11.0))
        result = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "verify_stl.py"), str(tampered_copy), str(sig_path)],
            capture_output=True, text=True,
        )
        check(result.returncode == 1, "verify_stl.py wykrywa podmieniony plik u uzytkownika")

        print("\n[7] ATAK: podmiana pliku na dysku serwera")
        db_path = workdir / "data" / "library.db"
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT storage_path, sha256 FROM files WHERE id = ?", (file_id,)).fetchone()
        target = workdir / "data" / "storage" / row["storage_path"]
        conn.close()

        os.chmod(str(target), 0o644)
        target.write_bytes(cube_stl(999.0))  # inna geometria, poprawny STL

        status, grant2 = user.call("POST", "/api/files/{}/grant".format(file_id))
        status, body, _ = user.call("GET", grant2["url"], raw=True)
        check(status == 409, "podmieniony plik NIE zostaje wydany")

        conn = sqlite3.connect(str(db_path))
        state = conn.execute("SELECT status FROM files WHERE id = ?", (file_id,)).fetchone()[0]
        conn.close()
        check(state == "quarantined", "plik automatycznie trafil do kwarantanny")

        status, models = user.call("GET", "/api/models/{}".format(slug))
        quarantined = [f for f in models["files"] if f["id"] == file_id][0]
        check(quarantined["status"] == "quarantined", "katalog pokazuje plik jako zablokowany")

        print("\n[8] ATAK: podmiana pliku RAZEM z poprawieniem hasha w bazie")
        evil = cube_stl(31.0)
        evil_sha = hashlib.sha256(evil).hexdigest()

        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT storage_path FROM files WHERE id = ?", (second_id,)).fetchone()
        victim = workdir / "data" / "storage" / row["storage_path"]
        os.chmod(str(victim), 0o644)
        victim.write_bytes(evil)
        # Napastnik ma pełny dostęp do bazy i "naprawia" wszystkie widoczne ślady.
        conn.execute(
            "UPDATE files SET sha256 = ?, size = ? WHERE id = ?", (evil_sha, len(evil), second_id)
        )
        conn.commit()
        conn.close()

        status, grant3 = user.call("POST", "/api/files/{}/grant".format(second_id))
        if status == 200:
            status, _, _ = user.call("GET", grant3["url"], raw=True)
        check(status == 409, "podmiana z poprawionym hashem w bazie tez zostaje zatrzymana")

        status, verdict = user.call("GET", "/api/files/{}/verify".format(second_id))
        check(verdict["ok"] is False, "endpoint weryfikacji zglasza problem")
        check("podpis" in verdict["reason"] or "manifest" in verdict["reason"],
              "powod wskazuje na niezgodnosc podpisu: {}".format(verdict["reason"]))

        print("\n[9] Audyt calej biblioteki")
        status, audit = admin.call("POST", "/api/admin/audit")
        check(status == 200 and len(audit["problems"]) >= 2, "audyt wylapuje oba uszkodzone pliki")

        cli = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "audit.py"), "--json"],
            capture_output=True, text=True, cwd=str(ROOT), env=env,
        )
        check(cli.returncode == 1, "tools/audit.py konczy sie kodem 1 przy problemach")

        print("\n[10] Zabezpieczenia HTTP")
        status, _, headers = anon.call("GET", "/", raw=True)
        check(headers.get("X-Content-Type-Options") == "nosniff", "naglowek nosniff obecny")
        check("frame-ancestors 'none'" in headers.get("Content-Security-Policy", ""), "CSP zablokowany clickjacking")

        status, _ = anon.call("GET", "/api/download/1?token=" + "A" * 200, raw=False)
        check(status == 403, "smieciowy token nie wywala serwera")

        print("\n[11] Plik w formacie ASCII STL")
        status, ascii_up = admin.upload(slug, "plytka.stl", ASCII_STL)
        check(status == 200 and ascii_up["triangles"] == 2, "ASCII STL przyjety i policzony")
        sign_all_pending(admin, private, key_id, "test-biblioteka")
        status, ascii_grant = user.call("POST", "/api/files/{}/grant".format(ascii_up["file_id"]))
        status, ascii_payload, _ = user.call("GET", ascii_grant["url"], raw=True)
        check(status == 200 and ascii_payload == ASCII_STL, "ASCII STL wydany bez zmian w bajtach")

        print("\n[12] Deduplikacja i usuwanie plikow")
        status, other_model = admin.call("POST", "/api/admin/models", {"title": "Drugi model"})
        shared_bytes = cube_stl(5.0)
        status, copy_a = admin.upload(slug, "wspolny.stl", shared_bytes)
        status, copy_b = admin.upload(other_model["slug"], "wspolny.stl", shared_bytes)
        check(copy_b["deduplicated"] is True, "ta sama tresc wgrana drugi raz nie zajmuje miejsca dwa razy")
        check(copy_a["sha256"] == copy_b["sha256"], "obie pozycje wskazuja te sama tresc")
        sign_all_pending(admin, private, key_id, "test-biblioteka")

        status, _ = admin.call("DELETE", "/api/admin/files/{}".format(copy_a["file_id"]))
        check(status == 200, "pierwsza pozycja usunieta")
        status, grant_b = user.call("POST", "/api/files/{}/grant".format(copy_b["file_id"]))
        status, body_b, _ = user.call("GET", grant_b["url"], raw=True)
        check(status == 200 and hashlib.sha256(body_b).hexdigest() == copy_b["sha256"],
              "usuniecie jednej pozycji nie skasowalo tresci wspoldzielonej z druga")

        print("\n[13] Model nieopublikowany")
        status, draft = admin.call("POST", "/api/admin/models", {
            "title": "Szkic roboczy", "is_published": False
        })
        status, listing = anon.call("GET", "/api/models")
        check(draft["slug"] not in [m["slug"] for m in listing["models"]],
              "szkic nie pojawia sie w katalogu")
        status, _ = anon.call("GET", "/api/models/{}".format(draft["slug"]))
        check(status == 404, "anonim nie otworzy szkicu po adresie")

        print("\n[14] Termin waznosci linku i sciezka poza magazynem")
        # Test zna sekret serwera, wiec sklada wlasne tokeny. Najpierw kontrola:
        # swiezy token musi dzialac, inaczej ponizszy wynik nic by nie dowodzil.
        fresh = app_security.make_token(
            {"fid": copy_b["file_id"], "uid": 2, "sha": copy_b["sha256"], "n": "kontrola"},
            300, "download")
        status, _, _ = user.call(
            "GET", "/api/download/{}?token={}".format(copy_b["file_id"], fresh), raw=True)
        check(status == 200, "token zlozony sekretem serwera dziala (kontrola testu)")

        stale = app_security.make_token(
            {"fid": copy_b["file_id"], "uid": 2, "sha": copy_b["sha256"], "n": "przeterminowany"},
            -60, "download")
        status, _, _ = user.call(
            "GET", "/api/download/{}?token={}".format(copy_b["file_id"], stale), raw=True)
        check(status == 403, "ten sam token po terminie waznosci odrzucony")

        # Napastnik z dostepem do bazy kieruje wpis poza katalog magazynu.
        conn = sqlite3.connect(str(db_path))
        conn.execute("UPDATE files SET storage_path = ? WHERE id = ?",
                     ("../../../../etc/hosts", copy_b["file_id"]))
        conn.commit()
        conn.close()
        status, grant_evil = user.call("POST", "/api/files/{}/grant".format(copy_b["file_id"]))
        if status == 200:
            status, _, _ = user.call("GET", grant_evil["url"], raw=True)
        check(status == 409, "sciezka wychodzaca poza magazyn zablokowana")

        print("\n[15] Limit prob logowania")
        attacker = Client(BASE)
        codes = []
        for attempt in range(11):
            code, _ = attacker.call("POST", "/api/auth/login", {
                "email": "ofiara@example.com", "password": "zgaduje-haslo-{}".format(attempt)
            })
            codes.append(code)
        check(codes[:10] == [401] * 10, "pierwsze 10 prob to zwykle odmowy")
        check(codes[10] == 429, "11. proba zablokowana limitem")

    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
        shutil.rmtree(str(workdir), ignore_errors=True)

    print("\n{}\nZdane: {}   Niezdane: {}".format("-" * 50, passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
