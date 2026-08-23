#!/usr/bin/env python3
"""End-to-end test: does swapping a file actually get caught?

    ./.venv/bin/python tests/e2e.py

The test starts a real server in OFFLINE mode (no private key), signs files the
way tools/sign_pending.py does, and then plays the attacker: it swaps a file on
disk, and then swaps a file *together with* correcting the digest in the
database. Both attacks have to be stopped.
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

# The server subprocess gets the same secret. That lets the test mint its own
# download tokens and check how the server treats their expiry.
SECRET = "0" * 64
os.environ["STL_SECRET_KEY"] = SECRET

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from app import security as app_security  # noqa: E402

ADMIN_EMAIL = "admin@example.com"
ADMIN_PASSWORD = "a-very-long-test-password"
PORT = 8731
BASE = "http://127.0.0.1:{}".format(PORT)

ASCII_STL = b"""solid plate
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
endsolid plate
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
    """A minimal, valid binary STL - a cube of 12 triangles."""
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
        headers = {"Accept": "application/json", "Accept-Language": "en"}
        if self.csrf:
            headers["X-CSRF-Token"] = self.csrf
        headers.update(extra or {})
        return headers

    def call(self, method, path, body=None, raw=False):
        """Returns (http status, data)."""
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
                    # response.headers is a Message object - it looks names up
                    # case-insensitively, and the server sends them lowercase.
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
            {"file_id": item["id"], "manifest": manifest,
             "signature": private.sign(canonical(manifest)).hex()},
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
        "STL_SECRET_KEY": SECRET,
        "STL_SIGNING_PUBLIC_KEY": public_raw.hex(),   # offline mode: no private key
        "STL_PUBLISHER": "test-library",
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
            print("The server did not come up.")
            return 1

        admin = Client(BASE)

        print("\n[1] Accounts and permissions")
        status, _ = admin.login(ADMIN_EMAIL, ADMIN_PASSWORD)
        check(status == 200, "administrator signs in")
        status, _ = Client(BASE).login(ADMIN_EMAIL, "an-entirely-wrong-password")
        check(status == 401, "wrong password rejected")

        anon = Client(BASE)
        status, _ = anon.call("POST", "/api/admin/models", {"title": "Takeover attempt"})
        check(status == 401, "an anonymous visitor cannot create a model")

        user = Client(BASE)
        status, _ = user.register("user@example.com", "another-long-user-password")
        check(status == 200, "an ordinary user registers")
        status, _ = user.call("POST", "/api/admin/models", {"title": "Takeover attempt"})
        check(status == 403, "an ordinary user has no access to the admin panel")

        # CSRF: a request with the session cookie but without the header.
        no_csrf = Client(BASE)
        no_csrf.login(ADMIN_EMAIL, ADMIN_PASSWORD)
        no_csrf.csrf = None
        status, _ = no_csrf.call("POST", "/api/admin/models", {"title": "No CSRF"})
        check(status == 403, "a request without the CSRF token is rejected")

        print("\n[2] Models and uploads")
        status, model = admin.call("POST", "/api/admin/models", {
            "title": "Test cube", "description": "description", "category": "test", "license": "CC0"
        })
        check(status == 200, "model created")
        slug = model["slug"]

        status, upload = admin.upload(slug, "cube.stl", cube_stl())
        check(status == 200 and upload["status"] == "pending",
              "file uploaded, awaiting signature (offline mode)")
        file_id = upload["file_id"]
        original_sha = upload["sha256"]

        status, second = admin.upload(slug, "cube2.stl", cube_stl(12.0))
        check(status == 200, "second file uploaded")
        second_id = second["file_id"]

        status, bad = admin.upload(slug, "junk.stl", b"this is not an STL at all, just text")
        check(status == 400, "a file that is not an STL is rejected")

        print("\n[3] Downloading without a signature")
        status, _ = user.call("POST", "/api/files/{}/grant".format(file_id))
        check(status == 409, "an unsigned file cannot be downloaded")

        print("\n[4] Signing from an offline machine")
        signed_count = sign_all_pending(admin, private, key_id, "test-library")
        check(signed_count == 2, "both files signed ({})".format(signed_count))

        # The server must reject a signature made with a foreign key.
        intruder = Ed25519PrivateKey.generate()
        status, third = admin.upload(slug, "third.stl", cube_stl(7.0))
        third_id = third["file_id"]
        manifest = {
            "schema": "stl-library/manifest/v1", "publisher": "test-library", "model": slug,
            "filename": "third.stl", "size": third["size"], "sha256": third["sha256"],
            "uploaded_at": int(time.time()), "key_id": key_id,
        }
        status, _ = admin.call("POST", "/api/admin/signatures", {
            "file_id": third_id, "manifest": manifest,
            "signature": intruder.sign(canonical(manifest)).hex()
        })
        check(status == 400, "a signature from a foreign key is rejected")

        print("\n[5] An honest download")
        status, grant = user.call("POST", "/api/files/{}/grant".format(file_id))
        check(status == 200, "the user gets a download link")

        status, payload, headers = user.call("GET", grant["url"], raw=True)
        check(status == 200, "file downloaded")
        check(hashlib.sha256(payload).hexdigest() == original_sha, "content matches the digest")
        check(headers.get("X-STL-Key-Id") == key_id, "X-STL-Key-Id header carries the key identifier")

        status, anon_grant = anon.call("POST", "/api/files/{}/grant".format(file_id))
        check(status == 401, "an anonymous visitor gets no link")

        status, _, _ = user.call("GET", "/api/download/{}?token=made-up".format(file_id), raw=True)
        check(status == 403, "a made-up token is rejected")

        # The same token moved to a different file.
        token = grant["url"].split("token=")[1]
        status, _, _ = user.call("GET", "/api/download/{}?token={}".format(second_id, token), raw=True)
        check(status == 403, "a token bound to one file does not work on another")

        print("\n[6] Offline verification with verify_stl.py")
        status, sidecar = user.call("GET", "/api/files/{}/signature".format(file_id))
        stl_path = workdir / "downloaded.stl"
        sig_path = workdir / "downloaded.stl.sig.json"
        stl_path.write_bytes(payload)
        sig_path.write_text(json.dumps(sidecar), encoding="utf-8")

        result = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "verify_stl.py"), str(stl_path), str(sig_path)],
            capture_output=True, text=True,
        )
        check(result.returncode == 0, "verify_stl.py confirms authenticity")

        # The same verification without the `cryptography` library - pure Python.
        pure_env = dict(os.environ, PYTHONPATH="")
        pure = subprocess.run(
            [sys.executable, "-c",
             "import sys; sys.modules['cryptography']=None; "
             "sys.argv=['v', {!r}, {!r}]; exec(open({!r}).read())".format(
                 str(stl_path), str(sig_path), str(ROOT / "tools" / "verify_stl.py"))],
            capture_output=True, text=True, env=pure_env,
        )
        check("OK" in pure.stdout, "the built-in Ed25519 implementation confirms it too")

        tampered_copy = workdir / "swapped.stl"
        tampered_copy.write_bytes(cube_stl(11.0))
        result = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "verify_stl.py"), str(tampered_copy), str(sig_path)],
            capture_output=True, text=True,
        )
        check(result.returncode == 1, "verify_stl.py catches a swap on the user's side")

        print("\n[7] ATTACK: file swapped on the server's disk")
        db_path = workdir / "data" / "library.db"
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT storage_path, sha256 FROM files WHERE id = ?", (file_id,)).fetchone()
        target = workdir / "data" / "storage" / row["storage_path"]
        conn.close()

        os.chmod(str(target), 0o644)
        target.write_bytes(cube_stl(999.0))  # different geometry, still a valid STL

        status, grant2 = user.call("POST", "/api/files/{}/grant".format(file_id))
        status, body, _ = user.call("GET", grant2["url"], raw=True)
        check(status == 409, "the swapped file is NOT released")

        conn = sqlite3.connect(str(db_path))
        state = conn.execute("SELECT status FROM files WHERE id = ?", (file_id,)).fetchone()[0]
        conn.close()
        check(state == "quarantined", "the file was quarantined automatically")

        status, models = user.call("GET", "/api/models/{}".format(slug))
        quarantined = [f for f in models["files"] if f["id"] == file_id][0]
        check(quarantined["status"] == "quarantined", "the catalogue shows the file as blocked")

        print("\n[8] ATTACK: file swapped AND the digest corrected in the database")
        evil = cube_stl(31.0)
        evil_sha = hashlib.sha256(evil).hexdigest()

        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT storage_path FROM files WHERE id = ?", (second_id,)).fetchone()
        victim = workdir / "data" / "storage" / row["storage_path"]
        os.chmod(str(victim), 0o644)
        victim.write_bytes(evil)
        # The attacker has full database access and "fixes" every visible trace.
        conn.execute(
            "UPDATE files SET sha256 = ?, size = ? WHERE id = ?", (evil_sha, len(evil), second_id)
        )
        conn.commit()
        conn.close()

        status, grant3 = user.call("POST", "/api/files/{}/grant".format(second_id))
        if status == 200:
            status, _, _ = user.call("GET", grant3["url"], raw=True)
        check(status == 409, "a swap with a corrected digest in the database is stopped too")

        status, verdict = user.call("GET", "/api/files/{}/verify".format(second_id))
        check(verdict["ok"] is False, "the verify endpoint reports a problem")
        check(verdict["reason_key"] == "integrity.catalog_mismatch",
              "the reason points at the manifest mismatch [{}]".format(verdict["reason_key"]))

        print("\n[9] Auditing the whole library")
        status, audit = admin.call("POST", "/api/admin/audit")
        check(status == 200 and len(audit["problems"]) >= 2, "the audit catches both damaged files")

        cli = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "audit.py"), "--json"],
            capture_output=True, text=True, cwd=str(ROOT), env=env,
        )
        check(cli.returncode == 1, "tools/audit.py exits with code 1 when problems exist")

        print("\n[10] HTTP hardening")
        status, _, headers = anon.call("GET", "/", raw=True)
        check(headers.get("X-Content-Type-Options") == "nosniff", "nosniff header present")
        check("frame-ancestors 'none'" in headers.get("Content-Security-Policy", ""),
              "CSP blocks clickjacking")

        status, _ = anon.call("GET", "/api/download/1?token=" + "A" * 200, raw=False)
        check(status == 403, "a garbage token does not crash the server")

        print("\n[11] ASCII STL files")
        status, ascii_up = admin.upload(slug, "plate.stl", ASCII_STL)
        check(status == 200 and ascii_up["triangles"] == 2, "ASCII STL accepted and counted")
        sign_all_pending(admin, private, key_id, "test-library")
        status, ascii_grant = user.call("POST", "/api/files/{}/grant".format(ascii_up["file_id"]))
        status, ascii_payload, _ = user.call("GET", ascii_grant["url"], raw=True)
        check(status == 200 and ascii_payload == ASCII_STL, "ASCII STL served byte for byte")

        print("\n[12] Deduplication and deletion")
        status, other_model = admin.call("POST", "/api/admin/models", {"title": "Second model"})
        shared_bytes = cube_stl(5.0)
        status, copy_a = admin.upload(slug, "shared.stl", shared_bytes)
        status, copy_b = admin.upload(other_model["slug"], "shared.stl", shared_bytes)
        check(copy_b["deduplicated"] is True, "identical content uploaded twice is stored once")
        check(copy_a["sha256"] == copy_b["sha256"], "both entries point at the same content")
        sign_all_pending(admin, private, key_id, "test-library")

        status, _ = admin.call("DELETE", "/api/admin/files/{}".format(copy_a["file_id"]))
        check(status == 200, "the first entry is deleted")
        status, grant_b = user.call("POST", "/api/files/{}/grant".format(copy_b["file_id"]))
        status, body_b, _ = user.call("GET", grant_b["url"], raw=True)
        check(status == 200 and hashlib.sha256(body_b).hexdigest() == copy_b["sha256"],
              "deleting one entry did not remove content shared with another")

        print("\n[13] Unpublished model")
        status, draft = admin.call("POST", "/api/admin/models", {
            "title": "Working draft", "is_published": False
        })
        status, listing = anon.call("GET", "/api/models")
        check(draft["slug"] not in [m["slug"] for m in listing["models"]],
              "the draft does not appear in the catalogue")
        status, _ = anon.call("GET", "/api/models/{}".format(draft["slug"]))
        check(status == 404, "an anonymous visitor cannot open the draft by address")

        print("\n[14] Link expiry and paths outside storage")
        # The test knows the server's secret, so it mints its own tokens. First a
        # control: a fresh token has to work, otherwise the result below proves
        # nothing.
        fresh = app_security.make_token(
            {"fid": copy_b["file_id"], "uid": 2, "sha": copy_b["sha256"], "n": "control"},
            300, "download")
        status, _, _ = user.call(
            "GET", "/api/download/{}?token={}".format(copy_b["file_id"], fresh), raw=True)
        check(status == 200, "a token minted with the server's secret works (test control)")

        stale = app_security.make_token(
            {"fid": copy_b["file_id"], "uid": 2, "sha": copy_b["sha256"], "n": "expired"},
            -60, "download")
        status, _, _ = user.call(
            "GET", "/api/download/{}?token={}".format(copy_b["file_id"], stale), raw=True)
        check(status == 403, "the same token past its deadline is rejected")

        # An attacker with database access points an entry outside the storage root.
        conn = sqlite3.connect(str(db_path))
        conn.execute("UPDATE files SET storage_path = ? WHERE id = ?",
                     ("../../../../etc/hosts", copy_b["file_id"]))
        conn.commit()
        conn.close()
        status, grant_evil = user.call("POST", "/api/files/{}/grant".format(copy_b["file_id"]))
        if status == 200:
            status, _, _ = user.call("GET", grant_evil["url"], raw=True)
        check(status == 409, "a path escaping the storage directory is blocked")

        print("\n[15] Sign-in rate limit")
        attacker = Client(BASE)
        codes = []
        for attempt in range(11):
            code, _ = attacker.call("POST", "/api/auth/login", {
                "email": "victim@example.com", "password": "guessing-{}".format(attempt)
            })
            codes.append(code)
        check(codes[:10] == [401] * 10, "the first 10 attempts are ordinary refusals")
        check(codes[10] == 429, "the 11th attempt is rate-limited")

        print("\n[16] Language negotiation")
        polish = Client(BASE)
        status, body = polish.call("POST", "/api/auth/login",
                                   {"email": ADMIN_EMAIL, "password": "wrong-password-here"})
        english_message = body["detail"]

        class PolishClient(Client):
            def _headers(self, extra=None):
                headers = super()._headers(extra)
                headers["Accept-Language"] = "pl-PL,pl;q=0.9"
                return headers

        pl_client = PolishClient(BASE)
        status, body = pl_client.call("POST", "/api/auth/login",
                                      {"email": "someone@example.com", "password": "wrong-password"})
        check(body["detail"] != english_message, "Accept-Language changes the API message language")
        check("hasło" in body["detail"], "the Polish message actually comes back in Polish")

    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
        shutil.rmtree(str(workdir), ignore_errors=True)

    print("\n{}\nPassed: {}   Failed: {}".format("-" * 50, passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
