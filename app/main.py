"""Biblioteka cyfrowa plikow STL - API i serwowanie frontendu."""

import json
import re
import secrets
import time
import unicodedata
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, Response, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field

from . import config, db, integrity, security, storage

SESSION_COOKIE = "stl_session"
CSRF_COOKIE = "stl_csrf"
CSRF_HEADER = "x-csrf-token"

app = FastAPI(title="Biblioteka STL", docs_url=None, redoc_url=None, openapi_url=None)


# --- Pomocnicze --------------------------------------------------------------


# Litery, ktore nie rozkladaja sie w NFKD na "podstawa + znak diakrytyczny".
# Bez tej mapy "kolo" wyszloby jako "koo", bo samo 'l' zniknieloby przy
# konwersji do ASCII. Pozostale polskie znaki (a, c, e, n, o, s, z) NFKD
# obsluguje poprawnie.
TRANSLITERATION = str.maketrans({
    "ł": "l", "Ł": "L",
    "ø": "o", "Ø": "O",
    "đ": "d", "Đ": "D",
    "æ": "ae", "Æ": "AE",
    "ß": "ss",
})


def slugify(text: str) -> str:
    normalized = unicodedata.normalize("NFKD", text.translate(TRANSLITERATION))
    ascii_text = normalized.encode("ascii", "ignore").decode("ascii").lower()
    slug = re.sub(r"[^a-z0-9]+", "-", ascii_text).strip("-")
    return slug or "model-{}".format(secrets.token_hex(4))


def client_ip(request: Request) -> str:
    # Za odwrotnym proxy ustaw zaufany nagłówek w konfiguracji serwera WWW.
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else ""


def now() -> int:
    return int(time.time())


# --- Sesja i uprawnienia -----------------------------------------------------


def current_user(request: Request) -> Optional[Dict[str, Any]]:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    payload = security.read_token(token, purpose="session")
    if payload is None:
        return None
    user = db.query_one(
        "SELECT id, email, is_admin, is_active FROM users WHERE id = ?",
        (payload.get("uid"),),
    )
    if user is None or not user["is_active"]:
        return None
    return user


def require_user(request: Request) -> Dict[str, Any]:
    user = current_user(request)
    if user is None:
        raise HTTPException(status_code=401, detail="Wymagane zalogowanie")
    return user


def require_admin(request: Request) -> Dict[str, Any]:
    user = require_user(request)
    if not user["is_admin"]:
        raise HTTPException(status_code=403, detail="Wymagane uprawnienia administratora")
    return user


def set_session(response: Response, user_id: int) -> str:
    token = security.make_token({"uid": user_id}, config.SESSION_TTL_SECONDS, "session")
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=config.SESSION_TTL_SECONDS,
        httponly=True,
        samesite="lax",
        secure=config.COOKIE_SECURE,
        path="/",
    )
    csrf = secrets.token_urlsafe(32)
    response.set_cookie(
        CSRF_COOKIE,
        csrf,
        max_age=config.SESSION_TTL_SECONDS,
        httponly=False,  # frontend musi go odczytac i odeslac w naglowku
        samesite="lax",
        secure=config.COOKIE_SECURE,
        path="/",
    )
    return csrf


# --- Middleware: naglowki bezpieczenstwa i CSRF -------------------------------


@app.middleware("http")
async def security_layer(request: Request, call_next):
    # Double-submit cookie: kazde zapytanie zmieniajace stan musi przyniesc
    # naglowek X-CSRF-Token rowny ciasteczku CSRF. Atakujacy z obcej domeny
    # ciasteczka nie odczyta, wiec naglowka nie podrobi.
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        cookie_value = request.cookies.get(CSRF_COOKIE)
        header_value = request.headers.get(CSRF_HEADER)
        if cookie_value and not (
            header_value and secrets.compare_digest(cookie_value, header_value)
        ):
            return JSONResponse({"detail": "Brak lub bledny token CSRF"}, status_code=403)

    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; "
        "frame-ancestors 'none'",
    )
    return response


# --- Start -------------------------------------------------------------------


@app.on_event("startup")
def startup() -> None:
    db.init()

    if config.SECRET_KEY_IS_EPHEMERAL:
        print(
            "[UWAGA] STL_SECRET_KEY nie jest ustawiony - wygenerowano losowy. "
            "Po restarcie wszyscy zostana wylogowani. W produkcji ustaw go na stale."
        )
    if security.public_key_hex() is None:
        print(
            "[UWAGA] Brak klucza podpisu. Uruchom: python3 tools/keygen.py "
            "i ustaw STL_SIGNING_PUBLIC_KEY. Bez tego zaden plik nie bedzie do pobrania."
        )
    elif config.ONLINE_SIGNING:
        print(
            "[INFO] Tryb podpisywania: ONLINE (klucz prywatny na serwerze). "
            "Do produkcji rozwaz tryb offline - patrz README."
        )
    else:
        print("[INFO] Tryb podpisywania: OFFLINE (serwer nie ma klucza prywatnego).")

    if config.ADMIN_EMAIL and config.ADMIN_PASSWORD:
        existing = db.query_one("SELECT id FROM users WHERE email = ?", (config.ADMIN_EMAIL.lower(),))
        if existing is None:
            db.execute(
                "INSERT INTO users (email, password_hash, is_admin, is_active, created_at) "
                "VALUES (?, ?, 1, 1, ?)",
                (config.ADMIN_EMAIL.lower(), security.hash_password(config.ADMIN_PASSWORD), now()),
            )
            db.audit("admin.bootstrap", None, config.ADMIN_EMAIL.lower())
            print("[INFO] Utworzono konto administratora: {}".format(config.ADMIN_EMAIL))


# --- Modele zapytan ----------------------------------------------------------


class Credentials(BaseModel):
    email: EmailStr
    password: str = Field(min_length=10, max_length=256)


class ModelIn(BaseModel):
    title: str = Field(min_length=2, max_length=200)
    description: str = Field(default="", max_length=5000)
    category: str = Field(default="inne", max_length=60)
    license: str = Field(default="CC BY-NC 4.0", max_length=100)
    is_published: bool = True


class SignatureIn(BaseModel):
    file_id: int
    manifest: Dict[str, Any]
    signature: str = Field(min_length=64, max_length=256)


# --- Autoryzacja -------------------------------------------------------------


@app.post("/api/auth/register")
def register(payload: Credentials, response: Response) -> Dict[str, Any]:
    if not config.ALLOW_REGISTRATION:
        raise HTTPException(status_code=403, detail="Rejestracja jest wylaczona")

    email = payload.email.lower()
    if db.query_one("SELECT id FROM users WHERE email = ?", (email,)):
        raise HTTPException(status_code=409, detail="Konto o tym adresie juz istnieje")

    user_id = db.execute(
        "INSERT INTO users (email, password_hash, is_admin, is_active, created_at) "
        "VALUES (?, ?, 0, 1, ?)",
        (email, security.hash_password(payload.password), now()),
    )
    db.audit("user.register", user_id, email)
    csrf = set_session(response, user_id)
    return {"email": email, "is_admin": False, "csrf": csrf}


@app.post("/api/auth/login")
def login(payload: Credentials, request: Request, response: Response) -> Dict[str, Any]:
    email = payload.email.lower()
    ip = client_ip(request)
    window_start = now() - config.LOGIN_WINDOW_SECONDS

    recent = db.query_one(
        "SELECT COUNT(*) AS c FROM login_attempts WHERE email = ? AND ip = ? AND ts > ?",
        (email, ip, window_start),
    )
    if recent and recent["c"] >= config.LOGIN_MAX_ATTEMPTS:
        raise HTTPException(
            status_code=429, detail="Za duzo prob logowania. Sprobuj ponownie pozniej."
        )

    user = db.query_one(
        "SELECT id, email, password_hash, is_admin, is_active FROM users WHERE email = ?",
        (email,),
    )
    password_ok = user is not None and security.verify_password(
        payload.password, user["password_hash"]
    )

    if not password_ok or not user["is_active"]:
        db.execute(
            "INSERT INTO login_attempts (email, ip, ts) VALUES (?, ?, ?)", (email, ip, now())
        )
        db.audit("user.login_failed", None, "{} z {}".format(email, ip))
        # Ten sam komunikat w obu przypadkach - nie zdradzamy, czy konto istnieje.
        raise HTTPException(status_code=401, detail="Bledny e-mail lub haslo")

    db.execute("DELETE FROM login_attempts WHERE email = ? AND ip = ?", (email, ip))
    db.audit("user.login", user["id"], ip)
    csrf = set_session(response, user["id"])
    return {"email": user["email"], "is_admin": bool(user["is_admin"]), "csrf": csrf}


@app.post("/api/auth/logout")
def logout(response: Response) -> Dict[str, str]:
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")
    return {"status": "wylogowano"}


@app.get("/api/auth/me")
def me(request: Request) -> Dict[str, Any]:
    user = current_user(request)
    if user is None:
        return {"authenticated": False, "registration_open": config.ALLOW_REGISTRATION}
    return {
        "authenticated": True,
        "email": user["email"],
        "is_admin": bool(user["is_admin"]),
        "csrf": request.cookies.get(CSRF_COOKIE, ""),
    }


# --- Klucz publiczny ---------------------------------------------------------


@app.get("/api/pubkey")
def pubkey() -> Dict[str, Any]:
    """Klucz publiczny biblioteki. Kazdy moze go pobrac i sprawdzic podpisy
    samodzielnie, bez ufania temu serwerowi."""
    key_hex = security.public_key_hex()
    if key_hex is None:
        raise HTTPException(status_code=503, detail="Serwer nie ma skonfigurowanego klucza")
    return {
        "algorithm": "Ed25519",
        "public_key": key_hex,
        "key_id": security.key_id(key_hex),
        "publisher": config.PUBLISHER,
        "manifest_schema": security.MANIFEST_SCHEMA,
    }


# --- Katalog -----------------------------------------------------------------


def file_public_view(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": row["id"],
        "filename": row["filename"],
        "size": row["size"],
        "triangles": row["triangles"],
        "sha256": row["sha256"],
        "status": row["status"],
        "key_id": row["key_id"],
        "signed_at": row["signed_at"],
        "uploaded_at": row["uploaded_at"],
    }


@app.get("/api/models")
def list_models(
    q: str = "", category: str = "", limit: int = 60, offset: int = 0
) -> Dict[str, Any]:
    limit = max(1, min(limit, 200))
    offset = max(0, offset)

    conditions = ["m.is_published = 1"]
    params: List[Any] = []
    if q:
        conditions.append("(m.title LIKE ? OR m.description LIKE ?)")
        like = "%{}%".format(q)
        params.extend([like, like])
    if category:
        conditions.append("m.category = ?")
        params.append(category)

    where = " AND ".join(conditions)
    rows = db.query_all(
        "SELECT m.id, m.slug, m.title, m.description, m.category, m.license, m.created_at, "
        "  (SELECT COUNT(*) FROM files f WHERE f.model_id = m.id AND f.status = 'signed') AS files_ready, "
        "  (SELECT COUNT(*) FROM files f WHERE f.model_id = m.id) AS files_total "
        "FROM models m WHERE {} ORDER BY m.created_at DESC LIMIT ? OFFSET ?".format(where),
        tuple(params) + (limit, offset),
    )
    total = db.query_one(
        "SELECT COUNT(*) AS c FROM models m WHERE {}".format(where), tuple(params)
    )
    categories = db.query_all(
        "SELECT category, COUNT(*) AS c FROM models WHERE is_published = 1 "
        "GROUP BY category ORDER BY c DESC"
    )
    return {
        "models": rows,
        "total": total["c"] if total else 0,
        "categories": categories,
    }


@app.get("/api/models/{slug}")
def get_model(slug: str, request: Request) -> Dict[str, Any]:
    model = db.query_one("SELECT * FROM models WHERE slug = ?", (slug,))
    if model is None or (not model["is_published"] and current_user(request) is None):
        raise HTTPException(status_code=404, detail="Nie ma takiego modelu")

    files = db.query_all(
        "SELECT * FROM files WHERE model_id = ? ORDER BY filename", (model["id"],)
    )
    return {
        "model": {
            "slug": model["slug"],
            "title": model["title"],
            "description": model["description"],
            "category": model["category"],
            "license": model["license"],
            "created_at": model["created_at"],
        },
        "files": [file_public_view(row) for row in files],
        "authenticated": current_user(request) is not None,
    }


# --- Pobieranie --------------------------------------------------------------


def load_file_or_404(file_id: int) -> Dict[str, Any]:
    row = db.query_one("SELECT * FROM files WHERE id = ?", (file_id,))
    if row is None:
        raise HTTPException(status_code=404, detail="Nie ma takiego pliku")
    return row


@app.post("/api/files/{file_id}/grant")
def grant_download(file_id: int, request: Request) -> Dict[str, Any]:
    """Wystawia jednorazowy, wygasajacy link do pobrania.

    Token jest zwiazany z konkretnym plikiem, konkretnym uzytkownikiem i
    konkretnym hashem - przeklejenie go pod inny plik uniewaznia podpis HMAC.
    """
    user = require_user(request)
    row = load_file_or_404(file_id)

    try:
        integrity.check_file(row, deep=False)
    except integrity.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="Plik niedostepny: {}".format(exc.reason))

    token = security.make_token(
        {"fid": row["id"], "uid": user["id"], "sha": row["sha256"], "n": secrets.token_hex(8)},
        config.DOWNLOAD_TOKEN_TTL_SECONDS,
        "download",
    )
    return {
        "url": "/api/download/{}?token={}".format(row["id"], token),
        "expires_in": config.DOWNLOAD_TOKEN_TTL_SECONDS,
        "sha256": row["sha256"],
        "filename": row["filename"],
    }


def consume_download_token(file_id: int, token: str) -> Dict[str, Any]:
    payload = security.read_token(token, purpose="download")
    if payload is None:
        raise HTTPException(status_code=403, detail="Link wygasl albo jest nieprawidlowy")
    if int(payload.get("fid", -1)) != file_id:
        raise HTTPException(status_code=403, detail="Link nie pasuje do tego pliku")
    return payload


@app.get("/api/download/{file_id}")
def download(file_id: int, token: str, request: Request):
    payload = consume_download_token(file_id, token)
    row = load_file_or_404(file_id)

    if payload.get("sha") != row["sha256"]:
        # Hash zmienil sie miedzy wystawieniem linku a pobraniem.
        integrity.quarantine(file_id, "hash zmienil sie po wystawieniu linku")
        raise HTTPException(status_code=409, detail="Plik zmienil sie od czasu wystawienia linku")

    try:
        integrity.guard_download(row)
    except integrity.IntegrityError as exc:
        raise HTTPException(
            status_code=409,
            detail="Weryfikacja pliku nie powiodla sie, pobieranie wstrzymane: {}".format(exc.reason),
        )

    db.execute(
        "INSERT INTO downloads (user_id, file_id, ts, ip) VALUES (?, ?, ?, ?)",
        (payload.get("uid"), file_id, now(), client_ip(request)),
    )

    return FileResponse(
        path=str(storage.absolute_path(row["storage_path"])),
        media_type="model/stl",
        filename=row["filename"],
        headers={
            "X-STL-SHA256": row["sha256"],
            "X-STL-Signature": row["signature"] or "",
            "X-STL-Key-Id": row["key_id"] or "",
            "Cache-Control": "no-store",
        },
    )


@app.get("/api/files/{file_id}/signature")
def file_signature(file_id: int, request: Request) -> Dict[str, Any]:
    """Plik .sig.json - manifest + podpis + klucz publiczny do weryfikacji offline."""
    require_user(request)
    row = load_file_or_404(file_id)
    if row["status"] != "signed":
        raise HTTPException(status_code=409, detail="Plik nie ma jeszcze podpisu")
    return integrity.sidecar(row)


@app.get("/api/files/{file_id}/verify")
def verify_now(file_id: int, request: Request) -> Dict[str, Any]:
    """Weryfikacja na zadanie - przelicza hash pliku na dysku i sprawdza podpis."""
    require_user(request)
    row = load_file_or_404(file_id)
    try:
        integrity.check_file(row, deep=True)
    except integrity.IntegrityError as exc:
        return {"ok": False, "reason": exc.reason, "checked_at": now()}
    return {
        "ok": True,
        "sha256": row["sha256"],
        "key_id": row["key_id"],
        "checked_at": now(),
    }


# --- Panel administratora ----------------------------------------------------


@app.post("/api/admin/models")
def create_model(payload: ModelIn, request: Request) -> Dict[str, Any]:
    admin = require_admin(request)
    slug = slugify(payload.title)
    if db.query_one("SELECT id FROM models WHERE slug = ?", (slug,)):
        slug = "{}-{}".format(slug, secrets.token_hex(3))

    model_id = db.execute(
        "INSERT INTO models (slug, title, description, category, license, is_published, "
        "created_at, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            slug,
            payload.title,
            payload.description,
            payload.category or "inne",
            payload.license,
            1 if payload.is_published else 0,
            now(),
            admin["id"],
        ),
    )
    db.audit("model.create", admin["id"], slug)
    return {"id": model_id, "slug": slug}


@app.post("/api/admin/models/{slug}/files")
async def upload_file(
    slug: str,
    request: Request,
    file: UploadFile = File(...),
    filename: str = Form(default=""),
) -> Dict[str, Any]:
    admin = require_admin(request)
    model = db.query_one("SELECT * FROM models WHERE slug = ?", (slug,))
    if model is None:
        raise HTTPException(status_code=404, detail="Nie ma takiego modelu")

    safe_name = (filename or file.filename or "model.stl").strip()
    safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", safe_name)[:120]
    if not safe_name.lower().endswith(".stl"):
        safe_name += ".stl"

    try:
        sha256_hex, size, triangles, relative, deduplicated = storage.store_upload(
            file.file, config.MAX_UPLOAD_BYTES
        )
    except storage.InvalidSTL as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    finally:
        await file.close()

    uploaded_at = now()
    file_id = db.execute(
        "INSERT INTO files (model_id, filename, size, sha256, storage_path, triangles, "
        "status, uploaded_at, uploaded_by) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?)",
        (model["id"], safe_name, size, sha256_hex, relative, triangles, uploaded_at, admin["id"]),
    )
    db.audit("file.upload", admin["id"], "{} sha256={}".format(safe_name, sha256_hex))

    row = load_file_or_404(file_id)
    signed, message = integrity.sign_file_row(row, model["slug"])
    if signed:
        db.audit("file.signed_online", admin["id"], "file_id={}".format(file_id))

    return {
        "file_id": file_id,
        "sha256": sha256_hex,
        "size": size,
        "triangles": triangles,
        "deduplicated": deduplicated,
        "status": "signed" if signed else "pending",
        "note": message,
    }


@app.get("/api/admin/pending")
def pending_files(request: Request) -> Dict[str, Any]:
    """Lista plikow czekajacych na podpis - wejscie dla tools/sign_pending.py."""
    require_admin(request)
    rows = db.query_all(
        "SELECT f.id, f.filename, f.size, f.sha256, f.uploaded_at, m.slug AS model_slug "
        "FROM files f JOIN models m ON m.id = f.model_id "
        "WHERE f.status = 'pending' ORDER BY f.uploaded_at"
    )
    key_hex = security.public_key_hex()
    return {
        "pending": rows,
        "publisher": config.PUBLISHER,
        "key_id": security.key_id(key_hex) if key_hex else None,
        "manifest_schema": security.MANIFEST_SCHEMA,
    }


@app.post("/api/admin/signatures")
def submit_signature(payload: SignatureIn, request: Request) -> Dict[str, Any]:
    """Przyjmuje podpis zlozony na maszynie offline.

    Serwer nie ufa temu, co dostal: sam odtwarza manifest z wlasnych danych,
    porownuje go z nadeslanym i dopiero potem sprawdza podpis kluczem publicznym.
    """
    admin = require_admin(request)
    row = db.query_one(
        "SELECT f.*, m.slug AS model_slug FROM files f JOIN models m ON m.id = f.model_id "
        "WHERE f.id = ?",
        (payload.file_id,),
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Nie ma takiego pliku")

    public = security.load_public_key()
    if public is None:
        raise HTTPException(status_code=503, detail="Serwer nie ma klucza publicznego")
    key_hex = security.public_key_hex()

    expected = security.build_manifest(
        model_slug=row["model_slug"],
        filename=row["filename"],
        size=int(row["size"]),
        sha256_hex=row["sha256"],
        uploaded_at=int(row["uploaded_at"]),
        key_id_hex=security.key_id(key_hex),
    )
    if payload.manifest != expected:
        raise HTTPException(
            status_code=400,
            detail="Nadeslany manifest nie zgadza sie z danymi pliku na serwerze",
        )

    if not security.verify_manifest(expected, payload.signature, public):
        raise HTTPException(status_code=400, detail="Podpis nie przechodzi weryfikacji")

    ok, problem = storage.verify_stored_file(row["storage_path"], row["sha256"])
    if not ok:
        integrity.quarantine(row["id"], problem or "blad weryfikacji przy podpisywaniu")
        raise HTTPException(status_code=409, detail="Plik na dysku jest niezgodny: {}".format(problem))

    db.execute(
        "UPDATE files SET manifest = ?, signature = ?, key_id = ?, signed_at = ?, "
        "status = 'signed' WHERE id = ?",
        (
            json.dumps(expected, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
            payload.signature,
            expected["key_id"],
            now(),
            row["id"],
        ),
    )
    db.audit("file.signed_offline", admin["id"], "file_id={}".format(row["id"]))
    return {"status": "signed", "file_id": row["id"]}


@app.post("/api/admin/audit")
def run_audit(request: Request) -> Dict[str, Any]:
    """Przeglad calej biblioteki: kazdy plik przeliczony i sprawdzony."""
    admin = require_admin(request)
    rows = db.query_all("SELECT * FROM files ORDER BY id")

    problems: List[Dict[str, Any]] = []
    checked = 0
    for row in rows:
        checked += 1
        if row["status"] == "pending":
            ok, problem = storage.verify_stored_file(row["storage_path"], row["sha256"])
            if not ok:
                integrity.quarantine(row["id"], problem or "blad")
                problems.append({"file_id": row["id"], "filename": row["filename"], "reason": problem})
            continue
        try:
            integrity.check_file(row, deep=True)
        except integrity.IntegrityError as exc:
            if row["status"] != "quarantined":
                integrity.quarantine(row["id"], exc.reason)
            problems.append(
                {"file_id": row["id"], "filename": row["filename"], "reason": exc.reason}
            )

    db.audit("library.audit", admin["id"], "sprawdzono={} problemow={}".format(checked, len(problems)))
    return {"checked": checked, "problems": problems, "ran_at": now()}


@app.get("/api/admin/stats")
def admin_stats(request: Request) -> Dict[str, Any]:
    require_admin(request)

    def count(sql: str, params: tuple = ()) -> int:
        row = db.query_one(sql, params)
        return row["c"] if row else 0

    return {
        "users": count("SELECT COUNT(*) AS c FROM users"),
        "models": count("SELECT COUNT(*) AS c FROM models"),
        "files_signed": count("SELECT COUNT(*) AS c FROM files WHERE status = 'signed'"),
        "files_pending": count("SELECT COUNT(*) AS c FROM files WHERE status = 'pending'"),
        "files_quarantined": count("SELECT COUNT(*) AS c FROM files WHERE status = 'quarantined'"),
        "downloads_24h": count(
            "SELECT COUNT(*) AS c FROM downloads WHERE ts > ?", (now() - 86400,)
        ),
        "signing_mode": "online" if config.ONLINE_SIGNING else "offline",
        "key_id": security.key_id(security.public_key_hex())
        if security.public_key_hex()
        else None,
        "recent_audit": db.query_all(
            "SELECT ts, action, detail FROM audit_log ORDER BY id DESC LIMIT 25"
        ),
    }


@app.delete("/api/admin/files/{file_id}")
def delete_file(file_id: int, request: Request) -> Dict[str, str]:
    admin = require_admin(request)
    row = load_file_or_404(file_id)

    db.execute("DELETE FROM files WHERE id = ?", (file_id,))
    # Tresc kasujemy tylko wtedy, gdy zaden inny wpis jej nie uzywa.
    still_used = db.query_one("SELECT id FROM files WHERE sha256 = ?", (row["sha256"],))
    if still_used is None:
        try:
            path = storage.absolute_path(row["storage_path"])
            if path.exists():
                path.chmod(0o640)
                path.unlink()
        except (OSError, ValueError):
            pass
    db.audit("file.delete", admin["id"], "file_id={} {}".format(file_id, row["filename"]))
    return {"status": "usunieto"}


# --- Frontend ----------------------------------------------------------------

app.mount("/static", StaticFiles(directory=str(config.STATIC_DIR)), name="static")


@app.get("/")
def index() -> FileResponse:
    return FileResponse(str(config.STATIC_DIR / "index.html"))


@app.get("/admin")
def admin_page() -> FileResponse:
    return FileResponse(str(config.STATIC_DIR / "admin.html"))


@app.get("/model/{slug}")
def model_page(slug: str) -> FileResponse:
    return FileResponse(str(config.STATIC_DIR / "index.html"))
