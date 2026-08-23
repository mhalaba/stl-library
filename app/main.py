"""Digital STL library - API and frontend serving."""

import json
import re
import secrets
import time
import unicodedata
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, File, Form, HTTPException, Request, Response, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field

from . import config, db, integrity, messages, security, storage

SESSION_COOKIE = "stl_session"
CSRF_COOKIE = "stl_csrf"
CSRF_HEADER = "x-csrf-token"

app = FastAPI(title="STL Library", docs_url=None, redoc_url=None, openapi_url=None)


# --- Helpers -----------------------------------------------------------------

# Letters that do not decompose into "base + combining mark" under NFKD.
# Without this map "koło" would become "koo", because the bare 'ł' is dropped
# on the way to ASCII. The other Polish letters (ą, ć, ę, ń, ó, ś, ż, ź) are
# handled correctly by NFKD.
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
    # Behind a reverse proxy, make the web server set a trusted header.
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else ""


def now() -> int:
    return int(time.time())


def fail(status_code: int, request: Request, key: str, **params: Any) -> HTTPException:
    """Build an HTTPException whose message is in the reader's language."""
    return HTTPException(
        status_code=status_code,
        detail=messages.t(key, messages.resolve_lang(request), **params),
    )


# --- Session and permissions -------------------------------------------------


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
        raise fail(401, request, "auth.required")
    return user


def require_admin(request: Request) -> Dict[str, Any]:
    user = require_user(request)
    if not user["is_admin"]:
        raise fail(403, request, "auth.admin_required")
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
        httponly=False,  # the frontend has to read it back into a header
        samesite="lax",
        secure=config.COOKIE_SECURE,
        path="/",
    )
    return csrf


# --- Middleware: security headers and CSRF -----------------------------------


@app.middleware("http")
async def security_layer(request: Request, call_next):
    # Double-submit cookie: any state-changing request must carry an
    # X-CSRF-Token header matching the CSRF cookie. An attacker on another
    # origin cannot read the cookie, so cannot produce the header.
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        cookie_value = request.cookies.get(CSRF_COOKIE)
        header_value = request.headers.get(CSRF_HEADER)
        if cookie_value and not (
            header_value and secrets.compare_digest(cookie_value, header_value)
        ):
            return JSONResponse(
                {"detail": messages.t("csrf.invalid", messages.resolve_lang(request))},
                status_code=403,
            )

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


# --- Startup -----------------------------------------------------------------


@app.on_event("startup")
def startup() -> None:
    db.init()

    if config.SECRET_KEY_IS_EPHEMERAL:
        print(
            "[WARNING] STL_SECRET_KEY is not set - a random one was generated. "
            "Everyone will be signed out on restart. Set it permanently in production."
        )
    if security.public_key_hex() is None:
        print(
            "[WARNING] No signing key configured. Run: python3 tools/keygen.py "
            "and set STL_SIGNING_PUBLIC_KEY. Until then no file can be downloaded."
        )
    elif config.ONLINE_SIGNING:
        print(
            "[INFO] Signing mode: ONLINE (private key on the server). "
            "For production consider offline mode - see README."
        )
    else:
        print("[INFO] Signing mode: OFFLINE (the server holds no private key).")

    if config.ADMIN_EMAIL and config.ADMIN_PASSWORD:
        existing = db.query_one(
            "SELECT id FROM users WHERE email = ?", (config.ADMIN_EMAIL.lower(),)
        )
        if existing is None:
            db.execute(
                "INSERT INTO users (email, password_hash, is_admin, is_active, created_at) "
                "VALUES (?, ?, 1, 1, ?)",
                (
                    config.ADMIN_EMAIL.lower(),
                    security.hash_password(config.ADMIN_PASSWORD),
                    now(),
                ),
            )
            db.audit("admin.bootstrap", None, config.ADMIN_EMAIL.lower())
            print("[INFO] Administrator account created: {}".format(config.ADMIN_EMAIL))


# --- Request models ----------------------------------------------------------


class Credentials(BaseModel):
    email: EmailStr
    password: str = Field(min_length=10, max_length=256)


class ModelIn(BaseModel):
    title: str = Field(min_length=2, max_length=200)
    description: str = Field(default="", max_length=5000)
    category: str = Field(default="other", max_length=60)
    license: str = Field(default="CC BY-NC 4.0", max_length=100)
    is_published: bool = True


class SignatureIn(BaseModel):
    file_id: int
    manifest: Dict[str, Any]
    signature: str = Field(min_length=64, max_length=256)


# --- Authentication ----------------------------------------------------------


@app.post("/api/auth/register")
def register(payload: Credentials, request: Request, response: Response) -> Dict[str, Any]:
    if not config.ALLOW_REGISTRATION:
        raise fail(403, request, "auth.registration_closed")

    email = payload.email.lower()
    if db.query_one("SELECT id FROM users WHERE email = ?", (email,)):
        raise fail(409, request, "auth.email_taken")

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
        raise fail(429, request, "auth.too_many_attempts")

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
        db.audit("user.login_failed", None, "{} from {}".format(email, ip))
        # The same message either way - we do not reveal whether the account exists.
        raise fail(401, request, "auth.invalid_credentials")

    db.execute("DELETE FROM login_attempts WHERE email = ? AND ip = ?", (email, ip))
    db.audit("user.login", user["id"], ip)
    csrf = set_session(response, user["id"])
    return {"email": user["email"], "is_admin": bool(user["is_admin"]), "csrf": csrf}


@app.post("/api/auth/logout")
def logout(request: Request, response: Response) -> Dict[str, str]:
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")
    return {"status": messages.t("auth.signed_out", messages.resolve_lang(request))}


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


# --- Public key --------------------------------------------------------------


@app.get("/api/pubkey")
def pubkey(request: Request) -> Dict[str, Any]:
    """The library's public key. Anyone may fetch it and check signatures
    themselves, without trusting this server."""
    key_hex = security.public_key_hex()
    if key_hex is None:
        raise fail(503, request, "sign.no_public_key")
    return {
        "algorithm": "Ed25519",
        "public_key": key_hex,
        "key_id": security.key_id(key_hex),
        "publisher": config.PUBLISHER,
        "manifest_schema": security.MANIFEST_SCHEMA,
    }


# --- Catalogue ---------------------------------------------------------------


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
        raise fail(404, request, "model.not_found")

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


# --- Downloads ---------------------------------------------------------------


def load_file_or_404(file_id: int, request: Request) -> Dict[str, Any]:
    row = db.query_one("SELECT * FROM files WHERE id = ?", (file_id,))
    if row is None:
        raise fail(404, request, "file.not_found")
    return row


@app.post("/api/files/{file_id}/grant")
def grant_download(file_id: int, request: Request) -> Dict[str, Any]:
    """Issue a single expiring download link.

    The token is bound to one file, one user and one digest - moving it to a
    different file invalidates the HMAC.
    """
    user = require_user(request)
    row = load_file_or_404(file_id, request)
    lang = messages.resolve_lang(request)

    try:
        integrity.check_file(row, deep=False)
    except integrity.IntegrityError as exc:
        raise fail(409, request, "file.unavailable", reason=exc.reason(lang))

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


def consume_download_token(file_id: int, token: str, request: Request) -> Dict[str, Any]:
    payload = security.read_token(token, purpose="download")
    if payload is None:
        raise fail(403, request, "download.link_invalid")
    if int(payload.get("fid", -1)) != file_id:
        raise fail(403, request, "download.link_wrong_file")
    return payload


@app.get("/api/download/{file_id}")
def download(file_id: int, token: str, request: Request):
    payload = consume_download_token(file_id, token, request)
    row = load_file_or_404(file_id, request)
    lang = messages.resolve_lang(request)

    if payload.get("sha") != row["sha256"]:
        # The digest changed between issuing the link and using it.
        integrity.quarantine(file_id, "digest changed after the link was issued")
        raise fail(409, request, "file.changed_since_link")

    try:
        integrity.guard_download(row)
    except integrity.IntegrityError as exc:
        raise fail(409, request, "file.verification_failed", reason=exc.reason(lang))

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
    """The .sig.json document - manifest, signature and public key, enough to
    verify the download offline."""
    require_user(request)
    row = load_file_or_404(file_id, request)
    if row["status"] != "signed":
        raise fail(409, request, "file.not_signed_yet")
    return integrity.sidecar(row)


@app.get("/api/files/{file_id}/verify")
def verify_now(file_id: int, request: Request) -> Dict[str, Any]:
    """On-demand check - re-hashes the file on disk and verifies the signature."""
    require_user(request)
    row = load_file_or_404(file_id, request)
    try:
        integrity.check_file(row, deep=True)
    except integrity.IntegrityError as exc:
        return {
            "ok": False,
            "reason": exc.reason(messages.resolve_lang(request)),
            "reason_key": exc.key,
            "checked_at": now(),
        }
    return {
        "ok": True,
        "sha256": row["sha256"],
        "key_id": row["key_id"],
        "checked_at": now(),
    }


# --- Administration ----------------------------------------------------------


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
            payload.category or "other",
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
        raise fail(404, request, "model.not_found")

    safe_name = (filename or file.filename or "model.stl").strip()
    safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", safe_name)[:120]
    if not safe_name.lower().endswith(".stl"):
        safe_name += ".stl"

    try:
        sha256_hex, size, triangles, relative, deduplicated = storage.store_upload(
            file.file, config.MAX_UPLOAD_BYTES
        )
    except storage.InvalidSTL as exc:
        raise fail(400, request, exc.key, **exc.params)
    finally:
        await file.close()

    uploaded_at = now()
    file_id = db.execute(
        "INSERT INTO files (model_id, filename, size, sha256, storage_path, triangles, "
        "status, uploaded_at, uploaded_by) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?)",
        (model["id"], safe_name, size, sha256_hex, relative, triangles, uploaded_at, admin["id"]),
    )
    db.audit("file.upload", admin["id"], "{} sha256={}".format(safe_name, sha256_hex))

    row = load_file_or_404(file_id, request)
    signed, note = integrity.sign_file_row(row, model["slug"])
    if signed:
        db.audit("file.signed_online", admin["id"], "file_id={}".format(file_id))

    return {
        "file_id": file_id,
        "sha256": sha256_hex,
        "size": size,
        "triangles": triangles,
        "deduplicated": deduplicated,
        "status": "signed" if signed else "pending",
        "note": note,
    }


@app.get("/api/admin/pending")
def pending_files(request: Request) -> Dict[str, Any]:
    """Files awaiting a signature - the input for tools/sign_pending.py."""
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
    """Accept a signature produced on an offline machine.

    The server does not take it on trust: it rebuilds the manifest from its own
    data, compares it with the one submitted, and only then checks the signature
    against the public key.
    """
    admin = require_admin(request)
    row = db.query_one(
        "SELECT f.*, m.slug AS model_slug FROM files f JOIN models m ON m.id = f.model_id "
        "WHERE f.id = ?",
        (payload.file_id,),
    )
    if row is None:
        raise fail(404, request, "file.not_found")

    public = security.load_public_key()
    if public is None:
        raise fail(503, request, "sign.no_public_key")
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
        raise fail(400, request, "sign.manifest_mismatch")

    if not security.verify_manifest(expected, payload.signature, public):
        raise fail(400, request, "sign.signature_invalid")

    ok, problem = storage.verify_stored_file(row["storage_path"], row["sha256"])
    if not ok:
        key, params = problem
        rendered = messages.t(key, messages.resolve_lang(request), **params)
        integrity.quarantine(row["id"], messages.t(key, "en", **params))
        raise fail(409, request, "sign.file_mismatch", reason=rendered)

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
    """Sweep the whole library: every file re-hashed and re-checked."""
    admin = require_admin(request)
    lang = messages.resolve_lang(request)
    rows = db.query_all("SELECT * FROM files ORDER BY id")

    problems: List[Dict[str, Any]] = []
    checked = 0
    for row in rows:
        checked += 1
        if row["status"] == "pending":
            ok, problem = storage.verify_stored_file(row["storage_path"], row["sha256"])
            if not ok:
                key, params = problem
                integrity.quarantine(row["id"], messages.t(key, "en", **params))
                problems.append({
                    "file_id": row["id"],
                    "filename": row["filename"],
                    "reason": messages.t(key, lang, **params),
                })
            continue
        try:
            integrity.check_file(row, deep=True)
        except integrity.IntegrityError as exc:
            if row["status"] != "quarantined":
                integrity.quarantine(row["id"], exc.reason("en"))
            problems.append({
                "file_id": row["id"],
                "filename": row["filename"],
                "reason": exc.reason(lang),
            })

    db.audit("library.audit", admin["id"], "checked={} problems={}".format(checked, len(problems)))
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
    row = load_file_or_404(file_id, request)

    db.execute("DELETE FROM files WHERE id = ?", (file_id,))
    # Remove the content only if no other entry still refers to it.
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
    return {"status": messages.t("file.deleted", messages.resolve_lang(request))}


# --- Frontend ----------------------------------------------------------------


class RevalidatingStatic(StaticFiles):
    """Serve assets with revalidation forced.

    StaticFiles already sends ETag and Last-Modified, but with no Cache-Control
    header a browser is free to apply heuristic freshness and keep yesterday's
    app.js after a deploy. `no-cache` does not disable caching - it only forbids
    using the cached copy without asking, so unchanged files still come back
    as a cheap 304.
    """

    def file_response(self, *args, **kwargs):
        response = super().file_response(*args, **kwargs)
        response.headers.setdefault("Cache-Control", "no-cache")
        return response


app.mount("/static", RevalidatingStatic(directory=str(config.STATIC_DIR)), name="static")


# The HTML shell must be revalidated on every visit. Without this a browser can
# keep serving yesterday's page - and with it yesterday's app.js - after a deploy.
SHELL_HEADERS = {"Cache-Control": "no-cache"}


def shell(name: str) -> FileResponse:
    return FileResponse(str(config.STATIC_DIR / name), headers=SHELL_HEADERS)


@app.get("/")
def index() -> FileResponse:
    return shell("index.html")


@app.get("/admin")
def admin_page() -> FileResponse:
    return shell("admin.html")


@app.get("/model/{slug}")
def model_page(slug: str) -> FileResponse:
    return shell("index.html")
