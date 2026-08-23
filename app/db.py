"""SQLite access layer. Every query goes through parameters - no SQL is built
by string concatenation.
"""

import sqlite3
import time
from contextlib import contextmanager
from typing import Any, Dict, Iterator, List, Optional

from . import config

SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    is_admin      INTEGER NOT NULL DEFAULT 0,
    is_active     INTEGER NOT NULL DEFAULT 1,
    created_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS models (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    slug         TEXT    NOT NULL UNIQUE,
    title        TEXT    NOT NULL,
    description  TEXT    NOT NULL DEFAULT '',
    category     TEXT    NOT NULL DEFAULT 'other',
    license      TEXT    NOT NULL DEFAULT 'CC BY-NC 4.0',
    is_published INTEGER NOT NULL DEFAULT 1,
    created_at   INTEGER NOT NULL,
    created_by   INTEGER REFERENCES users(id)
);

-- status:
--   pending      - uploaded, waiting for a signature (offline mode)
--   signed       - manifest signed with the Ed25519 key, file downloadable
--   quarantined  - a check failed, the file is blocked
CREATE TABLE IF NOT EXISTS files (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    model_id      INTEGER NOT NULL REFERENCES models(id) ON DELETE CASCADE,
    filename      TEXT    NOT NULL,
    size          INTEGER NOT NULL,
    sha256        TEXT    NOT NULL,
    storage_path  TEXT    NOT NULL,
    triangles     INTEGER NOT NULL DEFAULT 0,
    status        TEXT    NOT NULL DEFAULT 'pending',
    signature     TEXT,
    key_id        TEXT,
    manifest      TEXT,
    signed_at     INTEGER,
    uploaded_at   INTEGER NOT NULL,
    uploaded_by   INTEGER REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_files_model  ON files(model_id);
CREATE INDEX IF NOT EXISTS idx_files_sha    ON files(sha256);
CREATE INDEX IF NOT EXISTS idx_files_status ON files(status);

CREATE TABLE IF NOT EXISTS downloads (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    ts      INTEGER NOT NULL,
    ip      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_downloads_user ON downloads(user_id, ts);

CREATE TABLE IF NOT EXISTS login_attempts (
    id    INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    ip    TEXT NOT NULL,
    ts    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_attempts ON login_attempts(email, ip, ts);

CREATE TABLE IF NOT EXISTS audit_log (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       INTEGER NOT NULL,
    actor_id INTEGER,
    action   TEXT NOT NULL,
    detail   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
"""


def connect() -> sqlite3.Connection:
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(config.DB_PATH), timeout=15.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def cursor(commit: bool = False) -> Iterator[sqlite3.Cursor]:
    conn = connect()
    try:
        cur = conn.cursor()
        yield cur
        if commit:
            conn.commit()
    finally:
        conn.close()


def init() -> None:
    conn = connect()
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


def query_all(sql: str, params: tuple = ()) -> List[Dict[str, Any]]:
    with cursor() as cur:
        cur.execute(sql, params)
        return [dict(row) for row in cur.fetchall()]


def query_one(sql: str, params: tuple = ()) -> Optional[Dict[str, Any]]:
    with cursor() as cur:
        cur.execute(sql, params)
        row = cur.fetchone()
        return dict(row) if row else None


def execute(sql: str, params: tuple = ()) -> int:
    """Returns lastrowid."""
    with cursor(commit=True) as cur:
        cur.execute(sql, params)
        return cur.lastrowid


def audit(action: str, actor_id: Optional[int] = None, detail: str = "") -> None:
    execute(
        "INSERT INTO audit_log (ts, actor_id, action, detail) VALUES (?, ?, ?, ?)",
        (int(time.time()), actor_id, action, detail),
    )
