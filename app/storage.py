"""Content-addressed file storage.

A file's path is derived from its own SHA-256:

    storage/ab/cd/abcd....stl

Two consequences. Swapping a file's content immediately puts it out of step
with the path it lives under — detectable without consulting the database at
all. And the same file uploaded twice occupies space once.
"""

import os
import shutil
import struct
import tempfile
from pathlib import Path
from typing import Any, BinaryIO, Dict, Optional, Tuple

from . import config, security

# A problem is reported as (message key, format parameters) so the caller can
# render it in the reader's language. See app/messages.py.
Problem = Tuple[str, Dict[str, Any]]


class InvalidSTL(Exception):
    """Raised when an upload is not a usable STL file."""

    def __init__(self, key: str, **params: Any):
        super().__init__(key)
        self.key = key
        self.params = params


def storage_path_for(sha256_hex: str) -> Path:
    return config.STORAGE_DIR / sha256_hex[0:2] / sha256_hex[2:4] / (sha256_hex + ".stl")


def relative_path_for(sha256_hex: str) -> str:
    return str(storage_path_for(sha256_hex).relative_to(config.STORAGE_DIR))


def absolute_path(relative: str) -> Path:
    """Join a stored relative path with the storage root, refusing anything that
    escapes it — a database row must never be able to point at /etc/passwd."""
    resolved = (config.STORAGE_DIR / relative).resolve()
    root = config.STORAGE_DIR.resolve()
    if root != resolved and root not in resolved.parents:
        raise ValueError("path outside storage directory: {}".format(relative))
    return resolved


def inspect_stl(path: Path) -> int:
    """Check that the file really is an STL and return its triangle count.

    Raises InvalidSTL if the structure does not add up. This is a filter against
    junk and files merely named `.stl`, not a security control — that is what
    the signature is for.
    """
    size = path.stat().st_size
    if size < 15:
        raise InvalidSTL("upload.too_small")

    with open(path, "rb") as handle:
        header = handle.read(84)

        # Binary form: 80-byte header, uint32 triangle count, then exactly
        # 50 bytes per triangle.
        if len(header) == 84:
            (count,) = struct.unpack("<I", header[80:84])
            if size == 84 + count * 50 and count > 0:
                return count

        # ASCII form: starts with "solid" and contains "facet normal" lines.
        handle.seek(0)
        head = handle.read(2048).lstrip()
        if head[:5].lower() == b"solid":
            handle.seek(0)
            facets = 0
            for line in handle:
                if line.strip().lower().startswith(b"facet normal"):
                    facets += 1
            if facets > 0:
                return facets
            raise InvalidSTL("upload.ascii_no_facet")

    raise InvalidSTL("upload.unknown_format")


def store_upload(source: BinaryIO, max_bytes: int) -> Tuple[str, int, int, str, bool]:
    """Write a stream into storage.

    Returns (sha256, size, triangle count, relative path, was_already_present).
    The upload lands in a temporary file first; only after hashing and STL
    validation does it move to its final path.
    """
    config.STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    tmp_fd, tmp_name = tempfile.mkstemp(dir=str(config.STORAGE_DIR), suffix=".part")
    tmp_path = Path(tmp_name)

    try:
        written = 0
        with os.fdopen(tmp_fd, "wb") as out:
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > max_bytes:
                    raise InvalidSTL("upload.too_large", limit=max_bytes // (1024 * 1024))
                out.write(chunk)

        if written == 0:
            raise InvalidSTL("upload.empty")

        triangles = inspect_stl(tmp_path)
        sha256_hex, size = security.sha256_file(tmp_path)
        target = storage_path_for(sha256_hex)

        if target.exists():
            # Identical content is already in the library; keep the original.
            tmp_path.unlink()
            return sha256_hex, size, triangles, relative_path_for(sha256_hex), True

        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(tmp_path), str(target))
        os.chmod(str(target), 0o440)  # read-only
        return sha256_hex, size, triangles, relative_path_for(sha256_hex), False
    except Exception:
        if tmp_path.exists():
            tmp_path.unlink()
        raise


def verify_stored_file(relative: str, expected_sha256: str) -> Tuple[bool, Optional[Problem]]:
    """Re-hash the file on disk and compare it against the expected digest.

    Returns (ok, problem). `problem` is a (message key, parameters) pair.
    """
    try:
        path = absolute_path(relative)
    except ValueError:
        return False, ("storage.path_outside", {"path": relative})

    if not path.exists():
        return False, ("storage.missing", {})

    actual, _ = security.sha256_file(path)
    if actual != expected_sha256:
        return False, (
            "storage.hash_mismatch",
            {"actual": actual[:16], "expected": expected_sha256[:16]},
        )
    return True, None
