"""Skladowanie plikow adresowane trescia (content-addressed storage).

Sciezka pliku wynika z jego wlasnego SHA-256:

    storage/ab/cd/abcd....stl

Konsekwencja jest taka, ze podmiana zawartosci pliku od razu rozjezdza sie ze
sciezka, pod ktora ten plik lezy - wykrywalne bez zagladania do bazy danych.
Dodatkowo ten sam plik wgrany dwa razy zajmuje miejsce raz.
"""

import os
import shutil
import struct
import tempfile
from pathlib import Path
from typing import BinaryIO, Optional, Tuple

from . import config, security


class InvalidSTL(Exception):
    pass


def storage_path_for(sha256_hex: str) -> Path:
    return config.STORAGE_DIR / sha256_hex[0:2] / sha256_hex[2:4] / (sha256_hex + ".stl")


def relative_path_for(sha256_hex: str) -> str:
    return str(storage_path_for(sha256_hex).relative_to(config.STORAGE_DIR))


def absolute_path(relative: str) -> Path:
    """Skleja sciezke wzgledna z katalogiem storage i pilnuje, zeby wynik
    nie wyszedl poza niego (ochrona przed '../' w bazie)."""
    resolved = (config.STORAGE_DIR / relative).resolve()
    root = config.STORAGE_DIR.resolve()
    if root != resolved and root not in resolved.parents:
        raise ValueError("sciezka poza katalogiem storage: {}".format(relative))
    return resolved


def inspect_stl(path: Path) -> int:
    """Sprawdza, czy plik naprawde jest STL-em, i zwraca liczbe trojkatow.

    Rzuca InvalidSTL, jesli struktura sie nie zgadza. To nie jest zabezpieczenie
    kryptograficzne, tylko filtr na smieci i pliki podszywajace sie pod STL.
    """
    size = path.stat().st_size
    if size < 15:
        raise InvalidSTL("plik jest za maly, zeby byc STL-em")

    with open(path, "rb") as handle:
        header = handle.read(84)

        # Wariant binarny: 80 bajtow naglowka + uint32 z liczba trojkatow,
        # a dalej dokladnie 50 bajtow na trojkat.
        if len(header) == 84:
            (count,) = struct.unpack("<I", header[80:84])
            if size == 84 + count * 50 and count > 0:
                return count

        # Wariant ASCII: zaczyna sie od "solid" i zawiera "facet normal".
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
            raise InvalidSTL("plik ASCII zaczyna sie od 'solid', ale nie ma zadnej sciany")

    raise InvalidSTL("nierozpoznany format - to nie jest poprawny plik STL")


def store_upload(source: BinaryIO, max_bytes: int) -> Tuple[str, int, int, str, bool]:
    """Zapisuje strumien do storage.

    Zwraca (sha256, rozmiar, liczba trojkatow, sciezka wzgledna, czy_juz_byl).
    Plik ląduje najpierw w pliku tymczasowym: dopiero po policzeniu hasha i
    walidacji STL trafia na docelowa sciezke.
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
                    raise InvalidSTL(
                        "plik przekracza limit {} MB".format(max_bytes // (1024 * 1024))
                    )
                out.write(chunk)

        if written == 0:
            raise InvalidSTL("pusty plik")

        triangles = inspect_stl(tmp_path)
        sha256_hex, size = security.sha256_file(tmp_path)
        target = storage_path_for(sha256_hex)

        if target.exists():
            # Ta sama tresc juz jest w bibliotece - zostawiamy oryginal.
            tmp_path.unlink()
            return sha256_hex, size, triangles, relative_path_for(sha256_hex), True

        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(tmp_path), str(target))
        os.chmod(str(target), 0o440)  # tylko do odczytu
        return sha256_hex, size, triangles, relative_path_for(sha256_hex), False
    except Exception:
        if tmp_path.exists():
            tmp_path.unlink()
        raise


def verify_stored_file(relative: str, expected_sha256: str) -> Tuple[bool, Optional[str]]:
    """Przelicza SHA-256 pliku na dysku i porownuje z oczekiwanym.

    Zwraca (czy_ok, komunikat_bledu).
    """
    try:
        path = absolute_path(relative)
    except ValueError as exc:
        return False, str(exc)

    if not path.exists():
        return False, "plik nie istnieje na dysku"

    actual, _ = security.sha256_file(path)
    if actual != expected_sha256:
        return False, "SHA-256 sie nie zgadza (na dysku {}, oczekiwano {})".format(
            actual[:16], expected_sha256[:16]
        )
    return True, None
