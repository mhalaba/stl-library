"""User-facing message catalogue.

Every string the API can show to a person lives here in both languages.
Internal strings — audit-log entries, server console output — stay English and
are not routed through this module.

Language is picked from the `stl_lang` cookie (set by the language switcher in
the UI), falling back to `Accept-Language`, falling back to English.
"""

from typing import Any, Optional

from . import config

SUPPORTED = ("en", "pl")
LANG_COOKIE = "stl_lang"
DEFAULT_LANG = config.DEFAULT_LANGUAGE if config.DEFAULT_LANGUAGE in SUPPORTED else "en"

CATALOG = {
    # --- Authentication ------------------------------------------------------
    "auth.required": {
        "en": "You need to be signed in",
        "pl": "Wymagane zalogowanie",
    },
    "auth.admin_required": {
        "en": "Administrator privileges required",
        "pl": "Wymagane uprawnienia administratora",
    },
    "auth.registration_closed": {
        "en": "Registration is closed",
        "pl": "Rejestracja jest wyłączona",
    },
    "auth.email_taken": {
        "en": "An account with this address already exists",
        "pl": "Konto o tym adresie już istnieje",
    },
    "auth.too_many_attempts": {
        "en": "Too many sign-in attempts. Try again later.",
        "pl": "Za dużo prób logowania. Spróbuj ponownie później.",
    },
    # Deliberately identical whether or not the account exists.
    "auth.invalid_credentials": {
        "en": "Wrong e-mail or password",
        "pl": "Błędny e-mail lub hasło",
    },
    "auth.signed_out": {
        "en": "signed out",
        "pl": "wylogowano",
    },
    "csrf.invalid": {
        "en": "Missing or invalid CSRF token",
        "pl": "Brak lub błędny token CSRF",
    },

    # --- Catalogue -----------------------------------------------------------
    "model.not_found": {
        "en": "No such model",
        "pl": "Nie ma takiego modelu",
    },
    "file.not_found": {
        "en": "No such file",
        "pl": "Nie ma takiego pliku",
    },
    "file.unavailable": {
        "en": "File unavailable: {reason}",
        "pl": "Plik niedostępny: {reason}",
    },
    "file.not_signed_yet": {
        "en": "This file has not been signed yet",
        "pl": "Plik nie ma jeszcze podpisu",
    },
    "file.changed_since_link": {
        "en": "The file changed after the link was issued",
        "pl": "Plik zmienił się od czasu wystawienia linku",
    },
    "file.verification_failed": {
        "en": "Verification failed, download stopped: {reason}",
        "pl": "Weryfikacja pliku nie powiodła się, pobieranie wstrzymane: {reason}",
    },
    "file.deleted": {
        "en": "deleted",
        "pl": "usunięto",
    },

    # --- Download links ------------------------------------------------------
    "download.link_invalid": {
        "en": "The link has expired or is invalid",
        "pl": "Link wygasł albo jest nieprawidłowy",
    },
    "download.link_wrong_file": {
        "en": "This link does not belong to this file",
        "pl": "Link nie pasuje do tego pliku",
    },

    # --- Uploads -------------------------------------------------------------
    "upload.too_large": {
        "en": "File exceeds the {limit} MB limit",
        "pl": "Plik przekracza limit {limit} MB",
    },
    "upload.empty": {
        "en": "Empty file",
        "pl": "Pusty plik",
    },
    "upload.too_small": {
        "en": "File is too small to be an STL",
        "pl": "Plik jest za mały, żeby być STL-em",
    },
    "upload.ascii_no_facet": {
        "en": "File starts with 'solid' but contains no facet",
        "pl": "Plik zaczyna się od 'solid', ale nie ma żadnej ściany",
    },
    "upload.unknown_format": {
        "en": "Unrecognised format — this is not a valid STL file",
        "pl": "Nierozpoznany format — to nie jest poprawny plik STL",
    },

    # --- Signing -------------------------------------------------------------
    "sign.no_public_key": {
        "en": "The server has no public key configured",
        "pl": "Serwer nie ma skonfigurowanego klucza publicznego",
    },
    "sign.manifest_mismatch": {
        "en": "The submitted manifest does not match the file on the server",
        "pl": "Nadesłany manifest nie zgadza się z danymi pliku na serwerze",
    },
    "sign.signature_invalid": {
        "en": "The signature does not verify",
        "pl": "Podpis nie przechodzi weryfikacji",
    },
    "sign.file_mismatch": {
        "en": "The file on disk does not match: {reason}",
        "pl": "Plik na dysku jest niezgodny: {reason}",
    },

    # --- Integrity checks ----------------------------------------------------
    "integrity.quarantined": {
        "en": "the file is quarantined after a failed check",
        "pl": "plik jest w kwarantannie po nieudanej weryfikacji",
    },
    "integrity.unsigned": {
        "en": "the file has not been signed yet",
        "pl": "plik nie ma jeszcze złożonego podpisu",
    },
    "integrity.manifest_missing": {
        "en": "the manifest is missing or damaged",
        "pl": "brak manifestu albo manifest jest uszkodzony",
    },
    "integrity.schema_unknown": {
        "en": "unknown manifest version",
        "pl": "nieznana wersja manifestu",
    },
    "integrity.catalog_mismatch": {
        "en": "the signed manifest does not match the catalogue entry",
        "pl": "podpisany manifest nie zgadza się z wpisem w katalogu",
    },
    "integrity.no_public_key": {
        "en": "the server has no public key configured",
        "pl": "serwer nie ma skonfigurowanego klucza publicznego",
    },
    "integrity.key_mismatch": {
        "en": "the manifest was signed with a key the server no longer uses",
        "pl": "manifest podpisany innym kluczem niż aktualny",
    },
    "integrity.signature_missing": {
        "en": "no signature",
        "pl": "brak podpisu",
    },
    "integrity.signature_invalid": {
        "en": "the Ed25519 signature is invalid",
        "pl": "podpis Ed25519 jest nieprawidłowy",
    },
    "integrity.disk_mismatch": {
        "en": "the file on disk does not match its signature: {reason}",
        "pl": "plik na dysku nie zgadza się z podpisem: {reason}",
    },

    # --- Storage -------------------------------------------------------------
    "storage.missing": {
        "en": "the file is not on disk",
        "pl": "plik nie istnieje na dysku",
    },
    "storage.hash_mismatch": {
        "en": "SHA-256 mismatch (on disk {actual}, expected {expected})",
        "pl": "SHA-256 się nie zgadza (na dysku {actual}, oczekiwano {expected})",
    },
    "storage.path_outside": {
        "en": "path points outside the storage directory: {path}",
        "pl": "ścieżka poza katalogiem magazynu: {path}",
    },
}


def resolve_lang(request: Any) -> str:
    """Pick a language for this request. Never raises."""
    if request is None:
        return DEFAULT_LANG

    cookie = request.cookies.get(LANG_COOKIE)
    if cookie in SUPPORTED:
        return cookie

    header = request.headers.get("accept-language", "")
    for part in header.split(","):
        code = part.split(";")[0].strip().lower()[:2]
        if code in SUPPORTED:
            return code
    return DEFAULT_LANG


def t(key: str, lang: Optional[str] = None, **params: Any) -> str:
    """Translate `key`, filling in `{placeholders}`.

    An unknown key returns the key itself rather than raising - a missing
    translation should never turn into a 500.
    """
    entry = CATALOG.get(key)
    if entry is None:
        return key
    template = entry.get(lang or DEFAULT_LANG) or entry["en"]
    if not params:
        return template
    try:
        return template.format(**params)
    except (KeyError, IndexError):
        return template
