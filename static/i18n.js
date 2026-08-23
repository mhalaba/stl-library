/* Interface translations.

   English is the default. The chosen language is stored in localStorage and
   mirrored into the `stl_lang` cookie, so the API can return its own messages
   in the same language (see app/messages.py). */

(function () {
  "use strict";

  var SUPPORTED = ["en", "pl"];
  var COOKIE = "stl_lang";

  var DICT = {
    en: {
      "brand": "STL Library",
      "title.catalogue": "STL Library",
      "title.admin": "Administrator panel — STL Library",
      "search.placeholder": "Search models…",

      "nav.panel": "panel",
      "nav.catalogue": "catalogue",
      "auth.signIn": "Sign in",
      "auth.signOut": "Sign out",
      "auth.createAccount": "Create account",
      "auth.email": "E-mail",
      "auth.password": "Password",
      "auth.passwordNew": "Password (min. 10 characters)",
      "auth.cancel": "Cancel",
      "auth.noAccount": "I don't have an account yet",
      "auth.haveAccount": "I already have an account",
      "auth.modalHint": "Only signed-in users can download files — that way every download link is personal and expires.",

      "catalogue.notice.strong": "Every file in this library is signed with an Ed25519 key. ",
      "catalogue.notice.rest": "On download the server re-hashes it and checks the signature, and your browser verifies the digest once more before the file reaches your disk. A file that fails either check is not released.",
      "catalogue.empty": "No models to show.",
      "catalogue.signedCount": "{ready} / {total} signed",
      "catalogue.back": "← catalogue",

      "model.meta": "{category} · {license} · added {date}",
      "model.files": "Files",
      "model.description": "Description",
      "model.noFiles": "This model has no files yet.",
      "model.fileFacts": "{size} · {triangles} triangles · added {date}",

      "file.signed": "signed",
      "file.quarantined": "quarantined",
      "file.pending": "awaiting signature",
      "file.key": "key {id}",
      "file.download": "Download",
      "file.preview": "Preview",
      "file.checkSignature": "Check signature",

      "status.downloading": "Downloading…",
      "status.hashing": "Checking the digest…",
      "status.noWebCrypto": "This browser exposes no WebCrypto — skipping the client-side check.",
      "status.digestMismatch": "Digest mismatch ({actual} instead of {expected}). File rejected.",
      "status.downloadOk": "Downloaded and verified. The .sig.json file came along for offline checking.",
      "status.rendered": "Verified and rendered ({triangles} triangles). Drag to rotate, scroll to zoom.",
      "status.serverChecking": "The server is re-hashing the file…",
      "status.signatureOk": "Signature valid, the file on the server is untouched (key {id}).",
      "status.verifyFailed": "Verification failed: {reason}",
      "status.noWebGL": "This browser does not support WebGL.",
      "status.refused": "The server refused to release the file",
      "viewer.hint": "Pick a file and press “Preview” to look at the model.",
      "viewer.parseFailed": "Could not read the geometry",

      "error.generic": "Error {status}",

      "admin.heading": "Administrator panel",
      "admin.signInFirst": "← go back to the catalogue and sign in as an administrator",
      "admin.mode": "Signing mode: {mode}. ",
      "admin.modeOnline": "The private key sits on the server — convenient, but a break-in would let an attacker sign a swapped file. For production switch to offline mode (README, “Offline mode”).",
      "admin.modeOffline": "The private key is off the server. Uploaded files stay “pending” until you sign them with tools/sign_pending.py.",
      "admin.activeKey": "Active key: {id}",
      "admin.stat.users": "users",
      "admin.stat.models": "models",
      "admin.stat.signed": "files signed",
      "admin.stat.pending": "awaiting signature",
      "admin.stat.quarantined": "quarantined",
      "admin.stat.downloads": "downloads / 24h",

      "admin.newModel": "New model",
      "admin.field.title": "Title",
      "admin.field.description": "Description",
      "admin.field.category": "Category",
      "admin.field.license": "Licence",
      "admin.placeholder.title": "e.g. Headphone hook",
      "admin.placeholder.category": "e.g. accessories",
      "admin.placeholder.description": "Short description, print settings, suggested material…",
      "admin.createModel": "Create model",
      "admin.saving": "Saving…",
      "admin.modelCreated": "Model created at /model/{slug}",

      "admin.upload": "Upload an STL file",
      "admin.field.model": "Model",
      "admin.field.file": "File .stl",
      "admin.uploadButton": "Upload and hash",
      "admin.pickBoth": "Pick a model and a file.",
      "admin.uploading": "Uploading…",
      "admin.uploaded": "Uploaded. SHA-256: {sha} · triangles: {triangles} · status: {status}",
      "admin.uploadedDedup": " · this content was already in the library",

      "admin.audit": "Integrity audit",
      "admin.auditHint": "Re-hashes every file on disk and verifies its signature. Anything that does not match is quarantined and disappears from the catalogue.",
      "admin.auditRun": "Check the whole library",
      "admin.auditWorking": "Re-hashing…",
      "admin.auditClean": "Checked {checked} files — everything matches.",
      "admin.auditProblems": "Checked {checked} files, problems: {problems}",
      "admin.table.file": "File",
      "admin.table.reason": "Reason",

      "admin.log": "Event log",
      "admin.table.when": "When",
      "admin.table.event": "Event",
      "admin.table.details": "Details"
    },

    pl: {
      "brand": "Biblioteka STL",
      "title.catalogue": "Biblioteka STL",
      "title.admin": "Panel administratora — Biblioteka STL",
      "search.placeholder": "Szukaj modelu…",

      "nav.panel": "panel",
      "nav.catalogue": "katalog",
      "auth.signIn": "Zaloguj się",
      "auth.signOut": "Wyloguj",
      "auth.createAccount": "Załóż konto",
      "auth.email": "E-mail",
      "auth.password": "Hasło",
      "auth.passwordNew": "Hasło (min. 10 znaków)",
      "auth.cancel": "Anuluj",
      "auth.noAccount": "Nie mam jeszcze konta",
      "auth.haveAccount": "Mam już konto",
      "auth.modalHint": "Pliki pobierają wyłącznie zalogowani użytkownicy — dzięki temu każdy link do pobrania jest imienny i wygasa.",

      "catalogue.notice.strong": "Każdy plik w tej bibliotece jest podpisany kluczem Ed25519. ",
      "catalogue.notice.rest": "Przy pobieraniu serwer przelicza jego SHA-256 i sprawdza podpis, a Twoja przeglądarka weryfikuje hash jeszcze raz, zanim plik trafi na dysk. Plik, który nie przejdzie kontroli, nie zostanie wydany.",
      "catalogue.empty": "Brak modeli do pokazania.",
      "catalogue.signedCount": "{ready} / {total} podpisanych",
      "catalogue.back": "← katalog",

      "model.meta": "{category} · {license} · dodano {date}",
      "model.files": "Pliki",
      "model.description": "Opis",
      "model.noFiles": "Ten model nie ma jeszcze plików.",
      "model.fileFacts": "{size} · {triangles} trójkątów · dodano {date}",

      "file.signed": "podpisany",
      "file.quarantined": "kwarantanna",
      "file.pending": "czeka na podpis",
      "file.key": "klucz {id}",
      "file.download": "Pobierz",
      "file.preview": "Podgląd",
      "file.checkSignature": "Sprawdź podpis",

      "status.downloading": "Pobieranie…",
      "status.hashing": "Sprawdzanie sumy kontrolnej…",
      "status.noWebCrypto": "Przeglądarka nie udostępnia WebCrypto — pomijam kontrolę po stronie klienta.",
      "status.digestMismatch": "Suma kontrolna się nie zgadza ({actual} zamiast {expected}). Plik odrzucony.",
      "status.downloadOk": "Pobrano i zweryfikowano. Dorzuciłem plik .sig.json do sprawdzenia offline.",
      "status.rendered": "Zweryfikowano i wyświetlono ({triangles} trójkątów). Obracaj myszą, przybliżaj kółkiem.",
      "status.serverChecking": "Serwer przelicza plik…",
      "status.signatureOk": "Podpis poprawny, plik na serwerze nietknięty (klucz {id}).",
      "status.verifyFailed": "Weryfikacja nie przeszła: {reason}",
      "status.noWebGL": "Ta przeglądarka nie obsługuje WebGL.",
      "status.refused": "Serwer odmówił wydania pliku",
      "viewer.hint": "Wybierz plik i kliknij „Podgląd”, żeby obejrzeć model.",
      "viewer.parseFailed": "Nie udało się odczytać geometrii",

      "error.generic": "Błąd {status}",

      "admin.heading": "Panel administratora",
      "admin.signInFirst": "← wróć do katalogu i zaloguj się jako administrator",
      "admin.mode": "Tryb podpisywania: {mode}. ",
      "admin.modeOnline": "Klucz prywatny leży na serwerze — wygodne, ale włamanie pozwoliłoby podpisać podmieniony plik. Do produkcji przełącz się na tryb offline (README, sekcja „Tryb offline”).",
      "admin.modeOffline": "Klucz prywatny jest poza serwerem. Wgrane pliki czekają w stanie „pending”, dopóki nie podpiszesz ich narzędziem tools/sign_pending.py.",
      "admin.activeKey": "Aktywny klucz: {id}",
      "admin.stat.users": "użytkowników",
      "admin.stat.models": "modeli",
      "admin.stat.signed": "plików podpisanych",
      "admin.stat.pending": "czeka na podpis",
      "admin.stat.quarantined": "w kwarantannie",
      "admin.stat.downloads": "pobrań / 24h",

      "admin.newModel": "Nowy model",
      "admin.field.title": "Tytuł",
      "admin.field.description": "Opis",
      "admin.field.category": "Kategoria",
      "admin.field.license": "Licencja",
      "admin.placeholder.title": "np. Uchwyt na słuchawki",
      "admin.placeholder.category": "np. akcesoria",
      "admin.placeholder.description": "Krótki opis, parametry druku, zalecany materiał…",
      "admin.createModel": "Utwórz model",
      "admin.saving": "Zapisywanie…",
      "admin.modelCreated": "Utworzono model o adresie /model/{slug}",

      "admin.upload": "Wgraj plik STL",
      "admin.field.model": "Model",
      "admin.field.file": "Plik .stl",
      "admin.uploadButton": "Wgraj i policz sumę kontrolną",
      "admin.pickBoth": "Wybierz model i plik.",
      "admin.uploading": "Wysyłanie…",
      "admin.uploaded": "Wgrano. SHA-256: {sha} · trójkątów: {triangles} · status: {status}",
      "admin.uploadedDedup": " · ta sama treść była już w bibliotece",

      "admin.audit": "Audyt integralności",
      "admin.auditHint": "Przelicza SHA-256 każdego pliku na dysku i sprawdza jego podpis. Cokolwiek się nie zgadza, trafia do kwarantanny i znika z katalogu.",
      "admin.auditRun": "Sprawdź całą bibliotekę",
      "admin.auditWorking": "Przeliczanie…",
      "admin.auditClean": "Sprawdzono {checked} plików — wszystko się zgadza.",
      "admin.auditProblems": "Sprawdzono {checked} plików, problemów: {problems}",
      "admin.table.file": "Plik",
      "admin.table.reason": "Powód",

      "admin.log": "Dziennik zdarzeń",
      "admin.table.when": "Kiedy",
      "admin.table.event": "Zdarzenie",
      "admin.table.details": "Szczegóły"
    }
  };

  function detect() {
    var stored = null;
    try {
      stored = window.localStorage.getItem(COOKIE);
    } catch (err) {
      stored = null;
    }
    if (SUPPORTED.indexOf(stored) >= 0) return stored;

    var match = document.cookie.match(/(?:^|;\s*)stl_lang=([^;]+)/);
    if (match && SUPPORTED.indexOf(match[1]) >= 0) return match[1];

    var navLang = (navigator.language || "en").slice(0, 2).toLowerCase();
    return SUPPORTED.indexOf(navLang) >= 0 ? navLang : "en";
  }

  var current = detect();

  /* Mirror the choice into a cookie so the API answers in the same language. */
  function persist(code) {
    document.cookie = COOKIE + "=" + code + ";path=/;max-age=31536000;samesite=lax";
    try {
      window.localStorage.setItem(COOKIE, code);
    } catch (err) {
      /* private mode - the cookie alone will do */
    }
  }

  persist(current);
  document.documentElement.lang = current;

  function t(key, params) {
    var table = DICT[current] || DICT.en;
    var text = table[key];
    if (text === undefined) text = DICT.en[key];
    if (text === undefined) return key;
    if (!params) return text;
    return text.replace(/\{(\w+)\}/g, function (whole, name) {
      return Object.prototype.hasOwnProperty.call(params, name) ? params[name] : whole;
    });
  }

  /* Fill in elements marked up in the HTML: data-i18n for text content,
     data-i18n-placeholder / data-i18n-title for those attributes. */
  function applyStatic(root) {
    var scope = root || document;
    scope.querySelectorAll("[data-i18n]").forEach(function (node) {
      node.textContent = t(node.getAttribute("data-i18n"));
    });
    scope.querySelectorAll("[data-i18n-placeholder]").forEach(function (node) {
      node.setAttribute("placeholder", t(node.getAttribute("data-i18n-placeholder")));
    });
    var titled = scope.querySelector("title[data-i18n-title]");
    if (titled) document.title = t(titled.getAttribute("data-i18n-title"));
  }

  function setLang(code) {
    if (SUPPORTED.indexOf(code) < 0 || code === current) return;
    persist(code);
    window.location.reload();
  }

  /* The switcher itself: one button per language, current one disabled. */
  function switcher() {
    var wrap = document.createElement("span");
    wrap.className = "lang-switch";
    SUPPORTED.forEach(function (code) {
      var button = document.createElement("button");
      button.type = "button";
      button.textContent = code.toUpperCase();
      button.className = code === current ? "lang-active" : "";
      button.setAttribute("aria-label", code === "en" ? "English" : "Polski");
      if (code === current) button.setAttribute("aria-current", "true");
      button.addEventListener("click", function () { setLang(code); });
      wrap.appendChild(button);
    });
    return wrap;
  }

  window.I18N = {
    t: t,
    lang: function () { return current; },
    setLang: setLang,
    applyStatic: applyStatic,
    switcher: switcher,
    SUPPORTED: SUPPORTED
  };
})();
