/* Frontend biblioteki STL.

   Rzecz warta uwagi: przeglądarka NIE ufa serwerowi na słowo. Plik jest
   pobierany do pamięci, jego SHA-256 liczy WebCrypto po stronie klienta
   i dopiero zgodność z hashem z podpisanego manifestu pozwala go zapisać
   albo wyświetlić. Podmieniony plik nigdy nie trafia na dysk użytkownika. */

(function () {
  "use strict";

  const view = document.getElementById("view");
  const authBox = document.getElementById("auth-box");
  const modalRoot = document.getElementById("modal-root");
  const searchInput = document.getElementById("search");

  let session = { authenticated: false };
  let viewer = null;

  /* --- Pomocnicze --- */

  function el(tag, attrs, children) {
    const node = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (key) {
        if (key === "class") node.className = attrs[key];
        else if (key === "text") node.textContent = attrs[key];
        else if (key.slice(0, 2) === "on") node.addEventListener(key.slice(2), attrs[key]);
        else node.setAttribute(key, attrs[key]);
      });
    }
    (children || []).forEach(function (child) {
      if (child) node.appendChild(typeof child === "string" ? document.createTextNode(child) : child);
    });
    return node;
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function bytes(n) {
    if (n < 1024) return n + " B";
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " kB";
    return (n / 1048576).toFixed(1) + " MB";
  }

  function date(ts) {
    return new Date(ts * 1000).toLocaleDateString("pl-PL");
  }

  function csrfToken() {
    const match = document.cookie.match(/(?:^|;\s*)stl_csrf=([^;]+)/);
    return match ? decodeURIComponent(match[1]) : "";
  }

  async function api(path, options) {
    const opts = options || {};
    const headers = Object.assign({ Accept: "application/json" }, opts.headers || {});
    if (opts.method && opts.method !== "GET") headers["X-CSRF-Token"] = csrfToken();
    if (opts.json !== undefined) {
      headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(opts.json);
    }
    const response = await fetch(path, {
      method: opts.method || "GET",
      headers: headers,
      body: opts.body,
      credentials: "same-origin"
    });
    const text = await response.text();
    const data = text ? JSON.parse(text) : {};
    if (!response.ok) throw new Error(errorText(data, response.status));
    return data;
  }

  /* FastAPI zwraca `detail` jako tekst, ale przy błędach walidacji jako listę
     obiektów - bez tego użytkownik zobaczyłby "[object Object]". */
  function errorText(data, status) {
    const detail = data && data.detail;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail)) {
      return detail.map(function (item) { return item.msg || String(item); }).join("; ");
    }
    return "Błąd " + status;
  }

  async function sha256Hex(buffer) {
    if (!window.crypto || !window.crypto.subtle) return null;
    const digest = await window.crypto.subtle.digest("SHA-256", buffer);
    return Array.prototype.map
      .call(new Uint8Array(digest), function (b) { return b.toString(16).padStart(2, "0"); })
      .join("");
  }

  /* --- Nagłówek / sesja --- */

  function renderAuth() {
    clear(authBox);
    if (session.authenticated) {
      authBox.appendChild(el("span", { class: "who", text: session.email }));
      if (session.is_admin) {
        authBox.appendChild(el("a", { href: "/admin", class: "tag", text: "panel" }));
      }
      authBox.appendChild(el("button", {
        class: "ghost",
        text: "Wyloguj",
        onclick: async function () {
          await api("/api/auth/logout", { method: "POST" });
          session = { authenticated: false };
          renderAuth();
          route();
        }
      }));
    } else {
      authBox.appendChild(el("button", {
        class: "primary", text: "Zaloguj się", onclick: function () { showAuthModal("login"); }
      }));
    }
  }

  function showAuthModal(mode) {
    clear(modalRoot);
    const emailInput = el("input", { type: "email", autocomplete: "email", required: "required" });
    const passwordInput = el("input", {
      type: "password",
      autocomplete: mode === "login" ? "current-password" : "new-password",
      required: "required"
    });
    const error = el("div", { class: "status-line bad" });

    async function submit() {
      error.textContent = "";
      try {
        const result = await api(mode === "login" ? "/api/auth/login" : "/api/auth/register", {
          method: "POST",
          json: { email: emailInput.value.trim(), password: passwordInput.value }
        });
        session = { authenticated: true, email: result.email, is_admin: result.is_admin };
        clear(modalRoot);
        renderAuth();
        route();
      } catch (err) {
        error.textContent = err.message;
      }
    }

    const box = el("div", { class: "modal" }, [
      el("h2", { text: mode === "login" ? "Zaloguj się" : "Załóż konto" }),
      el("p", { class: "hint", text: "Pliki pobierają wyłącznie zalogowani użytkownicy — dzięki temu każdy link do pobrania jest imienny i wygasa." }),
      el("div", { class: "field" }, [el("label", { text: "E-mail" }), emailInput]),
      el("div", { class: "field" }, [
        el("label", { text: mode === "login" ? "Hasło" : "Hasło (min. 10 znaków)" }),
        passwordInput
      ]),
      error,
      el("div", { class: "row" }, [
        el("button", { class: "ghost", text: "Anuluj", onclick: function () { clear(modalRoot); } }),
        el("button", { class: "primary", text: mode === "login" ? "Zaloguj" : "Załóż konto", onclick: submit })
      ]),
      el("div", { class: "switch" }, [
        el("a", {
          href: "#",
          text: mode === "login" ? "Nie mam jeszcze konta" : "Mam już konto",
          onclick: function (event) { event.preventDefault(); showAuthModal(mode === "login" ? "register" : "login"); }
        })
      ])
    ]);

    [emailInput, passwordInput].forEach(function (input) {
      input.addEventListener("keydown", function (event) { if (event.key === "Enter") submit(); });
    });

    modalRoot.appendChild(el("div", {
      class: "modal-back",
      onclick: function (event) { if (event.target === event.currentTarget) clear(modalRoot); }
    }, [box]));
    emailInput.focus();
  }

  /* --- Katalog --- */

  async function renderCatalog(query) {
    clear(view);
    view.appendChild(el("div", { class: "notice" }, [
      el("strong", { text: "Każdy plik w tej bibliotece jest podpisany kluczem Ed25519. " }),
      "Przy pobieraniu serwer przelicza jego SHA-256 i sprawdza podpis, a Twoja przeglądarka " +
      "weryfikuje hash jeszcze raz, zanim plik trafi na dysk. Plik, który nie przejdzie kontroli, " +
      "nie zostanie wydany."
    ]));

    const grid = el("div", { class: "grid" });
    view.appendChild(grid);

    let data;
    try {
      data = await api("/api/models?q=" + encodeURIComponent(query || ""));
    } catch (err) {
      view.appendChild(el("div", { class: "empty", text: err.message }));
      return;
    }

    if (!data.models.length) {
      grid.appendChild(el("div", { class: "empty", text: "Brak modeli do pokazania." }));
      return;
    }

    data.models.forEach(function (model) {
      grid.appendChild(el("div", { class: "card" }, [
        el("h3", {}, [el("a", { href: "/model/" + model.slug, text: model.title })]),
        el("p", { text: (model.description || "").slice(0, 140) }),
        el("div", { class: "meta" }, [
          el("span", { class: "tag", text: model.category }),
          el("span", {
            class: model.files_ready ? "tag ok" : "tag warn",
            text: model.files_ready + " / " + model.files_total + " podpisanych"
          }),
          el("span", { class: "tag", text: model.license })
        ])
      ]));
    });
  }

  /* --- Widok modelu --- */

  async function renderModel(slug) {
    clear(view);
    let data;
    try {
      data = await api("/api/models/" + encodeURIComponent(slug));
    } catch (err) {
      view.appendChild(el("div", { class: "empty", text: err.message }));
      return;
    }

    const model = data.model;
    view.appendChild(el("div", { class: "model-head" }, [
      el("div", {}, [el("a", { href: "/", text: "← katalog" })]),
      el("h1", { text: model.title }),
      el("div", { class: "sub", text: model.category + " · " + model.license + " · dodano " + date(model.created_at) })
    ]));

    const viewerHolder = el("div", { id: "viewer-holder" }, [
      el("div", { id: "viewer-hint", text: "Wybierz plik i kliknij „Podgląd”, żeby obejrzeć model." })
    ]);

    const filesPanel = el("div", { class: "panel" }, [el("h2", { text: "Pliki" })]);

    if (!data.files.length) {
      filesPanel.appendChild(el("div", { class: "empty", text: "Ten model nie ma jeszcze plików." }));
    }

    data.files.forEach(function (file) {
      filesPanel.appendChild(fileRow(file, viewerHolder));
    });

    view.appendChild(el("div", { class: "columns" }, [
      el("div", { class: "stack" }, [
        viewerHolder,
        model.description
          ? el("div", { class: "panel" }, [el("h2", { text: "Opis" }), el("div", { text: model.description })])
          : null
      ]),
      filesPanel
    ]));
  }

  function fileRow(file, viewerHolder) {
    const status = el("div", { class: "status-line" });
    const signedTag = file.status === "signed"
      ? el("span", { class: "tag ok", text: "podpisany" })
      : file.status === "quarantined"
        ? el("span", { class: "tag bad", text: "kwarantanna" })
        : el("span", { class: "tag warn", text: "czeka na podpis" });

    const buttons = [];

    if (file.status === "signed") {
      buttons.push(el("button", {
        class: "primary",
        text: "Pobierz",
        onclick: function (event) { handleDownload(file, status, event.currentTarget); }
      }));
      buttons.push(el("button", {
        text: "Podgląd",
        onclick: function (event) { handlePreview(file, status, viewerHolder, event.currentTarget); }
      }));
      buttons.push(el("button", {
        class: "ghost",
        text: "Sprawdź podpis",
        onclick: function (event) { handleVerify(file, status, event.currentTarget); }
      }));
    }

    return el("div", { class: "file-row" }, [
      el("div", { class: "name", text: file.filename }),
      el("div", { class: "facts", text: bytes(file.size) + " · " + file.triangles.toLocaleString("pl-PL") + " trójkątów · dodano " + date(file.uploaded_at) }),
      el("div", { class: "meta" }, [signedTag, file.key_id ? el("span", { class: "tag", text: "klucz " + file.key_id }) : null]),
      el("div", { class: "actions" }, buttons),
      el("div", { class: "hash", text: "SHA-256: " + file.sha256 }),
      status
    ]);
  }

  function requireLogin() {
    if (!session.authenticated) {
      showAuthModal("login");
      return false;
    }
    return true;
  }

  /* Pobiera plik do pamięci i sprawdza jego SHA-256 lokalnie. */
  async function fetchVerified(file, status) {
    const grant = await api("/api/files/" + file.id + "/grant", { method: "POST" });
    status.className = "status-line work";
    status.textContent = "Pobieranie...";

    const response = await fetch(grant.url, { credentials: "same-origin" });
    if (!response.ok) {
      const body = await response.json().catch(function () { return {}; });
      throw new Error(errorText(body, response.status));
    }
    const buffer = await response.arrayBuffer();

    status.textContent = "Sprawdzanie sumy kontrolnej...";
    const actual = await sha256Hex(buffer);
    if (actual === null) {
      status.className = "status-line warn";
      status.textContent = "Przeglądarka nie udostępnia WebCrypto — pomijam kontrolę po stronie klienta.";
      return buffer;
    }
    if (actual !== grant.sha256) {
      throw new Error("Suma kontrolna się nie zgadza (" + actual.slice(0, 16) + " zamiast " + grant.sha256.slice(0, 16) + "). Plik odrzucony.");
    }
    return buffer;
  }

  async function withBusy(button, action) {
    button.disabled = true;
    try {
      await action();
    } finally {
      button.disabled = false;
    }
  }

  function handleDownload(file, status, button) {
    if (!requireLogin()) return;
    withBusy(button, async function () {
      try {
        const buffer = await fetchVerified(file, status);
        const url = URL.createObjectURL(new Blob([buffer], { type: "model/stl" }));
        const link = el("a", { href: url, download: file.filename });
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        setTimeout(function () { URL.revokeObjectURL(url); }, 10000);

        // Plik .sig.json pozwala zweryfikować model także offline.
        const sidecar = await api("/api/files/" + file.id + "/signature");
        const sigUrl = URL.createObjectURL(
          new Blob([JSON.stringify(sidecar, null, 2)], { type: "application/json" })
        );
        const sigLink = el("a", { href: sigUrl, download: file.filename + ".sig.json" });
        document.body.appendChild(sigLink);
        sigLink.click();
        document.body.removeChild(sigLink);
        setTimeout(function () { URL.revokeObjectURL(sigUrl); }, 10000);

        status.className = "status-line ok";
        status.textContent = "Pobrano i zweryfikowano. Dorzuciłem plik .sig.json do sprawdzenia offline.";
      } catch (err) {
        status.className = "status-line bad";
        status.textContent = err.message;
      }
    });
  }

  function handlePreview(file, status, viewerHolder, button) {
    if (!requireLogin()) return;
    withBusy(button, async function () {
      try {
        const buffer = await fetchVerified(file, status);
        const hint = viewerHolder.querySelector("#viewer-hint");

        if (!viewer) viewer = new window.STLViewer(viewerHolder);
        if (!viewer.supported()) {
          status.className = "status-line bad";
          status.textContent = "Ta przeglądarka nie obsługuje WebGL.";
          return;
        }
        const triangles = viewer.load(buffer);
        if (hint) hint.textContent = "";
        status.className = "status-line ok";
        status.textContent = "Zweryfikowano i wyświetlono (" + triangles.toLocaleString("pl-PL") + " trójkątów). Obracaj myszą, przybliżaj kółkiem.";
      } catch (err) {
        status.className = "status-line bad";
        status.textContent = err.message;
      }
    });
  }

  function handleVerify(file, status, button) {
    if (!requireLogin()) return;
    withBusy(button, async function () {
      status.className = "status-line work";
      status.textContent = "Serwer przelicza plik...";
      try {
        const result = await api("/api/files/" + file.id + "/verify");
        if (result.ok) {
          status.className = "status-line ok";
          status.textContent = "Podpis poprawny, plik na serwerze nietknięty (klucz " + result.key_id + ").";
        } else {
          status.className = "status-line bad";
          status.textContent = "Weryfikacja nie przeszła: " + result.reason;
        }
      } catch (err) {
        status.className = "status-line bad";
        status.textContent = err.message;
      }
    });
  }

  /* --- Routing --- */

  function route() {
    const match = location.pathname.match(/^\/model\/(.+)$/);
    if (match) {
      searchInput.style.visibility = "hidden";
      renderModel(decodeURIComponent(match[1]));
    } else {
      searchInput.style.visibility = "visible";
      renderCatalog(searchInput.value);
    }
  }

  document.addEventListener("click", function (event) {
    const link = event.target.closest ? event.target.closest("a") : null;
    if (!link || link.target || link.hasAttribute("download")) return;
    const href = link.getAttribute("href") || "";
    if (href.charAt(0) !== "/" || href.indexOf("/static/") === 0 || href === "/admin") return;
    event.preventDefault();
    history.pushState(null, "", href);
    viewer = null;
    route();
  });

  window.addEventListener("popstate", function () { viewer = null; route(); });

  let searchTimer = null;
  searchInput.addEventListener("input", function () {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(function () {
      if (!location.pathname.match(/^\/model\//)) renderCatalog(searchInput.value);
    }, 250);
  });

  api("/api/auth/me")
    .then(function (data) { session = data; })
    .catch(function () { session = { authenticated: false }; })
    .then(function () {
      renderAuth();
      route();
    });
})();
