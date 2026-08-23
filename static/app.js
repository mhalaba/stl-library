/* Catalogue frontend.

   Worth noting: the browser does NOT take the server's word for it. A file is
   fetched into memory, WebCrypto computes its SHA-256 on the client, and only
   a match against the digest from the signed manifest lets it be saved or
   rendered. A swapped file never reaches the user's disk. */

(function () {
  "use strict";

  var t = window.I18N.t;
  var LOCALE = window.I18N.lang() === "pl" ? "pl-PL" : "en-GB";

  var view = document.getElementById("view");
  var authBox = document.getElementById("auth-box");
  var modalRoot = document.getElementById("modal-root");
  var searchInput = document.getElementById("search");

  var session = { authenticated: false };
  var viewer = null;

  /* --- Helpers --- */

  function el(tag, attrs, children) {
    var node = document.createElement(tag);
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
    return new Date(ts * 1000).toLocaleDateString(LOCALE);
  }

  function num(n) {
    return n.toLocaleString(LOCALE);
  }

  function csrfToken() {
    var match = document.cookie.match(/(?:^|;\s*)stl_csrf=([^;]+)/);
    return match ? decodeURIComponent(match[1]) : "";
  }

  async function api(path, options) {
    var opts = options || {};
    var headers = Object.assign({ Accept: "application/json" }, opts.headers || {});
    if (opts.method && opts.method !== "GET") headers["X-CSRF-Token"] = csrfToken();
    if (opts.json !== undefined) {
      headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(opts.json);
    }
    var response = await fetch(path, {
      method: opts.method || "GET",
      headers: headers,
      body: opts.body,
      credentials: "same-origin"
    });
    var text = await response.text();
    var data = text ? JSON.parse(text) : {};
    if (!response.ok) throw new Error(errorText(data, response.status));
    return data;
  }

  /* FastAPI returns `detail` as a string, but as a list of objects for
     validation errors - without this the user would see "[object Object]". */
  function errorText(data, status) {
    var detail = data && data.detail;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail)) {
      return detail.map(function (item) { return item.msg || String(item); }).join("; ");
    }
    return t("error.generic", { status: status });
  }

  async function sha256Hex(buffer) {
    if (!window.crypto || !window.crypto.subtle) return null;
    var digest = await window.crypto.subtle.digest("SHA-256", buffer);
    return Array.prototype.map
      .call(new Uint8Array(digest), function (b) { return b.toString(16).padStart(2, "0"); })
      .join("");
  }

  /* --- Header and session --- */

  function renderAuth() {
    clear(authBox);
    authBox.appendChild(window.I18N.switcher());

    if (session.authenticated) {
      authBox.appendChild(el("span", { class: "who", text: session.email }));
      if (session.is_admin) {
        authBox.appendChild(el("a", { href: "/admin", class: "tag", text: t("nav.panel") }));
      }
      authBox.appendChild(el("button", {
        class: "ghost",
        text: t("auth.signOut"),
        onclick: async function () {
          await api("/api/auth/logout", { method: "POST" });
          session = { authenticated: false };
          renderAuth();
          route();
        }
      }));
    } else {
      authBox.appendChild(el("button", {
        class: "primary", text: t("auth.signIn"), onclick: function () { showAuthModal("login"); }
      }));
    }
  }

  function showAuthModal(mode) {
    clear(modalRoot);
    var emailInput = el("input", { type: "email", autocomplete: "email", required: "required" });
    var passwordInput = el("input", {
      type: "password",
      autocomplete: mode === "login" ? "current-password" : "new-password",
      required: "required"
    });
    var error = el("div", { class: "status-line bad" });

    async function submit() {
      error.textContent = "";
      try {
        var result = await api(mode === "login" ? "/api/auth/login" : "/api/auth/register", {
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

    var box = el("div", { class: "modal" }, [
      el("h2", { text: mode === "login" ? t("auth.signIn") : t("auth.createAccount") }),
      el("p", { class: "hint", text: t("auth.modalHint") }),
      el("div", { class: "field" }, [el("label", { text: t("auth.email") }), emailInput]),
      el("div", { class: "field" }, [
        el("label", { text: mode === "login" ? t("auth.password") : t("auth.passwordNew") }),
        passwordInput
      ]),
      error,
      el("div", { class: "row" }, [
        el("button", { class: "ghost", text: t("auth.cancel"), onclick: function () { clear(modalRoot); } }),
        el("button", {
          class: "primary",
          text: mode === "login" ? t("auth.signIn") : t("auth.createAccount"),
          onclick: submit
        })
      ]),
      el("div", { class: "switch" }, [
        el("a", {
          href: "#",
          text: mode === "login" ? t("auth.noAccount") : t("auth.haveAccount"),
          onclick: function (event) {
            event.preventDefault();
            showAuthModal(mode === "login" ? "register" : "login");
          }
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

  /* --- Catalogue --- */

  async function renderCatalog(query) {
    clear(view);
    view.appendChild(el("div", { class: "notice" }, [
      el("strong", { text: t("catalogue.notice.strong") }),
      t("catalogue.notice.rest")
    ]));

    var grid = el("div", { class: "grid" });
    view.appendChild(grid);

    var data;
    try {
      data = await api("/api/models?q=" + encodeURIComponent(query || ""));
    } catch (err) {
      view.appendChild(el("div", { class: "empty", text: err.message }));
      return;
    }

    if (!data.models.length) {
      grid.appendChild(el("div", { class: "empty", text: t("catalogue.empty") }));
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
            text: t("catalogue.signedCount", { ready: model.files_ready, total: model.files_total })
          }),
          el("span", { class: "tag", text: model.license })
        ])
      ]));
    });
  }

  /* --- Model view --- */

  async function renderModel(slug) {
    clear(view);
    var data;
    try {
      data = await api("/api/models/" + encodeURIComponent(slug));
    } catch (err) {
      view.appendChild(el("div", { class: "empty", text: err.message }));
      return;
    }

    var model = data.model;
    view.appendChild(el("div", { class: "model-head" }, [
      el("div", {}, [el("a", { href: "/", text: t("catalogue.back") })]),
      el("h1", { text: model.title }),
      el("div", {
        class: "sub",
        text: t("model.meta", {
          category: model.category,
          license: model.license,
          date: date(model.created_at)
        })
      })
    ]));

    var viewerHolder = el("div", { id: "viewer-holder" }, [
      el("div", { id: "viewer-hint", text: t("viewer.hint") })
    ]);

    var filesPanel = el("div", { class: "panel" }, [el("h2", { text: t("model.files") })]);

    if (!data.files.length) {
      filesPanel.appendChild(el("div", { class: "empty", text: t("model.noFiles") }));
    }

    data.files.forEach(function (file) {
      filesPanel.appendChild(fileRow(file, viewerHolder));
    });

    view.appendChild(el("div", { class: "columns" }, [
      el("div", { class: "stack" }, [
        viewerHolder,
        model.description
          ? el("div", { class: "panel" }, [
              el("h2", { text: t("model.description") }),
              el("div", { text: model.description })
            ])
          : null
      ]),
      filesPanel
    ]));
  }

  function fileRow(file, viewerHolder) {
    var status = el("div", { class: "status-line" });
    var signedTag = file.status === "signed"
      ? el("span", { class: "tag ok", text: t("file.signed") })
      : file.status === "quarantined"
        ? el("span", { class: "tag bad", text: t("file.quarantined") })
        : el("span", { class: "tag warn", text: t("file.pending") });

    var buttons = [];

    if (file.status === "signed") {
      buttons.push(el("button", {
        class: "primary",
        text: t("file.download"),
        onclick: function (event) { handleDownload(file, status, event.currentTarget); }
      }));
      buttons.push(el("button", {
        text: t("file.preview"),
        onclick: function (event) { handlePreview(file, status, viewerHolder, event.currentTarget); }
      }));
      buttons.push(el("button", {
        class: "ghost",
        text: t("file.checkSignature"),
        onclick: function (event) { handleVerify(file, status, event.currentTarget); }
      }));
    }

    return el("div", { class: "file-row" }, [
      el("div", { class: "name", text: file.filename }),
      el("div", {
        class: "facts",
        text: t("model.fileFacts", {
          size: bytes(file.size),
          triangles: num(file.triangles),
          date: date(file.uploaded_at)
        })
      }),
      el("div", { class: "meta" }, [
        signedTag,
        file.key_id ? el("span", { class: "tag", text: t("file.key", { id: file.key_id }) }) : null
      ]),
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

  /* Fetch a file into memory and check its SHA-256 locally. */
  async function fetchVerified(file, status) {
    var grant = await api("/api/files/" + file.id + "/grant", { method: "POST" });
    status.className = "status-line work";
    status.textContent = t("status.downloading");

    var response = await fetch(grant.url, { credentials: "same-origin" });
    if (!response.ok) {
      var body = await response.json().catch(function () { return {}; });
      throw new Error(errorText(body, response.status) || t("status.refused"));
    }
    var buffer = await response.arrayBuffer();

    status.textContent = t("status.hashing");
    var actual = await sha256Hex(buffer);
    if (actual === null) {
      status.className = "status-line warn";
      status.textContent = t("status.noWebCrypto");
      return buffer;
    }
    if (actual !== grant.sha256) {
      throw new Error(t("status.digestMismatch", {
        actual: actual.slice(0, 16),
        expected: grant.sha256.slice(0, 16)
      }));
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

  function saveBlob(blob, filename) {
    var url = URL.createObjectURL(blob);
    var link = el("a", { href: url, download: filename });
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    setTimeout(function () { URL.revokeObjectURL(url); }, 10000);
  }

  function handleDownload(file, status, button) {
    if (!requireLogin()) return;
    withBusy(button, async function () {
      try {
        var buffer = await fetchVerified(file, status);
        saveBlob(new Blob([buffer], { type: "model/stl" }), file.filename);

        // The .sig.json file lets the model be verified offline later on.
        var sidecar = await api("/api/files/" + file.id + "/signature");
        saveBlob(
          new Blob([JSON.stringify(sidecar, null, 2)], { type: "application/json" }),
          file.filename + ".sig.json"
        );

        status.className = "status-line ok";
        status.textContent = t("status.downloadOk");
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
        var buffer = await fetchVerified(file, status);
        var hint = viewerHolder.querySelector("#viewer-hint");

        if (!viewer) viewer = new window.STLViewer(viewerHolder);
        if (!viewer.supported()) {
          status.className = "status-line bad";
          status.textContent = t("status.noWebGL");
          return;
        }
        var triangles = viewer.load(buffer);
        if (hint) hint.textContent = "";
        status.className = "status-line ok";
        status.textContent = t("status.rendered", { triangles: num(triangles) });
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
      status.textContent = t("status.serverChecking");
      try {
        var result = await api("/api/files/" + file.id + "/verify");
        if (result.ok) {
          status.className = "status-line ok";
          status.textContent = t("status.signatureOk", { id: result.key_id });
        } else {
          status.className = "status-line bad";
          status.textContent = t("status.verifyFailed", { reason: result.reason });
        }
      } catch (err) {
        status.className = "status-line bad";
        status.textContent = err.message;
      }
    });
  }

  /* --- Routing --- */

  function route() {
    var match = location.pathname.match(/^\/model\/(.+)$/);
    if (match) {
      searchInput.style.visibility = "hidden";
      renderModel(decodeURIComponent(match[1]));
    } else {
      searchInput.style.visibility = "visible";
      renderCatalog(searchInput.value);
    }
  }

  document.addEventListener("click", function (event) {
    var link = event.target.closest ? event.target.closest("a") : null;
    if (!link || link.target || link.hasAttribute("download")) return;
    var href = link.getAttribute("href") || "";
    if (href.charAt(0) !== "/" || href.indexOf("/static/") === 0 || href === "/admin") return;
    event.preventDefault();
    history.pushState(null, "", href);
    viewer = null;
    route();
  });

  window.addEventListener("popstate", function () { viewer = null; route(); });

  var searchTimer = null;
  searchInput.addEventListener("input", function () {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(function () {
      if (!location.pathname.match(/^\/model\//)) renderCatalog(searchInput.value);
    }, 250);
  });

  window.I18N.applyStatic(document);

  api("/api/auth/me")
    .then(function (data) { session = data; })
    .catch(function () { session = { authenticated: false }; })
    .then(function () {
      renderAuth();
      route();
    });
})();
