/* Panel administratora: dodawanie modeli, wgrywanie plików STL, audyt. */

(function () {
  "use strict";

  const view = document.getElementById("view");
  const authBox = document.getElementById("auth-box");

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

  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

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

  /* FastAPI przy błędach walidacji zwraca `detail` jako listę obiektów. */
  function errorText(data, status) {
    const detail = data && data.detail;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail)) {
      return detail.map(function (item) { return item.msg || String(item); }).join("; ");
    }
    return "Błąd " + status;
  }

  function stat(num, label) {
    return el("div", { class: "stat" }, [
      el("div", { class: "num", text: String(num) }),
      el("div", { class: "lbl", text: label })
    ]);
  }

  async function render() {
    clear(view);

    let stats;
    try {
      stats = await api("/api/admin/stats");
    } catch (err) {
      view.appendChild(el("div", { class: "empty" }, [
        el("div", { text: err.message }),
        el("div", {}, [el("a", { href: "/", text: "← wróć do katalogu i zaloguj się jako administrator" })])
      ]));
      return;
    }

    authBox.appendChild(el("a", { href: "/", class: "tag", text: "katalog" }));

    view.appendChild(el("div", { class: "notice" }, [
      el("strong", { text: "Tryb podpisywania: " + stats.signing_mode + ". " }),
      stats.signing_mode === "online"
        ? "Klucz prywatny leży na serwerze — wygodne, ale włamanie na serwer pozwoliłoby podpisać podmieniony plik. Do produkcji przełącz się na tryb offline (README, sekcja „Tryb offline”)."
        : "Klucz prywatny jest poza serwerem. Wgrane pliki czekają w stanie „pending”, dopóki nie podpiszesz ich narzędziem tools/sign_pending.py.",
      stats.key_id ? el("div", { text: "Aktywny klucz: " + stats.key_id }) : null
    ]));

    view.appendChild(el("div", { class: "admin-grid" }, [
      stat(stats.users, "użytkowników"),
      stat(stats.models, "modeli"),
      stat(stats.files_signed, "plików podpisanych"),
      stat(stats.files_pending, "czeka na podpis"),
      stat(stats.files_quarantined, "w kwarantannie"),
      stat(stats.downloads_24h, "pobrań / 24h")
    ]));

    view.appendChild(newModelPanel());
    view.appendChild(uploadPanel());
    view.appendChild(auditPanel());
    view.appendChild(logPanel(stats.recent_audit));
  }

  function newModelPanel() {
    const title = el("input", { type: "text", placeholder: "np. Uchwyt na słuchawki" });
    const category = el("input", { type: "text", placeholder: "np. akcesoria" });
    const license = el("input", { type: "text", value: "CC BY-NC 4.0" });
    const description = el("textarea", { placeholder: "Krótki opis, parametry druku, zalecany materiał..." });
    const status = el("div", { class: "status-line" });

    return el("div", { class: "panel" }, [
      el("h2", { text: "Nowy model" }),
      el("div", { class: "stack" }, [
        el("div", { class: "field" }, [el("label", { text: "Tytuł" }), title]),
        el("div", { class: "field" }, [el("label", { text: "Opis" }), description]),
        el("div", { class: "inline" }, [
          el("div", { class: "field grow" }, [el("label", { text: "Kategoria" }), category]),
          el("div", { class: "field grow" }, [el("label", { text: "Licencja" }), license])
        ]),
        el("div", {}, [
          el("button", {
            class: "primary",
            text: "Utwórz model",
            onclick: async function (event) {
              const button = event.currentTarget;
              button.disabled = true;
              status.className = "status-line work";
              status.textContent = "Zapisywanie...";
              try {
                const result = await api("/api/admin/models", {
                  method: "POST",
                  json: {
                    title: title.value.trim(),
                    description: description.value.trim(),
                    category: category.value.trim() || "inne",
                    license: license.value.trim() || "CC BY-NC 4.0",
                    is_published: true
                  }
                });
                status.className = "status-line ok";
                status.textContent = "Utworzono model o adresie /model/" + result.slug;
                title.value = description.value = category.value = "";
                await refreshModelSelect();
              } catch (err) {
                status.className = "status-line bad";
                status.textContent = err.message;
              } finally {
                button.disabled = false;
              }
            }
          })
        ]),
        status
      ])
    ]);
  }

  let modelSelect = null;

  async function refreshModelSelect() {
    if (!modelSelect) return;
    const data = await api("/api/models?limit=200");
    clear(modelSelect);
    data.models.forEach(function (model) {
      modelSelect.appendChild(el("option", { value: model.slug, text: model.title }));
    });
  }

  function uploadPanel() {
    modelSelect = el("select", {});
    const fileInput = el("input", { type: "file", accept: ".stl" });
    const status = el("div", { class: "status-line" });
    refreshModelSelect().catch(function () {});

    return el("div", { class: "panel" }, [
      el("h2", { text: "Wgraj plik STL" }),
      el("div", { class: "stack" }, [
        el("div", { class: "field" }, [el("label", { text: "Model" }), modelSelect]),
        el("div", { class: "field" }, [el("label", { text: "Plik .stl" }), fileInput]),
        el("div", {}, [
          el("button", {
            class: "primary",
            text: "Wgraj i policz sumę kontrolną",
            onclick: async function (event) {
              const button = event.currentTarget;
              if (!fileInput.files.length || !modelSelect.value) {
                status.className = "status-line bad";
                status.textContent = "Wybierz model i plik.";
                return;
              }
              button.disabled = true;
              status.className = "status-line work";
              status.textContent = "Wysyłanie...";
              try {
                const body = new FormData();
                body.append("file", fileInput.files[0]);
                const response = await fetch(
                  "/api/admin/models/" + encodeURIComponent(modelSelect.value) + "/files",
                  {
                    method: "POST",
                    headers: { "X-CSRF-Token": csrfToken() },
                    body: body,
                    credentials: "same-origin"
                  }
                );
                const data = await response.json();
                if (!response.ok) throw new Error(errorText(data, response.status));
                status.className = "status-line ok";
                status.textContent =
                  "Wgrano. SHA-256: " + data.sha256 + " · trójkątów: " + data.triangles +
                  " · status: " + data.status +
                  (data.deduplicated ? " · ta sama treść była już w bibliotece" : "");
                fileInput.value = "";
              } catch (err) {
                status.className = "status-line bad";
                status.textContent = err.message;
              } finally {
                button.disabled = false;
              }
            }
          })
        ]),
        status
      ])
    ]);
  }

  function auditPanel() {
    const status = el("div", { class: "status-line" });
    const results = el("div", {});

    return el("div", { class: "panel" }, [
      el("h2", { text: "Audyt integralności" }),
      el("p", { class: "lbl", text: "Przelicza SHA-256 każdego pliku na dysku i sprawdza jego podpis. Cokolwiek się nie zgadza, trafia do kwarantanny i znika z katalogu." }),
      el("button", {
        text: "Sprawdź całą bibliotekę",
        onclick: async function (event) {
          const button = event.currentTarget;
          button.disabled = true;
          clear(results);
          status.className = "status-line work";
          status.textContent = "Przeliczanie...";
          try {
            const data = await api("/api/admin/audit", { method: "POST" });
            if (!data.problems.length) {
              status.className = "status-line ok";
              status.textContent = "Sprawdzono " + data.checked + " plików — wszystko się zgadza.";
            } else {
              status.className = "status-line bad";
              status.textContent = "Sprawdzono " + data.checked + " plików, problemów: " + data.problems.length;
              const table = el("table", {}, [
                el("tr", {}, [el("th", { text: "Plik" }), el("th", { text: "Powód" })])
              ]);
              data.problems.forEach(function (problem) {
                table.appendChild(el("tr", {}, [
                  el("td", { text: problem.filename }),
                  el("td", { text: problem.reason })
                ]));
              });
              results.appendChild(table);
            }
          } catch (err) {
            status.className = "status-line bad";
            status.textContent = err.message;
          } finally {
            button.disabled = false;
          }
        }
      }),
      status,
      results
    ]);
  }

  function logPanel(entries) {
    const table = el("table", {}, [
      el("tr", {}, [el("th", { text: "Kiedy" }), el("th", { text: "Zdarzenie" }), el("th", { text: "Szczegóły" })])
    ]);
    (entries || []).forEach(function (entry) {
      table.appendChild(el("tr", {}, [
        el("td", { text: new Date(entry.ts * 1000).toLocaleString("pl-PL") }),
        el("td", { text: entry.action }),
        el("td", { class: "mono", text: entry.detail })
      ]));
    });
    return el("div", { class: "panel" }, [el("h2", { text: "Dziennik zdarzeń" }), table]);
  }

  render();
})();
