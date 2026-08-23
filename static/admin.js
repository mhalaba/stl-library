/* Administrator panel: models, uploads, integrity audit, event log. */

(function () {
  "use strict";

  var t = window.I18N.t;
  var LOCALE = window.I18N.lang() === "pl" ? "pl-PL" : "en-GB";

  var view = document.getElementById("view");
  var authBox = document.getElementById("auth-box");

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

  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

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

  /* FastAPI returns `detail` as a list of objects for validation errors. */
  function errorText(data, status) {
    var detail = data && data.detail;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail)) {
      return detail.map(function (item) { return item.msg || String(item); }).join("; ");
    }
    return t("error.generic", { status: status });
  }

  function stat(num, label) {
    return el("div", { class: "stat" }, [
      el("div", { class: "num", text: String(num) }),
      el("div", { class: "lbl", text: label })
    ]);
  }

  async function render() {
    clear(view);
    clear(authBox);
    authBox.appendChild(window.I18N.switcher());

    var stats;
    try {
      stats = await api("/api/admin/stats");
    } catch (err) {
      view.appendChild(el("div", { class: "empty" }, [
        el("div", { text: err.message }),
        el("div", {}, [el("a", { href: "/", text: t("admin.signInFirst") })])
      ]));
      return;
    }

    authBox.appendChild(el("a", { href: "/", class: "tag", text: t("nav.catalogue") }));

    view.appendChild(el("div", { class: "notice" }, [
      el("strong", { text: t("admin.mode", { mode: stats.signing_mode }) }),
      stats.signing_mode === "online" ? t("admin.modeOnline") : t("admin.modeOffline"),
      stats.key_id ? el("div", { text: t("admin.activeKey", { id: stats.key_id }) }) : null
    ]));

    view.appendChild(el("div", { class: "admin-grid" }, [
      stat(stats.users, t("admin.stat.users")),
      stat(stats.models, t("admin.stat.models")),
      stat(stats.files_signed, t("admin.stat.signed")),
      stat(stats.files_pending, t("admin.stat.pending")),
      stat(stats.files_quarantined, t("admin.stat.quarantined")),
      stat(stats.downloads_24h, t("admin.stat.downloads"))
    ]));

    view.appendChild(newModelPanel());
    view.appendChild(uploadPanel());
    view.appendChild(auditPanel());
    view.appendChild(logPanel(stats.recent_audit));
  }

  function newModelPanel() {
    var title = el("input", { type: "text", placeholder: t("admin.placeholder.title") });
    var category = el("input", { type: "text", placeholder: t("admin.placeholder.category") });
    var license = el("input", { type: "text", value: "CC BY-NC 4.0" });
    var description = el("textarea", { placeholder: t("admin.placeholder.description") });
    var status = el("div", { class: "status-line" });

    return el("div", { class: "panel" }, [
      el("h2", { text: t("admin.newModel") }),
      el("div", { class: "stack" }, [
        el("div", { class: "field" }, [el("label", { text: t("admin.field.title") }), title]),
        el("div", { class: "field" }, [el("label", { text: t("admin.field.description") }), description]),
        el("div", { class: "inline" }, [
          el("div", { class: "field grow" }, [el("label", { text: t("admin.field.category") }), category]),
          el("div", { class: "field grow" }, [el("label", { text: t("admin.field.license") }), license])
        ]),
        el("div", {}, [
          el("button", {
            class: "primary",
            text: t("admin.createModel"),
            onclick: async function (event) {
              var button = event.currentTarget;
              button.disabled = true;
              status.className = "status-line work";
              status.textContent = t("admin.saving");
              try {
                var result = await api("/api/admin/models", {
                  method: "POST",
                  json: {
                    title: title.value.trim(),
                    description: description.value.trim(),
                    category: category.value.trim() || "other",
                    license: license.value.trim() || "CC BY-NC 4.0",
                    is_published: true
                  }
                });
                status.className = "status-line ok";
                status.textContent = t("admin.modelCreated", { slug: result.slug });
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

  var modelSelect = null;

  async function refreshModelSelect() {
    if (!modelSelect) return;
    var data = await api("/api/models?limit=200");
    clear(modelSelect);
    data.models.forEach(function (model) {
      modelSelect.appendChild(el("option", { value: model.slug, text: model.title }));
    });
  }

  function uploadPanel() {
    modelSelect = el("select", {});
    var fileInput = el("input", { type: "file", accept: ".stl" });
    var status = el("div", { class: "status-line" });
    refreshModelSelect().catch(function () {});

    return el("div", { class: "panel" }, [
      el("h2", { text: t("admin.upload") }),
      el("div", { class: "stack" }, [
        el("div", { class: "field" }, [el("label", { text: t("admin.field.model") }), modelSelect]),
        el("div", { class: "field" }, [el("label", { text: t("admin.field.file") }), fileInput]),
        el("div", {}, [
          el("button", {
            class: "primary",
            text: t("admin.uploadButton"),
            onclick: async function (event) {
              var button = event.currentTarget;
              if (!fileInput.files.length || !modelSelect.value) {
                status.className = "status-line bad";
                status.textContent = t("admin.pickBoth");
                return;
              }
              button.disabled = true;
              status.className = "status-line work";
              status.textContent = t("admin.uploading");
              try {
                var body = new FormData();
                body.append("file", fileInput.files[0]);
                var response = await fetch(
                  "/api/admin/models/" + encodeURIComponent(modelSelect.value) + "/files",
                  {
                    method: "POST",
                    headers: { "X-CSRF-Token": csrfToken() },
                    body: body,
                    credentials: "same-origin"
                  }
                );
                var data = await response.json();
                if (!response.ok) throw new Error(errorText(data, response.status));
                status.className = "status-line ok";
                status.textContent =
                  t("admin.uploaded", {
                    sha: data.sha256,
                    triangles: data.triangles,
                    status: data.status
                  }) + (data.deduplicated ? t("admin.uploadedDedup") : "");
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
    var status = el("div", { class: "status-line" });
    var results = el("div", {});

    return el("div", { class: "panel" }, [
      el("h2", { text: t("admin.audit") }),
      el("p", { class: "lbl", text: t("admin.auditHint") }),
      el("button", {
        text: t("admin.auditRun"),
        onclick: async function (event) {
          var button = event.currentTarget;
          button.disabled = true;
          clear(results);
          status.className = "status-line work";
          status.textContent = t("admin.auditWorking");
          try {
            var data = await api("/api/admin/audit", { method: "POST" });
            if (!data.problems.length) {
              status.className = "status-line ok";
              status.textContent = t("admin.auditClean", { checked: data.checked });
            } else {
              status.className = "status-line bad";
              status.textContent = t("admin.auditProblems", {
                checked: data.checked,
                problems: data.problems.length
              });
              var table = el("table", {}, [
                el("tr", {}, [
                  el("th", { text: t("admin.table.file") }),
                  el("th", { text: t("admin.table.reason") })
                ])
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
    var table = el("table", {}, [
      el("tr", {}, [
        el("th", { text: t("admin.table.when") }),
        el("th", { text: t("admin.table.event") }),
        el("th", { text: t("admin.table.details") })
      ])
    ]);
    (entries || []).forEach(function (entry) {
      table.appendChild(el("tr", {}, [
        el("td", { text: new Date(entry.ts * 1000).toLocaleString(LOCALE) }),
        el("td", { text: entry.action }),
        el("td", { class: "mono", text: entry.detail })
      ]));
    });
    return el("div", { class: "panel" }, [el("h2", { text: t("admin.log") }), table]);
  }

  window.I18N.applyStatic(document);
  render();
})();
