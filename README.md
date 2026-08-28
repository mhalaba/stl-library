# STL Library

[![tests](https://github.com/mhalaba/stl-library/actions/workflows/tests.yml/badge.svg)](https://github.com/mhalaba/stl-library/actions/workflows/tests.yml)

*Polish version: [README.pl.md](README.pl.md) · Interface available in English and Polish.*

A web catalogue of STL files for 3D printing in which **every file is
cryptographically signed**, and its integrity is checked on every download —
first on the server, then again in the visitor's browser. A file that fails
either check is not released, and it is quarantined.

The project was built around a single requirement: *nobody may swap a file in
the library for a different one*. The answer is not a token attached to the
file — it is three [independent layers](#why-a-token-alone-is-not-enough), the
most important of which is an Ed25519 signature made with a key kept **off the
server**.

Companion: **[HART](https://github.com/mhalaba/hart)** — a local-first STL vault
that never uploads the mesh. Same canonical Ed25519 sidecar (`*.stl.sig.json`),
plus a sabotage scanner (cavities, 3MF polyglots, triangle bombs, XSS in
`solid`). Sidecars from this library verify in HART; sidecars from HART verify
with `tools/verify_stl.py`. MIT · [Halaba.online](https://halaba.online).

### What it does

- Catalogue of models with search, categories and licences.
- User accounts — only signed-in visitors download, and every link is personal and expires.
- Administrator panel: models, uploads, integrity audit, event log.
- In-browser 3D preview of a model (drag to rotate, scroll to zoom).
- Offline verification of a downloaded file, without trusting the server, using a dependency-free script.
- Library-wide audit from the command line, ready for cron.
- English and Polish throughout — interface, API messages and documentation.

### Stack

Python 3.9+ · FastAPI · SQLite · plain JavaScript. The frontend has **no**
external dependencies — the 3D preview is written directly against WebGL, so
the page works under a CSP with no `unsafe-inline` and without calling out to
any CDN.

---

## Why a token alone is not enough

A token attached to a file does not protect against the file being swapped; it
protects against the file being downloaded by the wrong person. Those are two
different problems. Hence three independent layers:

| Layer | Mechanism | What it stops |
|---|---|---|
| **Integrity** | SHA-256 of every file, computed on upload and recomputed on every release | Any change to the bytes — disk corruption, a swapped file |
| **Authenticity** | **Ed25519** signature over the file's manifest | A swap that comes **together with** a corrected digest in the database |
| **Access control** | **HMAC-SHA256** token in a single expiring link | Downloads by people without an account, links passed around |

The second layer is the crucial one. If an attacker breaks into the server they
have both the files and the database — they can swap a file and "fix" its
digest. What they cannot do is forge the signature, as long as the private key
is not on that server. That is the entire point of
[offline mode](#offline-mode--recommended-in-production).

### What exactly is signed

The signature does not cover the file's bytes directly, but its **manifest** — a
canonical JSON document:

```json
{"filename":"wall-hook.stl","key_id":"52ef20536348f151","model":"wall-hook",
 "publisher":"stl-library","schema":"stl-library/manifest/v1","sha256":"9becf9…",
 "size":1848,"uploaded_at":1754136000}
```

Keys sorted, no whitespace — so the server, the signing tool and the verifier
all compute the signature over exactly the same bytes. The manifest binds the
content (`sha256`) to the filename, size, model and publisher, which means an
authentically signed file cannot be slipped into a different catalogue entry.

### A file's path comes from its content

Files live at `data/storage/ab/cd/abcd….stl`, where the name is the file's own
SHA-256. Swapping the content immediately puts it out of step with the path it
sits under — detectable without consulting the database. As a bonus, the same
file uploaded twice occupies space once.

### Verification in the browser

The "Download" button does not point straight at the file. The browser fetches
it into memory, computes SHA-256 with WebCrypto and compares it against the
digest from the signed manifest. Only a match lets the file be written to disk.
A `.sig.json` file is downloaded alongside the model, so authenticity can be
confirmed later, offline, without trusting the server:

```bash
python3 tools/verify_stl.py wall-hook.stl wall-hook.stl.sig.json
```

`verify_stl.py` has no dependencies at all — it carries its own Ed25519
verification implementation, so you can hand it to users without asking them to
install anything.

---

## Running it

```bash
cd stl-library
python3 -m venv .venv && ./.venv/bin/pip install -r requirements.txt
```

Generate the signing keys:

```bash
./.venv/bin/python tools/keygen.py
```

Copy `.env.example` to `.env` and fill in `STL_SECRET_KEY`,
`STL_SIGNING_PUBLIC_KEY` and the first administrator's credentials. Then:

```bash
./run.sh
```

The library comes up at http://127.0.0.1:8000, the administrator panel at `/admin`.

A few sample models to look at (delete once you upload your own):

```bash
./.venv/bin/python tools/seed_demo.py
```

For local work also set `STL_COOKIE_SECURE=false` in `.env` — without it the
browser rejects the session cookie over plain HTTP.

`.env` is **not** versioned (it holds keys), so after cloning the repository you
need to create it from `.env.example`.

---

## Two signing modes

### Online mode (default, convenient)

`STL_SIGNING_PRIVATE_KEY` is set on the server, and an uploaded file is signed
immediately. The drawback: whoever takes the server can sign any file. Fine for
local work and for libraries where a swapped file is not a realistic threat.

### Offline mode — recommended in production

The server has **no** `STL_SIGNING_PRIVATE_KEY`, only the public key. Uploaded
files get the status `pending` and **cannot be downloaded**. You create the
signatures from your own machine:

```bash
export STL_SIGNING_PRIVATE_KEY=<private key hex>
python3 tools/sign_pending.py --url https://your-library.example --email admin@example.com
```

The script fetches the list of unsigned files, rebuilds their manifests, signs
them locally and sends back the signatures alone. The private key never leaves
your machine.

The server does not take what it receives on trust: it rebuilds the manifest
from its own data, compares it with the submitted one, verifies the signature
against the public key and re-hashes the file on disk. A signature from a
foreign key, or a manifest that does not line up — rejected.

---

## Auditing

By hand (a button in the panel) or from the command line:

```bash
./.venv/bin/python tools/audit.py
```

Re-hashes every file and verifies the signatures. Anything that fails is
quarantined and disappears from the catalogue. Exit code `1` when problems are
found, which makes it suitable for cron:

```cron
17 4 * * * cd /srv/stl-library && ./.venv/bin/python tools/audit.py || mail -s "STL library: problem" you@example.com
```

---

## Tests

```bash
./.venv/bin/python tests/unit.py   # 82 tests, no server
./.venv/bin/python tests/e2e.py    # 49 tests against a real server
```

Both suites run in [GitHub Actions](.github/workflows/tests.yml) on every push,
on Python 3.9 and 3.13, together with a check that no secret reached the
repository.

**`tests/unit.py`** takes on the things that are awkward to trigger over HTTP: a
token signed for a different purpose, a manifest with reordered keys, a path
escaping the storage directory, a binary STL whose header inflates the triangle
count, a signature from a foreign key.

**`tests/e2e.py`** starts a real server in offline mode and plays the attacker.
Two file-swapping scenarios:

1. **file swapped on disk** → the server refuses to release it and quarantines it;
2. **file swapped + digest and size corrected in the database** → stopped on the
   signed manifest not lining up, even though the database "looks" right.

Beyond that: an expired download link (the test knows the server's secret and
mints its own tokens — with a control proving a *fresh* token works, so the
result means something), a token moved to a different file, a database row
pointing outside the storage directory, the sign-in rate limit, content
deduplication on delete, unpublished models, ASCII STL files, language
negotiation, and the fact that `verify_stl.py` catches a swap on the user's side
while its built-in Ed25519 implementation agrees with the `cryptography`
library.

---

## Other hardening

- **Passwords** — PBKDF2-HMAC-SHA256, 260,000 iterations, a random salt per account.
- **Sessions** — HttpOnly, SameSite=Lax, Secure cookie, HMAC-signed with an expiry.
- **CSRF** — double-submit cookie; every state-changing request must carry an
  `X-CSRF-Token` header matching the cookie.
- **Sign-in limit** — 10 attempts per (e-mail, IP) in 15 minutes; one error message
  whether or not the account exists.
- **Download links** — valid for 5 minutes, bound to the user, the file and its digest.
  Moving a token to a different file does not work.
- **Upload validation** — STL structure check (binary and ASCII), size limit, filename
  sanitisation, write through a temporary file.
- **Headers** — CSP without `unsafe-inline`, `X-Frame-Options: DENY`, `nosniff`, `no-referrer`.
- **Event log** — sign-ins, uploads, signatures, quarantines, audits.

---

## Languages

English is the default; Polish is a complete second version. The switcher in the
header stores the choice in `localStorage` and mirrors it into the `stl_lang`
cookie, so API messages come back in the same language. Without a cookie the
server falls back to `Accept-Language`, then to `STL_DEFAULT_LANGUAGE`.

Interface strings live in [`static/i18n.js`](static/i18n.js), API messages in
[`app/messages.py`](app/messages.py). A unit test fails if any key is missing a
translation, so adding a language means filling in one dictionary in each file.

---

## Production deployment

1. Put it behind HTTPS (nginx/Caddy) — without it `STL_COOKIE_SECURE=true` blocks sign-in.
2. Generate `STL_SECRET_KEY` once and leave it (changing it signs everyone out).
3. Choose offline mode: remove `STL_SIGNING_PRIVATE_KEY` from the server.
4. Back up the private key offline — losing it means re-signing the whole library
   with a new one.
5. Backups must cover `data/library.db` **and** `data/storage/`. The database
   without the files (or the other way round) is useless.
6. Run it under systemd or `uvicorn --workers N` behind a proxy; `data/` should
   belong to the service user and never be served directly by the web server.
7. Set up cron with `tools/audit.py`.

### What this does not solve

- It does not protect against a file being swapped **before** you sign it — you sign
  whatever you are given. If the source of a model is uncertain, check it before upload.
- It does not protect against an administrator who knowingly signs a bad file.
- In online mode it does not protect against server compromise — that is what offline
  mode is for.
- It does not deal with copyright in the models; the `license` field is descriptive only.

---

## Layout

```
app/
  config.py     configuration from environment variables
  db.py         SQLite: schema and access
  security.py   passwords, HMAC tokens, manifests and Ed25519 signatures
  storage.py    content-addressed storage, STL validation
  integrity.py  the verification path before a file is released
  messages.py   user-facing message catalogue (en/pl)
  main.py       API and routing
static/         frontend: catalogue, model view, 3D preview, admin panel
  i18n.js       interface translations and the language switcher
tools/
  keygen.py       key pair generation
  sign_pending.py signing from an offline machine
  verify_stl.py   verifier for end users (no dependencies)
  audit.py        integrity audit for cron
  seed_demo.py    sample models
tests/
  unit.py       crypto and storage layer, no server
  e2e.py        end-to-end, including simulated file swapping
```

---

## Licence

[MIT](LICENSE). Do what you like with it — just keep the copyright notice.

Note the two different licences in play here: MIT covers **the code of this
service**. The licence of the STL models themselves is a separate field on each
model in the catalogue (`CC BY-NC 4.0` by default) and has nothing to do with
MIT.
