#!/usr/bin/env bash
# Uruchamia bibliotekę lokalnie. Wczytuje .env, jeśli istnieje.
set -euo pipefail
cd "$(dirname "$0")"

if [ -f .env ]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
fi

PYTHON=./.venv/bin/python
[ -x "$PYTHON" ] || PYTHON=python3

exec "$PYTHON" -m uvicorn app.main:app --host "${HOST:-127.0.0.1}" --port "${PORT:-8000}" "$@"
