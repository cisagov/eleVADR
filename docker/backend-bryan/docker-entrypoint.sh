#!/bin/bash
set -e

if ! command -v zeek >/dev/null 2>&1; then
  echo "Zeek is not installed or not on PATH" >&2
  exit 1
fi

# Creates the first administrator only when no users exist and a password is provided.
if [ -n "${ELEVADR_BOOTSTRAP_ADMIN_PASSWORD:-}" ]; then
  python /app/bootstrap_admin.py
fi

cd /app
exec python -m backend_bryan.integration.http_reference_server \
  --host 0.0.0.0 --port "${ELEVADR_BACKEND_PORT:-8765}"
