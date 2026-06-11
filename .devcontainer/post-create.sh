#!/usr/bin/env bash
set -euo pipefail

certs=(/usr/local/share/ca-certificates/host/*.crt)
HOST_CA="${certs[0]}"
if [ -n "${HOST_CA}" ] && [ -s "${HOST_CA}" ]; then
  echo "Using corporate CA: ${HOST_CA}"
  export SSL_CERT_FILE="${HOST_CA}"
  export REQUESTS_CA_BUNDLE="${HOST_CA}"
  export NODE_EXTRA_CA_CERTS="${HOST_CA}"
  sudo update-ca-certificates
fi

export NVM_DIR="${HOME}/.nvm"

# shellcheck disable=SC1090,SC1091
[ -s "${NVM_DIR}/nvm.sh" ] && . "${NVM_DIR}/nvm.sh"

git config core.fileMode false

pnpm config set cache-dir /workspace/.local_cache/pnpm/cache
pnpm config set store-dir /workspace/.local_cache/pnpm/store

if [ -d backend ]; then
  echo "Installing backend dependencies with uv..."
  (cd backend && uv sync)
fi

if [ -d frontend ]; then
  echo "Installing frontend dependencies with pnpm..."
  (cd frontend && pnpm install)
fi

uv tool install pre-commit && uv tool install deptry \
  && uv tool update-shell \
  && pre-commit install && pre-commit install-hooks

echo "post-create complete."
