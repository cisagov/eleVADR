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

if [ -d backend ]; then
  echo "Installing backend dependencies with uv..."
  (cd backend && uv sync)
fi

if [ -d frontend ]; then
  echo "Installing frontend dependencies with pnpm..."
  (cd frontend && pnpm install)
fi

uv tool install pre-commit && uv tool update-shell \
  && export PATH="/home/elevadr/.local/bin:$PATH" \
  && pre-commit install && pre-commit install-hooks

# if [ -e ~/.gnupg/pubring.kbx ] || [ -d ~/.gnupg/private-keys-v1.d ]; then
#   chown -R "$(id -u):$(id -g)" ~/.gnupg
#   mkdir -p ~/.gnupg/private-keys-v1.d
#   chmod 700 ~/.gnupg ~/.gnupg/private-keys-v1.d
#   find ~/.gnupg -type f -exec chmod 600 {} \; 2>/dev/null || true
#   cat > ~/.gnupg/gpg-agent.conf <<'EOF'
# pinentry-program /usr/bin/pinentry-curses
# allow-loopback-pinentry
# EOF
#   gpgconf --kill gpg-agent 2>/dev/null || true
#   echo "GPG configured."
# else
#   echo "No GPG keyring found; skipping GPG setup."
# fi

echo "post-create complete."
