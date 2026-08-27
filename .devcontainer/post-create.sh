#!/usr/bin/env bash
set -euo pipefail

# Set to true only for environments that require additional corporate CA certificates.
ELEVADR_USE_CORP_CA=true

SYSTEM_CA_BUNDLE="/etc/ssl/certs/ca-certificates.crt"
CORP_CA_DIR="/workspace/.devcontainer/certs"
CORP_CA_ENV="${HOME}/.config/elevadr/corp-ca.env"
BASHRC="${HOME}/.bashrc"
BASHRC_MARKER_BEGIN="# >>> eleVADR corporate CA >>>"
BASHRC_MARKER_END="# <<< eleVADR corporate CA <<<"

remove_corp_ca_shell_config() {
  rm -f "${CORP_CA_ENV}"
  if [ -f "${BASHRC}" ]; then
    sed -i "/${BASHRC_MARKER_BEGIN//\//\\/}/,/${BASHRC_MARKER_END//\//\\/}/d" "${BASHRC}"
  fi
}

case "${ELEVADR_USE_CORP_CA,,}" in
  true|1|yes|on)
    echo "Corporate CA support enabled."

    CORP_INTERMEDIATE_CA="${CORP_CA_DIR}/corp-intermediate.crt"
    CORP_ROOT_CA="${CORP_CA_DIR}/corp-root.crt"

    for cert in "${CORP_INTERMEDIATE_CA}" "${CORP_ROOT_CA}"; do
      if [ ! -s "${cert}" ]; then
        echo "ERROR: ELEVADR_USE_CORP_CA=true but required certificate is missing: ${cert}" >&2
        exit 1
      fi
    done

    echo "Installing corporate CA certificates into the system trust store..."
    sudo install -m 0644 "${CORP_INTERMEDIATE_CA}" /usr/local/share/ca-certificates/corp-intermediate.crt
    sudo install -m 0644 "${CORP_ROOT_CA}" /usr/local/share/ca-certificates/corp-root.crt
    sudo update-ca-certificates

    # Apply corporate trust to this setup run.
    export SSL_CERT_FILE="${SYSTEM_CA_BUNDLE}"
    export REQUESTS_CA_BUNDLE="${SYSTEM_CA_BUNDLE}"
    export NODE_OPTIONS="--use-system-ca"
    unset NODE_EXTRA_CA_CERTS

    # Apply the same trust settings to future interactive bash terminals.
    mkdir -p "$(dirname "${CORP_CA_ENV}")"
    cat > "${CORP_CA_ENV}" <<ENVEOF
export SSL_CERT_FILE="${SYSTEM_CA_BUNDLE}"
export REQUESTS_CA_BUNDLE="${SYSTEM_CA_BUNDLE}"
export NODE_OPTIONS="--use-system-ca"
unset NODE_EXTRA_CA_CERTS
ENVEOF

    if [ -f "${BASHRC}" ]; then
      sed -i "/${BASHRC_MARKER_BEGIN//\//\\/}/,/${BASHRC_MARKER_END//\//\\/}/d" "${BASHRC}"
    fi
    cat >> "${BASHRC}" <<'BASHRCEOF'
# >>> eleVADR corporate CA >>>
if [ -f "${HOME}/.config/elevadr/corp-ca.env" ]; then
  . "${HOME}/.config/elevadr/corp-ca.env"
fi
# <<< eleVADR corporate CA <<<
BASHRCEOF
    ;;

  false|0|no|off|"")
    echo "Corporate CA support disabled; using default system trust."
    remove_corp_ca_shell_config
    ;;

  *)
    echo "ERROR: ELEVADR_USE_CORP_CA must be true or false (received: ${ELEVADR_USE_CORP_CA})." >&2
    exit 2
    ;;
esac

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
  (cd frontend && pnpm install --no-ignore-scripts)
fi

uv tool install pre-commit && uv tool install deptry \
  && uv tool update-shell \
  && pre-commit install && pre-commit install-hooks

echo "post-create complete."
