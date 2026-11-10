# eleVADR platform backend (backend) with auth and MongoDB persistence.
# Build from the repository root:
#   docker build -f docker/backend/Dockerfile .
FROM docker.io/zeek/zeek:9.0.0

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1

USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 1000 appgroup \
    && useradd --system --create-home --uid 1000 --gid 1000 appuser \
    && mkdir -p /app/storage \
    && chown -R appuser:appgroup /app

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

USER appuser
WORKDIR /app

ENV UV_PYTHON=3.13 \
    UV_COMPILE_BYTECODE=1 \
    VIRTUAL_ENV=/app/.venv \
    PATH="/app/.venv/bin:${PATH}"

# Optional corporate CA: put corp-ca.crt in docker/backend/certs/ (see docker/README.md).
COPY --chown=appuser:appgroup docker/backend/certs/ /tmp/certs/
COPY --chown=appuser:appgroup backend/requirements-platform.txt /tmp/requirements-platform.txt
RUN if [ -f /tmp/certs/corp-ca.crt ]; then export SSL_CERT_FILE=/tmp/certs/corp-ca.crt; fi && \
    uv venv /app/.venv && \
    uv pip install --no-cache -r /tmp/requirements-platform.txt

COPY --chown=appuser:appgroup backend/ /app/backend/
COPY --chown=appuser:appgroup docker/backend/bootstrap_admin.py /app/bootstrap_admin.py
COPY --chown=appuser:appgroup docker/backend/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Reports and retained PCAPs. backend.auth.backup_restore expects <app>/storage.
VOLUME ["/app/storage"]

ENV ELEVADR_BACKEND_PORT=8765

EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=20s \
    CMD curl -fs "http://127.0.0.1:${ELEVADR_BACKEND_PORT}/health" || exit 1

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
