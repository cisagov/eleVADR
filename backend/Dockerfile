# Use the official Zeek image as the base. This guarantees all native dependencies,
# C++ components, libnode, and libuv are perfect and pre-linked.
FROM zeek/zeek:8.0.5

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Install minimal runtime dependencies needed for python environments, pandas, and tools
USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libpcap-dev \
    libmaxminddb0 \
    libzmq5 \
    tree \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Set up non-root app user
RUN groupadd --system --gid 1000 appgroup \
    && useradd --system --create-home --uid 1000 --gid 1000 appuser

# Create standard workspace folders
RUN mkdir -p /app/data/uploads \
             /app/data/zeeks \
             /app/output \
             /input \
             /output \
             && chown -R appuser:appgroup /app /input /output

# Copy UV package manager
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

USER appuser
WORKDIR /app

# Tell UV to fetch Python 3.14 and prepare the isolated virtualenv
ENV UV_PYTHON=3.14
ENV UV_COMPILE_BYTECODE=1

# Copy dependency configuration
COPY --chown=appuser:appgroup pyproject.toml uv.lock* ./

# Install dependencies with cached UV operations
RUN --mount=type=secret,id=ssl_cert,required=false,uid=1000,gid=1000 \
    --mount=type=cache,target=/home/appuser/.cache/uv,uid=1000,gid=1000 \
    if [ -f /run/secrets/ssl_cert ]; then \
        SSL_CERT_FILE=/run/secrets/ssl_cert uv sync --frozen; \
    else \
        uv sync --frozen; \
    fi

# Copy application source code directly into the workspace
COPY --chown=appuser:appgroup src/ /app/src/

# Convert JSON reference data to Parquet
RUN uv run python src/app/data/assessor_data/convert_to_parquet.py \
    && rm -f src/app/data/assessor_data/port_risk_v2.json

# Copy entrypoint script
COPY --chown=appuser:appgroup docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENV PCAP_INPUT=/input/capture.pcap
ENV REPORT_OUTPUT=/output/report.json

VOLUME ["/input", "/output"]

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
