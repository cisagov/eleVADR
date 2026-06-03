# Multi-stage build for optimized image size
FROM ubuntu:26.04 AS builder

# Avoid interactive prompts during build
ENV DEBIAN_FRONTEND=noninteractive

# Install Zeek and build dependencies
# The SSL cert is mounted as a build secret and appended to the system bundle
# for the duration of this RUN step only - it is never written into the image layer
RUN --mount=type=secret,id=ssl_cert,required=false \
    apt-get update && apt-get install --no-install-recommends -y \
    wget \
    gnupg \
    lsb-release \
    ca-certificates \
    gpg \
    && if [ -f /run/secrets/ssl_cert ]; then \
        mkdir -p /usr/local/share/ca-certificates && \
        cp /run/secrets/ssl_cert /usr/local/share/ca-certificates/ssl-cert.crt && \
        update-ca-certificates; \
    fi \
    && echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' | tee /etc/apt/sources.list.d/security:zeek.list \
    && wget -qO - https://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/Release.key | gpg --dearmor -o /etc/apt/keyrings/zeek.gpg \
    && echo 'deb [signed-by=/etc/apt/keyrings/zeek.gpg] http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' \
       | tee /etc/apt/sources.list.d/security:zeek.list \
    && apt-get update \
    && apt-get install --no-install-recommends -y zeek=8.0.5-0 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Final stage
FROM python:3.14-slim

# Avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Install runtime dependencies

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libpcap0.8t64 \
    libmaxminddb0 \
    libzmq5 \
    tree \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy only necessary Zeek components from builder stage
COPY --from=builder /opt/zeek/bin /opt/zeek/bin
COPY --from=builder /opt/zeek/lib /opt/zeek/lib
COPY --from=builder /opt/zeek/share/zeek /opt/zeek/share/zeek

RUN groupadd --system --gid 1000 appgroup \
    && useradd --system --create-home --uid 1000 --gid 1000 appuser

# Create necessary directories and set permissions
RUN mkdir -p /app/data/uploads \
    /app/data/zeeks \
    /app/output \
    /input \
    /output \
    && chmod -R 755 /opt/zeek \
    && chown -R appuser:appgroup /app /input /output

# Add Zeek to PATH
ENV PATH="/opt/zeek/bin:${PATH}"

ENV UV_COMPILE_BYTECODE=1
ENV UV_SYSTEM_PYTHON=1

COPY --from=ghcr.io/astral-sh/uv:python3.14-trixie-slim /usr/local/bin/uv /usr/local/bin/uvx /bin/

USER appuser

# Set working directory
WORKDIR /app

# Copy requirements first for better layer caching
COPY --chown=appuser:appgroup pyproject.toml .

# Install Python dependencies
# Mount the cert secret again for pip's SSL verification
RUN --mount=type=secret,id=ssl_cert,required=false,uid=1000,gid=1000 \
    if [ -f /run/secrets/ssl_cert ]; then \
        SSL_CERT_FILE=/run/secrets/ssl_cert uv sync; \
    else \
        uv sync; \
    fi

# Copy application code
# COPY src/app/ .
COPY --chown=appuser:appgroup src/ .

# Convert JSON reference data to Parquet for reduced disk footprint,
# then remove the JSON source files to keep the image lean
RUN uv run python app/data/assessor_data/convert_to_parquet.py \
    && rm app/data/assessor_data/port_risk_v2.json

# Copy entrypoint script
COPY --chown=appuser:appgroup docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Set environment variables
ENV PCAP_INPUT=/input/capture.pcap
ENV REPORT_OUTPUT=/output/report.json

# Volume mounts for input/output
VOLUME ["/input", "/output"]

# Entrypoint
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
