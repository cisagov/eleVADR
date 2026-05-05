# Multi-stage build for optimized image size
FROM ubuntu:26.04 AS builder

# Avoid interactive prompts during build
ENV DEBIAN_FRONTEND=noninteractive

# Install Zeek and build dependencies
# The SSL cert is mounted as a build secret and appended to the system bundle
# for the duration of this RUN step only - it is never written into the image layer
RUN --mount=type=secret,id=ssl_cert,required=false \
    apt-get update && apt-get install --no-install-recommends -y \
    wget=1.21.2-2ubuntu1.1 \
    gnupg=2.2.27-3ubuntu2.5 \
    lsb-release=11.1.0ubuntu4 \
    ca-certificates=20240203~22.04.1 \
    && if [ -f /run/secrets/ssl_cert ]; then \
        mkdir -p /usr/local/share/ca-certificates && \
        cp /run/secrets/ssl_cert /usr/local/share/ca-certificates/ssl-cert.crt && \
        update-ca-certificates; \
    fi \
    && echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' | tee /etc/apt/sources.list.d/security:zeek.list \
    && wget -qO - https://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/Release.key | apt-key add - \
    && apt-get update \
    && apt-get install --no-install-recommends -y zeek=8.0.5-0 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Final stage
FROM python:3.10-slim

# Avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install runtime dependencies

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libpcap0.8t64=1.10.5-2 \
    libmaxminddb0=1.12.2-1 \
    libzmq5=4.3.5-1+b3 \
    tree=2.2.1-1 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*


# Copy only necessary Zeek components from builder stage
COPY --from=builder /opt/zeek/bin /opt/zeek/bin
COPY --from=builder /opt/zeek/lib /opt/zeek/lib
COPY --from=builder /opt/zeek/share/zeek /opt/zeek/share/zeek

# Add Zeek to PATH
ENV PATH="/opt/zeek/bin:${PATH}"

# Set working directory
WORKDIR /app

# Copy requirements first for better layer caching
COPY requirements.txt .

# Install Python dependencies
# Mount the cert secret again for pip's SSL verification
RUN --mount=type=secret,id=ssl_cert,required=false \
    if [ -f /run/secrets/ssl_cert ]; then \
        pip3 install --no-cache-dir --cert /run/secrets/ssl_cert -r requirements.txt; \
    else \
        pip3 install --no-cache-dir -r requirements.txt; \
    fi

# Copy application code
# COPY src/app/ .
COPY src/ .

# Convert JSON reference data to Parquet for reduced disk footprint,
# then remove the JSON source files to keep the image lean
RUN python app/data/assessor_data/convert_to_parquet.py \
    && rm app/data/assessor_data/port_risk_v2.json

# Create non-privileged user and group
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

# Copy entrypoint script
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh \
    && chown appuser:appgroup /usr/local/bin/docker-entrypoint.sh

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PCAP_INPUT=/input/capture.pcap
ENV REPORT_OUTPUT=/output/report.json

# Volume mounts for input/output
VOLUME ["/input", "/output"]

# Switch to non-privileged user
USER appuser

# Entrypoint
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
