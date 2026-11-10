# Build stage
FROM docker.io/node:22.22-slim AS build

WORKDIR /app

# Enable Corepack and prepare PNPM
ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"
RUN corepack enable

# Optional corporate CA: put corp-ca.crt in frontend/certs/ (see docker/README.md).
COPY certs/ /tmp/certs/
COPY package.json pnpm-lock.yaml* ./

RUN if [ -f /tmp/certs/corp-ca.crt ]; then \
        export NODE_EXTRA_CA_CERTS=/tmp/certs/corp-ca.crt; \
        pnpm config set cafile /tmp/certs/corp-ca.crt; \
    fi && \
    pnpm install --frozen-lockfile

# Copy static assets and configurations
COPY tsconfig.json vite.config.ts ./
COPY src/index.html ./
COPY src/public/ ./public
COPY src/app ./src

# The bundle is served behind a proxy or Ingress that routes API paths to the
# backend, so call the origin that served it. Local dev falls back to
# http://localhost:8000.
ENV VITE_DRILLDOWN_BASE_URL=same-origin

# Build production distribution bundle
RUN pnpm run build

# Production runtime stage
FROM docker.io/nginxinc/nginx-unprivileged:alpine

USER root

RUN rm -rf /usr/share/nginx/html/*

# Deploy compiled client assets
COPY --from=build /app/dist /usr/share/nginx/html
COPY src/nginx.conf /etc/nginx/conf.d/default.conf

RUN mkdir -p /usr/share/nginx/html/input \
    && chown -R nginx:nginx /usr/share/nginx/html

# nginx-unprivileged runs under port 8080 by default because non-root users cannot bind to <1024
EXPOSE 8080

USER nginx

CMD ["nginx", "-g", "daemon off;"]
