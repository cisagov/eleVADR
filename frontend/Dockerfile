# Build stage
FROM docker.io/node:22.22-alpine AS build

WORKDIR /app

# Enable Corepack and prepare PNPM
ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"
RUN corepack enable

COPY package.json pnpm-lock.yaml* ./

# Install workspace dependencies using BuildKit cache mounts
RUN --mount=type=secret,id=ssl_cert,required=false \
    --mount=type=cache,target=/pnpm/store \
    if [ -f /run/secrets/ssl_cert ]; then \
        pnpm config set cafile /run/secrets/ssl_cert; \
    fi && \
    pnpm install --frozen-lockfile

# Copy static assets and configurations
COPY tsconfig.json vite.config.ts ./
COPY src/index.html ./
COPY src/public/ ./public
COPY src/app ./src

# Build production distribution bundle
RUN --mount=type=secret,id=ssl_cert,required=false \
    pnpm run build

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
