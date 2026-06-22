# Production Hardening & Deployment #

eleVADR is designed to be capable of running in sensitive,
air-gapped critical infrastructure networks. Consequently,
both the backend analysis engine and frontend dashboard feature
production-hardened configurations to restrict runtime privileges
and enforce high reliability.

## Docker Setup ##

Local service orchestration is managed through `docker-compose.yml`.
This multi-container composition
runs the backend and frontend in isolated bridge networks with
restricted host access.

To build and launch the complete stack with {term}`Docker`:

```bash
docker compose up --build -d
```

---

### Security Hardening Configurations ###

#### 1. Read-Only Runtimes ####

To block unauthorized filesystem changes during execution,
both containers run with read-only root filesystems:

```yaml
read_only: true
```

#### 2. Capability Drop ####

To enforce the principle of least privilege, all Linux kernel
capabilities are dropped from the running processes:

```yaml
cap_drop:
  - ALL
security_opt:
  - no-new-privileges:true
```

#### 3. Dedicated Temporary Filesystem (tmpfs) Volumes ####

Because the root filesystem is read-only, eleVADR uses write-isolated
memory directories (`tmpfs`) to store temporary
directories, file uploads, caches, and analytical intermediates.
This ensures no data persists on the host machine after the container stops:

```yaml
tmpfs:
  - /tmp
  - /var/cache/nginx
  - /var/run
```

For the backend engine, memory limits are mapped directly to processing directories:

```yaml
volumes:
  - type: tmpfs
    target: /app/src/app/data/uploads
    tmpfs:
      mode: 1023
```

---

### Resource Limit Allocations ###

To ensure analytical processing does not consume all host resources,
the backend composition enforces memory and CPU
limits. The CPU allocation is explicitly matched to support
the parallel analysis engine:

```yaml
deploy:
  resources:
    limits:
      memory: 4GB
      cpus: "4"
    reservations:
      memory: 512MB
```

The React frontend runs inside an unprivileged Nginx container,
isolated within strict resource constraints:

```yaml
deploy:
  resources:
    limits:
      memory: 512MB
    reservations:
      memory: 200MB
```

---

### Corporate Proxy & CA Certificate Integration ###

On corporate networks, eleVADR requires intercepting proxies and
custom Certificate Authorities (CA) to fetch
external dependencies during compilation.

1. Place your CA certificate inside `.devcontainer/certs/corp-ca.crt`.
1. The Docker build engine resolves the certificate using BuildKit cache mounts.
1. Pass environment references to the container runtime to enforce trusted connections:

```yaml
environment:
  SSL_CERT_FILE: ${SSL_CERT_FILE}
  REQUESTS_CA_BUNDLE: ${REQUESTS_CA_BUNDLE}
  CURL_CA_BUNDLE: ${CURL_CA_BUNDLE}
```
