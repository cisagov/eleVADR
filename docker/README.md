# eleVADR containers and configuration

This folder holds the container definitions for the platform backend (`backend/`) and MongoDB
(`mongodb/`), and this README covers how to run them and every setting they read. The frontend
image is built from `frontend/Dockerfile`.

| Service (`docker-compose.yml`) | Image source | Port | Purpose |
| --- | --- | --- | --- |
| `mongodb` | `docker/mongodb/Dockerfile` | 27017 | Application database |
| `backend` | `docker/backend/Dockerfile` | 8765 | Platform backend: login, users, reports, PCAP analysis |
| `elevadr-ui` | `frontend/Dockerfile` | 8080 | React frontend served by nginx |
| `mongo-tools` | `docker.io/mongo:8.0` | none | Optional `mongodump` and `mongorestore` helper (profile `tools`) |

Known limitation: the frontend's drilldown panels call `/reports/<id>/drilldown/...`, `/reports/<id>/connections`,
`/devices` and `/services`. The platform backend does not serve these routes, so the `elevadr-ui` nginx answers
`/reports/` with a 404 and the message "Drilldown data is not available from this backend yet." The panels show that
message. Implementing the routes in `backend/` would remove the limitation, after which the nginx rule should go.

The Kubernetes manifests and pipelines for AKS are in the separate `elevadr-devops` repository.
There the same settings come from `kubernetes/deployment.yml` and an Azure DevOps variable group
instead of `.elevadr-platform.env`. Its build pipeline clones this repository and builds the
backend (`docker/backend/Dockerfile`), frontend (`frontend/Dockerfile`) and MongoDB
(`docker/mongodb/Dockerfile`) images from the Dockerfiles here, so changes to them reach AKS on the
next build. Keep them free of `RUN --mount` and other BuildKit-only syntax.

## Set up on a fresh clone

Requires Docker with Compose v2.

1. Create the environment file. The helper generates random credentials:

   ```bash
   python -m backend.auth.local_runtime init
   ```

   Without Python, copy `.elevadr-platform.env.example` to `.elevadr-platform.env` and fill in
   `ELEVADR_MONGO_ROOT_USERNAME`, `ELEVADR_MONGO_ROOT_PASSWORD` and `ELEVADR_JWT_SECRET` (32 or more characters).

2. To have the first administrator created automatically, add these to `.elevadr-platform.env`:

   ```text
   ELEVADR_BOOTSTRAP_ADMIN_USERNAME=admin
   ELEVADR_BOOTSTRAP_ADMIN_PASSWORD=<12 or more characters>
   ```

   The bootstrap only creates the admin when the `users` collection is empty. Remove the password after the first
   start, unless `ELEVADR_BOOTSTRAP_ADMIN_SYNC=true` is set to keep the admin password in sync with it.

3. Start the database only:

   ```bash
   docker compose --env-file .elevadr-platform.env up -d --build --wait mongodb
   ```

   Or the whole stack (database, `backend` and `elevadr-ui`):

   ```bash
   docker compose --env-file .elevadr-platform.env up -d --build --wait
   ```

   The UI is on <http://127.0.0.1:8080>, `backend` on <http://127.0.0.1:8765> and Mongo on `127.0.0.1:27017`.

4. Check it:

   ```bash
   docker compose --env-file .elevadr-platform.env ps
   ```

A corporate CA certificate for image builds is optional. If your network needs one, put the PEM file
at `docker/backend/certs/corp-ca.crt` for the backend image and `frontend/certs/corp-ca.crt` for the
frontend image. The files are gitignored. The Dockerfiles copy each `certs/` folder into the build and
use the certificate for `uv` and `pnpm` installs only when it exists. They do not use `RUN --mount`, so
the same Dockerfiles also build on ACR Tasks' classic builder, which the AKS pipeline in `elevadr-devops`
relies on.

The Windows helper scripts (`first_run_elevadr.bat` and the others) run only the `mongodb` service and
start the backend and frontend on the host. Do not run that workflow and the full stack at the same
time, because both use port 8765 and the `elevadr-mongodb` container.

## Settings reference

All settings are environment variables. Locally they come from `.elevadr-platform.env`. Not every
variable is passed through `docker-compose.yml`, so the last column says where each one can be set.
"Env file" means it is read when you run the backend outside Docker, and "Compose" means the
`backend` service passes it into the container.

| Variable | Default | Read by | Purpose | Where set |
| --- | --- | --- | --- | --- |
| `ELEVADR_MONGO_ROOT_USERNAME` | none, required | mongodb, backend | MongoDB root user, created on first start. | Env file, Compose, AKS |
| `ELEVADR_MONGO_ROOT_PASSWORD` | none, required | mongodb, backend | MongoDB root password. Hex or base64url only on AKS, because it goes into a `mongodb://` URI. | Env file, Compose, AKS |
| `ELEVADR_MONGO_PORT` | `27017` | mongodb | Host loopback port Compose publishes. Used by Compose only, not passed into containers. | Env file |
| `ELEVADR_AUTH_ENABLED` | `false` | backend | Turns on login and MongoDB persistence. When false the backend never connects to MongoDB. | Env file, Compose, AKS |
| `ELEVADR_MONGODB_URI` | `mongodb://127.0.0.1:27017` | backend | Connection string. Ignored when `ELEVADR_MONGO_HOST` is set. AKS builds its own from the root credentials. | Env file, AKS |
| `ELEVADR_MONGO_HOST` | none | backend | When set, the backend builds the connection string from this host, the root credentials and `ELEVADR_MONGO_HOST_PORT`, percent-encoding the credentials so special characters are safe. Compose sets it to `mongodb`. | Compose |
| `ELEVADR_MONGO_HOST_PORT` | `27017` | backend | Port used with `ELEVADR_MONGO_HOST`. | Compose |
| `ELEVADR_TRUSTED_PROXIES` | none | backend | Comma-separated CIDR ranges of proxies allowed to set `X-Forwarded-For`. The last forwarded hop is then used as the client address for login throttling. Without it, all clients behind a proxy share the proxy's address. Compose defaults to the private ranges `172.16.0.0/12`, `10.0.0.0/8` and `192.168.0.0/16`. Use the narrowest range that covers your proxy. | Env file, Compose |
| `ELEVADR_MONGODB_DATABASE` | `elevadr` | backend | Database name. | Env file, Compose, AKS |
| `ELEVADR_JWT_SECRET` | none, required when auth is on | backend | JWT signing secret, 32 or more characters. Changing it signs everyone out. | Env file, Compose, AKS |
| `ELEVADR_JWT_ALGORITHM` | `HS256` | backend | JWT algorithm. Only `HS256` is accepted. | Env file |
| `ELEVADR_JWT_EXPIRE_MINUTES` | `60` | backend | Access token lifetime, 1 to 10080. | Env file, Compose, AKS |
| `ELEVADR_CORS_ORIGINS` | `http://127.0.0.1:5173,http://localhost:5173` | backend | Comma-separated allowed browser origins. | Env file, Compose, AKS |
| `ELEVADR_MAX_PCAP_UPLOAD_MB` | `256` | backend | Largest accepted PCAP upload, 1 to 2048. On AKS the Ingress `proxy-body-size` must be larger. | Env file, Compose, AKS |
| `ELEVADR_PCAP_RETENTION_DAYS` | `0` | backend | Delete retained PCAPs not used within this many days. 0 keeps them, maximum 3650. | Env file, Compose |
| `ELEVADR_PCAP_STORAGE_LIMIT_GB` | `0` | backend | Cap on retained PCAP storage. 0 means no cap. | Env file, Compose |
| `ELEVADR_STORAGE_ROOT` | `<repo>/storage` | backend | Where reports and retained PCAPs are written. `/app/storage` in the container. | Env file |
| `ELEVADR_BACKUP_PASSPHRASE` | empty | backend | When set, backups are AES-GCM encrypted `.evbackup` archives. | Env file, Compose |
| `ELEVADR_BACKEND_PORT` | `8765` | backend container | Port the container entrypoint listens on. | AKS |
| `ELEVADR_BOOTSTRAP_ADMIN_USERNAME` | `admin` | backend | Name of the first admin. | Env file, Compose, AKS |
| `ELEVADR_BOOTSTRAP_ADMIN_PASSWORD` | none | backend | Creates the first admin when the `users` collection is empty. 12 or more characters. | Env file, Compose, AKS |
| `ELEVADR_BOOTSTRAP_ADMIN_SYNC` | off | backend | Set to `true` to update that admin's password to match `ELEVADR_BOOTSTRAP_ADMIN_PASSWORD` on each start when it differs. Changes made in the app are overwritten on the next restart. | Env file, Compose, AKS |
| `ELEVADR_ZEEK_COMMAND` | empty | backend | Zeek executable to use instead of searching `PATH`. | Env file, Compose, AKS |
| `ELEVADR_ZEEK_DOCKER_IMAGE` | `zeek/zeek:9.0.0` | backend | Zeek image used when Zeek is not on `PATH` and Docker is available. | Env file |
| `ELEVADR_EVIDENCE_TTL_SECONDS` | `7200` | backend | How long cached Zeek evidence is kept. | Env file |
| `ELEVADR_FINISHED_JOB_TTL_SECONDS` | `300` | backend | How long finished analysis jobs stay listed. | Env file |
| `ELEVADR_EVIDENCE_CACHE_ROOT` | `<temp dir>/elevadr-zeek-evidence-cache` | backend | Folder for cached Zeek evidence. | Env file |

There are two separate accounts:

- The MongoDB root user (`ELEVADR_MONGO_ROOT_USERNAME` and `ELEVADR_MONGO_ROOT_PASSWORD`) is only
  created when `/data/db` is empty. Changing these later does not change the existing root user.
  To reset, remove the volume (this deletes all data): `docker compose down -v`.
- The app admin (`ELEVADR_BOOTSTRAP_ADMIN_*`) lives in the `users` collection. It is created only
  when that collection is empty. With `ELEVADR_BOOTSTRAP_ADMIN_SYNC=true` the backend also updates
  its password on start when it differs from `ELEVADR_BOOTSTRAP_ADMIN_PASSWORD`, so no volume
  reset is needed to change it.

## MongoDB

MongoDB 8.0 Community Edition is the application database in development, staging and any
other deployed environment. The image is built from `mongodb/Dockerfile` and configured
by `mongodb/mongod.conf`. Both are baked into the image, so every environment runs the same configuration.

The only client of this database today is `backend` (service `backend` in
`docker-compose.yml`). With `ELEVADR_AUTH_ENABLED=false` the backend never connects to it.

### What is in the image

| Item | Value |
| --- | --- |
| Base image | `mongodb/mongodb-community-server:8.0.32-ubi9-slim`, pinned by tag |
| Config | `/etc/mongod.conf`, started with `mongod --config /etc/mongod.conf` |
| Data | `/data/db`, a named volume in compose and a PVC in Kubernetes |
| Port | 27017 |
| Run as | `mongod` (uid 1000), not root |
| Seed data | None. The database is empty on first start. |
| Init scripts | None. The base image creates the root user from `ELEVADR_MONGO_ROOT_USERNAME` and `ELEVADR_MONGO_ROOT_PASSWORD`. |

The base image does not include `mongodump` or `mongorestore`. The `mongo-tools` compose service
provides them (see "Dump and restore").

### Security configuration

Set in `mongod.conf` and in the compose service:

| Control | Setting |
| --- | --- |
| Authentication | `security.authorization: enabled`. Unauthenticated clients can connect but every command is rejected. |
| Auth mechanism | SCRAM-SHA-256 only (`authenticationMechanisms`). |
| Localhost auth bypass | Disabled (`enableLocalhostAuthBypass: false`). |
| Server-side JavaScript | Disabled (`javascriptEnabled: false`). The application does not use `$where`, `$function`, `$accumulator` or `mapReduce`. |
| Connections | `maxIncomingConnections: 100`. |
| WiredTiger cache | Capped at 0.25 GB so the database does not compete with the backend for memory. |
| Network exposure | Compose publishes the port on `127.0.0.1` only. Kubernetes uses a ClusterIP Service with no route. |
| Container | `read_only` root filesystem (only `/data/db` and a tmpfs `/tmp` are writable), all capabilities dropped, `no-new-privileges`. |
| Compute limits | 1 CPU and 1 GB memory limit in compose. |
| Credentials | Never in the image or the repo. Supplied through environment variables from `.elevadr-platform.env` (gitignored). |

Not configured, and relevant to STIG and hardening reviews: TLS on the Mongo port, the audit log
(not available in Community Edition), encryption at rest, and a least-privilege application user.
The backend connects with the root account (`authSource=admin`). TLS is not needed on the compose
network, but should be reviewed before the database is reachable from outside the cluster.

### Maintenance: dump and restore

Two tools can back up the data. Use `mongodump` for the database alone. Use the application backup
when you also need the report and PCAP files.

The database holds only metadata for reports and captures. The report JSON and PCAP bytes are files
in the `elevadr-storage` volume (`/app/storage`), so a database dump alone does not restore them.

#### mongodump and mongorestore

The `mongo-tools` service runs the tools on the compose network. Dumps are written to
`backups/mongodb/` (gitignored).

```bash
docker compose --env-file .elevadr-platform.env --profile tools run --rm mongo-tools \
  sh -c 'mongodump --uri="$MONGODB_URI" --db=elevadr --gzip --archive=/backups/elevadr-$(date +%Y%m%d-%H%M%S).archive.gz'
```

Restore into the same database (existing documents with the same `_id` are skipped; add `--drop` to
replace collections first):

```bash
docker compose --env-file .elevadr-platform.env --profile tools run --rm mongo-tools \
  sh -c 'mongorestore --uri="$MONGODB_URI" --gzip --archive=/backups/<file>.archive.gz --nsInclude="elevadr.*"'
```

To restore into a scratch database for inspection, add `--nsFrom='elevadr.*' --nsTo='elevadr_scratch.*'`.

Dumps include password hashes and audit data. Treat them as sensitive and do not commit them.
Indexes are included in the dump.

#### Application backup

`backend.auth.backup_restore` writes a zip (or an AES-GCM encrypted `.evbackup` when
`ELEVADR_BACKUP_PASSPHRASE` is set) with every collection plus `storage/users/`. It does not include
index definitions (the application recreates them on start) and it drops all collections on restore.
The Windows wrappers are `backup_elevadr.bat`, `validate_elevadr_backup.bat` and `restore_elevadr.bat`.

Known limitation: the tool uses `<repo>/storage` as the storage root and ignores
`ELEVADR_STORAGE_ROOT`. Inside the `backend` container that path is `/app/storage`, which is
also the mounted volume, so it works there. The argument is the output file, and the archive stays
inside the container until you copy it out:

```bash
docker compose --env-file .elevadr-platform.env exec backend \
  python -m backend.auth.backup_restore backup /tmp/elevadr-backup.zip
docker compose --env-file .elevadr-platform.env cp backend:/tmp/elevadr-backup.zip backups/
```

#### Volumes

| Volume | Contents |
| --- | --- |
| `elevadr-mongodb-data` | MongoDB data files |
| `elevadr-storage` | Report JSON files and retained PCAPs |

Do not run `docker compose down -v` unless you intend to delete both.

### Database, collections and documents

Database name: `elevadr` (`ELEVADR_MONGODB_DATABASE`). It is created on first write.

Collections are created and indexed by the application when it starts with auth enabled, except
`users`, whose indexes are also created by `create_user` and `has_users`. There are no
schema validators on the server. The shapes below are enforced by the application code in
`backend/auth/`.

All per-user collections carry `owner_id`, the string form of the owning user's `_id`.

| Collection | Holds | Source |
| --- | --- | --- |
| `users` | Accounts and password hashes | `auth/database.py` |
| `reports` | Metadata for saved analysis reports | `auth/report_store.py` |
| `captures` | Metadata for retained PCAP uploads | `auth/capture_store.py` |
| `audit_events` | Security and activity log | `auth/audit_store.py` |
| `context_profiles` | Saved Detection Context profiles | `auth/context_profile_store.py` |
| `topology_saved_queries` | Saved topology queries | `auth/topology_query_store.py` |
| `topology_saved_comparisons` | Saved topology comparisons | `auth/topology_comparison_store.py` |

#### users

| Field | Type | Notes |
| --- | --- | --- |
| `_id` | ObjectId | User id, used as the JWT `sub` |
| `username` | string | 1 to 128 characters |
| `username_normalized` | string | Lowercase `username`. Unique. |
| `password_hash` | string | Argon2id (PHC format). Passwords must be 12 or more characters. |
| `role` | string | `admin`, `analyst` or `read_only` |
| `disabled` | bool | Disabled users cannot log in |
| `session_version` | int | Incremented to invalidate tokens. Absent on users made by `create_user`; read as 0. |
| `created`, `updated` | datetime | UTC |
| `email`, `email_normalized` | string | Optional. Unique when present. |
| `last_login` | datetime | Optional |

Indexes: `users_username_unique` (unique on `username_normalized`), `users_email_unique` (unique,
partial on string `email_normalized`). Users are disabled, never deleted.

Roles: `admin` can view, write and manage users. `analyst` can view and write. `read_only` can only view.

#### reports

Metadata only. The report JSON is at `<storage>/users/<owner_id>/reports/<report_id>.json`.

| Field | Type | Notes |
| --- | --- | --- |
| `owner_id`, `owner_username` | string | |
| `report_id` | string | Matches `^[A-Za-z0-9_.-]{1,160}$` |
| `title` | string | Defaults to the source filename. 1 to 160 characters when renamed. |
| `source_filename` | string | Uploaded file name |
| `report_path` | string | Path of the JSON file relative to the storage root |
| `report_version` | string | |
| `finding_count`, `device_count`, `service_count`, `connection_count` | int | Summary counts |
| `capture_id` | string or null | Links to `captures.capture_id` |
| `created_at`, `updated_at` | datetime | |

Indexes: `reports_owner_created` (`owner_id`, `created_at` descending), `reports_owner_report_unique`
(unique on `owner_id`, `report_id`). No automatic expiry.

#### captures

Metadata only. The PCAP is at `<storage>/users/<owner_id>/pcaps/<capture_id>.pcap` (or `.pcapng`).

| Field | Type | Notes |
| --- | --- | --- |
| `capture_id` | string | 32 hex characters |
| `owner_id`, `owner_username` | string | |
| `filename` | string | Uploaded file name |
| `sha256` | string | Used to de-duplicate per owner |
| `size_bytes` | int | Counted against `ELEVADR_PCAP_STORAGE_LIMIT_GB` |
| `capture_path` | string | Relative to the storage root |
| `created_at`, `last_used_at` | datetime | |

Indexes: `captures_owner_created`, `captures_owner_sha_unique` (unique on `owner_id`, `sha256`),
`captures_last_used`. Retention is done by the application, not a TTL index: with
`ELEVADR_PCAP_RETENTION_DAYS` greater than 0 it deletes captures not used within that many days, at
startup and on uploads.

#### audit_events

Insert-only.

| Field | Type | Notes |
| --- | --- | --- |
| `created_at` | datetime | UTC |
| `actor_id`, `actor_username` | string or null | Null for failed logins by unknown users |
| `action` | string | For example `auth.login`, `user.create`, `report.delete`, `capture.delete`, `storage.cleanup` |
| `result` | string | `success`, `failure` or `denied` |
| `target_type`, `target_id` | string | |
| `metadata` | object | Sanitized. Keys that look like passwords, tokens or secrets are replaced with `[redacted]`. |

Indexes: `audit_created_desc`, `audit_actor_created`, and the TTL index `audit_retention_ttl` on
`created_at` with `expireAfterSeconds` of 180 days. The retention is fixed in code and cannot be
changed through an environment variable.

#### context_profiles

| Field | Type | Notes |
| --- | --- | --- |
| `owner_id`, `owner_username` | string | |
| `profile_id` | string | Same as `profile.id` |
| `profile` | object | The Detection Context profile as sent by the UI. `id` and `name` are required. |
| `created_at`, `updated_at` | datetime | |

Indexes: `context_profiles_owner_id` (unique on `owner_id`, `profile_id`), `context_profiles_owner_updated`.

#### topology_saved_queries

| Field | Type | Notes |
| --- | --- | --- |
| `owner_id` | string | |
| `query_id` | string | 1 to 100 characters, none of `/ \ $ .` |
| `data` | object | `id`, `name` (1 to 100 characters), `updatedAt`, and `query` |
| `data.query` | object | Only the keys `type`, `subnet`, `purdueLevel`, `roleGroup`, `service`, `suspicious`, `findingRelated`, `minCount`, `startAsset`, `maxHops` (1 to 4), `direction` (`both`, `outbound`, `inbound`) |
| `updated_at` | datetime | |

Indexes: `owner_id_1_query_id_1` (unique), `owner_id_1_updated_at_-1`. At most 100 are listed per user.

#### topology_saved_comparisons

| Field | Type | Notes |
| --- | --- | --- |
| `owner_id` | string | |
| `comparison_id` | string | Same rules as `query_id` |
| `data` | object | `id`, `name`, `currentReportId`, `baselineId`, `filter` (`All`, `New`, `Not observed`, `Count changed`), `findingsOnly`, `queryOnly`, `updatedAt` |
| `updated_at` | datetime | |

The comparison stores report ids only, never report contents. Indexes: `owner_id_1_comparison_id_1`
(unique), `owner_id_1_updated_at_-1`.

### Changing the image

Edit `mongod.conf` or the `Dockerfile` and rebuild with `docker compose build mongodb`. The
`elevadr-devops` pipeline (`pipelines/build.yml`) builds this same `docker/mongodb/Dockerfile` from
the app repository checkout, so there is no second copy to update.
