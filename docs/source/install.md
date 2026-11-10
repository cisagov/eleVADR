# Installation and Deployment #

eleVADR is designed to be capable of running in sensitive,
air-gapped critical infrastructure networks.

The supported workflow is the **local Windows platform**: the backend
and frontend run directly on the workstation, and Docker Desktop hosts
the localhost-only MongoDB database (and the Zeek runtime when Zeek is
not installed natively). Daily operation, administration, and recovery
are covered in the [Operator Guide](operator-guide.md).

---

## Prerequisites ##

Install these once per workstation:

| Requirement | Version | Used for |
| --- | --- | --- |
| Git | Any recent version | Cloning the repository |
| Python | 3.12 or newer, available as `python` | Backend, auth, and platform tooling |
| Node.js | 22.22.3 or newer **within the Node 22 line** | Vite frontend. Node 23+ is rejected by the preflight check |
| npm | Bundled with Node.js | Locked frontend install (`npm ci`) |
| Docker Desktop | Engine must be running | MongoDB, and Zeek when no native Zeek is found |

Zeek 8.0.5+ can optionally be installed natively and placed on `PATH`
(or pointed to with `ELEVADR_ZEEK_COMMAND`). Without it, eleVADR runs
Zeek from the `zeek/zeek:9.0.0` Docker image. Set
`ELEVADR_ZEEK_DOCKER_IMAGE` to use a different image.

Confirm the tools are available:

```powershell
git --version
python --version
node --version
npm --version
docker info
```

---

## Fresh clone setup ##

### 1. Clone the repository ###

Clone into a short path that is **not** inside a cloud-synced folder
such as OneDrive. Syncing `node_modules` and the Docker-related files
can slow installs and leave partially written dependencies.

```powershell
git clone https://github.com/cisagov/eleVADR.git C:\dev\eleVADR
cd C:\dev\eleVADR
```

`develop` is the default branch, so no checkout is needed.

If you use a Python virtual environment, create and activate it in
this shell first. The launcher windows inherit the shell's
environment, so use the same shell for both scripts below.

### 2. Run first-run setup (once) ###

From the repository root:

```powershell
.\first_run_elevadr.bat
```

The script stops at the first failure, so the last message tells you
which step to fix. It performs these steps:

1. Runs the deployment preflight (Python, Node, npm, Docker, and
   required package files).
2. Installs the backend requirements from
   `backend\requirements-platform.txt` with `pip`.
3. Installs the frontend from `frontend\package-lock.json` with
   `npm ci`.
4. Runs `setup_elevadr_database.bat`, which generates
   `.elevadr-platform.env` with random MongoDB credentials and a JWT
   signing secret, starts the MongoDB container, and waits until it is
   healthy.
5. Prompts for the first administrator (default username `admin`) if
   no users exist. Passwords must be at least 12 characters.
6. Enables authentication and reruns the preflight.

It is safe to run again on an initialized installation. Existing users
are detected and the administrator prompt is skipped.

### 3. Pre-pull the Zeek image (optional) ###

If you do not have a native Zeek installation, pull the Docker image
now so the first PCAP analysis does not depend on network access:

```powershell
.\prepare_zeek_runtime.bat
```

### 4. Start eleVADR ###

```powershell
.\start_elevadr.bat
```

This opens two terminal windows, one for the backend and one for the
frontend. Check them for startup errors.

| Service | Address |
| --- | --- |
| Frontend | `http://127.0.0.1:5173/` |
| Backend | `http://127.0.0.1:8765/` |

Open the frontend and sign in with the administrator account you
created. To check the backend, including the Zeek runtime and
detector status:

```powershell
Invoke-RestMethod http://127.0.0.1:8765/health
```

### 5. Validate the installation (optional) ###

```powershell
.\validate_clean_install.bat
```

This runs the initialized preflight, the database health check, a
frontend build, the release preflight, and the platform regression
tests, so it takes noticeably longer than the other steps.

---

## What a fresh clone does not contain ##

The repository holds source code only. Everything below is created on
each machine and is intentionally excluded from git.

| Item | How it is created | Notes |
| --- | --- | --- |
| `.elevadr-platform.env` | `setup_elevadr_database.bat` (during first run) | Holds the MongoDB credentials and JWT secret. Never commit, copy between machines, or paste it into support logs. See `.elevadr-platform.env.example` for the supported settings |
| `frontend/node_modules/` | `npm ci` (during first run) | Rerun `npm ci` in `frontend` if it is missing or damaged |
| Python packages | `pip install` (during first run) | Installed into the active Python environment |
| MongoDB data | Docker volume `elevadr-mongodb-data` | Users, report index, and audit history |
| `storage/` | Created by the backend as data is added | Retained PCAPs and saved report JSON under `storage/users/` |
| Zeek image | Pulled by Docker on first use, or by `prepare_zeek_runtime.bat` | Not needed when native Zeek is on `PATH` |

`frontend/.env.local` is included in the repository with default
values that point the frontend at the local backend on port 8765. It
only needs editing if the backend port changes. If you change it,
restart the frontend.

### Keep the environment file and the database together ###

MongoDB applies its root credentials only when the data volume is
first created. If `.elevadr-platform.env` is deleted and regenerated
while the `elevadr-mongodb-data` volume still exists, the new
credentials will not match the existing database and the backend will
fail to authenticate. Keep the file, or restore from a backup into a
fresh setup as described below.

### Moving to a new clone or machine ###

A new clone starts with an empty database and an empty `storage/`
folder. To carry over users, reports, and retained PCAPs:

1. On the old installation, create a backup:

   ```powershell
   .\backup_elevadr.bat
   ```

2. On the new clone, complete first-run setup and start the database.
3. Stop the backend (`stop_elevadr.bat`) but leave MongoDB running,
   then validate and restore:

   ```powershell
   .\validate_elevadr_backup.bat <backup-file>
   .\restore_elevadr.bat <backup-file> --yes
   ```

4. Start eleVADR again with `start_elevadr.bat`.

Backups exclude the JWT and MongoDB secrets, so the new installation
keeps its own. Sessions from the old installation are not carried
over, and users sign in again. Protect backup archives as sensitive
data, and see the [Operator Guide](operator-guide.md) for encrypted
backups.

---

## Daily operation ##

| Task | Command |
| --- | --- |
| Start (or restart) the backend and frontend | `.\start_elevadr.bat` |
| Stop the backend and frontend | `.\stop_elevadr.bat` |
| Start the database | `.\start_elevadr_database.bat` |
| Stop the database (data is preserved) | `.\stop_elevadr_database.bat` |
| Check database health | `.\check_elevadr_database.bat` |

`start_elevadr.bat` does not start MongoDB. If the database is not
running, for example after Docker Desktop was stopped, run
`start_elevadr_database.bat` first.

`start_elevadr.bat` also acts as a restart. It stops any eleVADR
frontend or backend already listening on ports 5173 and 8765, removes
leftover eleVADR Zeek containers, and aborts if a different program is
using either port. In-memory processing jobs are lost on restart;
MongoDB data, saved reports, retained PCAPs, and contexts are kept.

Do not run `docker compose down -v`, because it deletes the MongoDB
volume.

---

## Docker Compose ##

`docker-compose.yml` defines `mongodb`, `backend`, `elevadr-ui` and an
optional `mongo-tools` helper. All ports are bound to `127.0.0.1`. The
helper scripts start only the `mongodb` service, with
`--env-file .elevadr-platform.env`, so use the scripts rather than
calling `docker compose` directly. In this workflow the backend and
frontend run on the host, not in containers.

To run the whole stack in containers instead (UI on port 8080), stop
`start_elevadr.bat` first, because the container backend also uses port
8765. See `docker/README.md` in the repository for that workflow and for
every setting.

---

## Troubleshooting ##

**The preflight rejects Node.js.** The frontend requires Node 22.22.3
or newer within the Node 22 line. Install a supported 22.x release.

**`Cannot find module ... vite`, or the frontend does not start.**
`frontend\node_modules` is missing or incomplete. From `frontend`, run
`npm ci` (or rerun `first_run_elevadr.bat`). Use npm for the local
platform. The `pnpm-lock.yaml` file is used by CI and the
documentation build, and mixing installers in one `node_modules` folder
can leave it broken.

**`start_elevadr.bat` reports that port 5173 or 8765 is occupied.**
Another program is using the port. Close it, or stop it from Task
Manager, and start again.

**`WARNING: Platform environment file missing`.** Run
`setup_elevadr_database.bat` (or `first_run_elevadr.bat`) to generate
`.elevadr-platform.env`.

**MongoDB errors, or the backend cannot connect.** Make sure Docker
Desktop is running, then run `check_elevadr_database.bat` and
`start_elevadr_database.bat`.

**PCAP analysis cannot run.** Confirm Docker is running and the Zeek
image is available, or that native Zeek is on `PATH`.

More troubleshooting, including CORS and upload-size settings, is in
the [Operator Guide](operator-guide.md).
