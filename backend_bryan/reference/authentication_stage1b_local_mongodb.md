# Authentication Stage 1B - Local MongoDB Runtime

Stage 1B provides a supported local MongoDB Community Server runtime for the optional Stage 1 authentication foundation. It does not enable authentication or change the frontend.

## Security defaults

- MongoDB is published only on `127.0.0.1`.
- MongoDB authentication is enabled with a generated root credential.
- Credentials and the future JWT secret are stored in `.elevadr-platform.env`, which is gitignored.
- MongoDB data is stored in the named Docker volume `elevadr-mongodb-data` and survives normal container stop/recreation.
- `ELEVADR_AUTH_ENABLED=false` remains the generated default.
- The MongoDB image is pinned to `mongodb/mongodb-community-server:8.0.32-ubi9-slim`.

## First-time setup

Run:

```powershell
.\setup_elevadr_database.bat
```

The script checks Docker, creates `.elevadr-platform.env` if it does not already exist, starts MongoDB, waits for its health check, and verifies the container is healthy.

Install the optional Python dependencies before creating an application user:

```powershell
python -m pip install -r backend_bryan\requirements-platform.txt
```

Then create the first user:

```powershell
.\create_elevadr_user.bat analyst
```

The password is prompted interactively and is stored only as an Argon2 hash in MongoDB.

## Daily runtime commands

```powershell
.\start_elevadr_database.bat
.\check_elevadr_database.bat
.\stop_elevadr_database.bat
```

Stopping the container does not remove the named volume. Do not use `docker compose down -v` unless the intent is to destroy the local database.

## Enabling authentication later

Stage 1B deliberately leaves authentication disabled. The login UI stage will load the generated environment values into the backend process and deliberately switch `ELEVADR_AUTH_ENABLED=true` after the end-to-end login flow is ready.
