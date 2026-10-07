# Stage 1 authentication foundation

Stage 1 adds optional authentication infrastructure without changing the frontend or detector engine.
Authentication is **disabled by default**, preserving the existing single-user workflow.

## Optional dependencies

```powershell
python -m pip install -r backend_bryan\requirements-platform.txt
```

## Environment

- `ELEVADR_AUTH_ENABLED=false` — default; `/auth/me` returns the anonymous principal.
- `ELEVADR_MONGODB_URI=mongodb://127.0.0.1:27017`
- `ELEVADR_MONGODB_DATABASE=elevadr`
- `ELEVADR_JWT_SECRET=<at least 32 characters>` — required when auth is enabled.
- `ELEVADR_JWT_EXPIRE_MINUTES=60`

When enabled, startup connects to MongoDB, verifies connectivity, and creates unique username/email indexes on the `users` collection.
Passwords are Argon2id hashes and access tokens are signed JWTs. The analysis engine does not import or depend on this package.

## Endpoints

- `POST /auth/login` with JSON `{ "username": "...", "password": "..." }`
- `POST /auth/logout` — stateless acknowledgement; clients discard their token.
- `GET /auth/me` — anonymous while auth is disabled; bearer-token identity when enabled.

No frontend login UI is included in Stage 1.

## Bootstrap a user

After installing the optional dependencies and starting MongoDB:

```powershell
python -m backend_bryan.auth.create_user analyst --role analyst
```

The command prompts for the password instead of accepting it on the command line.

## Protected API behavior

When `ELEVADR_AUTH_ENABLED=true`, all analysis, PCAP upload, context-discovery, job polling, and cancellation endpoints require a valid `Authorization: Bearer <token>` header. `/health`, `/auth/login`, and `/auth/logout` remain public. `/auth/me` requires a bearer token when authentication is enabled and returns the anonymous principal when authentication is disabled.

Stage 1 uses stateless access tokens. `/auth/logout` does not revoke an already-issued token; the client discards it. Server-side revocation/refresh sessions are intentionally deferred to a later stage.
