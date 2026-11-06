# Operator Guide

This guide covers the supported local Windows workflow for the current eleVADR platform: first-run setup, authenticated PCAP analysis, saved reports and retained captures, user administration, storage, audit history, backup/restore, and health checks.

## 1. Prerequisites and first run

Install the supported prerequisites before extracting the eleVADR package:

- Python 3.12 or newer.
- Node.js 22.22.3 or newer in the Node 22 line, with npm.
- Docker Desktop with the Docker engine running.

From the repository/package root, run:

```powershell
.\first_run_elevadr.bat
```

The helper checks the deployment package and prerequisites, installs the platform Python requirements and locked frontend dependencies, starts the localhost-only MongoDB runtime, creates the first administrator when no users exist, enables authentication, and reruns deployment preflight. It is safe to run again on an initialized installation; existing users are detected and first-admin bootstrap is skipped.

Validate an initialized workstation with:

```powershell
.\validate_clean_install.bat
```

## 2. Start and sign in

Start the application with:

```powershell
.\start_elevadr.bat
```

The launcher starts the local backend on `127.0.0.1:8765` and the Vite frontend on `127.0.0.1:5173`. The backend loads `.elevadr-platform.env`, reports the Zeek runtime, and reports whether authentication, report persistence, and PCAP retention are enabled.

Open `http://127.0.0.1:5173/` and sign in with an eleVADR account.

Do not commit or share `.elevadr-platform.env`. It contains local MongoDB credentials and the JWT signing secret.

## 3. Roles

The backend enforces the role boundary; hiding a frontend control is not the security boundary.

| Capability | Admin | Analyst | Read Only |
| --- | :---: | :---: | :---: |
| View/open own saved reports | Yes | Yes | Yes |
| View retained PCAP metadata | Yes | Yes | Yes |
| Upload/analyze PCAP | Yes | Yes | No |
| Re-analyze retained PCAP | Yes | Yes | No |
| Change Analysis Context/modules | Yes | Yes | No |
| Rename/delete own reports | Yes | Yes | No |
| Delete retained PCAP | Yes | Yes | No |
| Change own password | Yes | Yes | Yes |
| Manage users/roles | Yes | No | No |

New accounts and password changes require passwords of at least 12 characters. Existing accounts created under the older minimum remain able to authenticate until their password is changed.

## 4. Analyze a PCAP

Use the Dashboard/PCAP workflow to choose a packet capture. eleVADR performs context discovery, lets the analyst review Detection Context and module choices, and then runs the analysis. Zeek evidence from discovery is reused for the analysis path rather than deliberately rerunning Zeek for the same evidence lifecycle.

A completed authenticated analysis produces an immutable report and associates it with the retained capture when applicable.

The default PCAP upload ceiling is 256 MiB. Operators can change it with `ELEVADR_MAX_PCAP_UPLOAD_MB` in `.elevadr-platform.env` when a site requires a different bound.

## 5. Detection Context profiles

Detection Context profiles preserve reusable analyst configuration separately from immutable report snapshots.

Authenticated profiles are owner-scoped and persisted with the user's platform data. Existing browser-local profiles are migrated when appropriate. Saving, applying, or deleting a profile does not rewrite the Detection Context snapshot already embedded in a completed report.

Read-only users can view/apply permitted profile data but cannot perform protected profile mutations.

## 6. Saved reports

The Reports workspace lists the signed-in user's persisted reports. Operators can search, sort, open, rename, and (when their role permits) delete reports.

Report JSON is stored under:

```text
storage/users/<user-id>/reports/
```

MongoDB stores the owner-scoped metadata/index. Cross-user object access is not disclosed.

Deleting or expiring a retained PCAP does not delete its saved reports.

## 7. Retained PCAPs, history, and comparison

Retained captures are stored under:

```text
storage/users/<user-id>/pcaps/
```

Identical captures are deduplicated per user by SHA-256. The PCAP workspace can re-analyze a retained capture without another browser upload.

Analysis History groups reports associated with a retained capture. When two reports from the same history are selected, Report Comparison can show new/resolved/changed findings, severity/confidence transitions, Analysis Context differences, module configuration changes, inventory differences, and relevant runtime metadata without modifying either source report.

## 8. Dashboard and activity

The signed-in workspace is organized around Dashboard, Reports, PCAPs, Activity/Audit, Storage, and Account/Users views.

Audit history records security and platform actions using bounded, sanitized metadata. Password-, token-, secret-, authorization-, credential-, and raw-PCAP-like fields are redacted. Normal users see their own recent activity; administrators can access the broader audit view.

Audit events are retained in MongoDB according to the platform's audit retention policy.

## 9. Storage and retention

The Storage view reports retained-PCAP and saved-report usage. Administrators can inspect per-user storage and run cleanup operations.

Important settings include:

```text
ELEVADR_PCAP_RETENTION_DAYS=0
ELEVADR_PCAP_STORAGE_LIMIT_GB=0
```

A value of `0` disables automatic expiry or quota enforcement respectively. Expiring or deleting a PCAP never deletes its saved reports. Orphan cleanup is constrained to retained-PCAP storage and does not remove report JSON.

## 10. User administration

Administrators can create users, assign Admin/Analyst/Read Only roles, and enable or disable accounts. Administrators cannot disable their own currently authenticated account through the normal administration path.

Password changes invalidate existing sessions for that account. Disabled accounts and role changes are resolved against MongoDB rather than trusting an old JWT until expiration.

Login failures are throttled with bounded per-account/per-client windows; eleVADR does not use permanent automatic account lockout.

## 11. Backup and restore

Create a platform backup with:

```powershell
.\backup_elevadr.bat
```

Backups include MongoDB platform documents and `storage/users/` so metadata and retained files move together. JWT/MongoDB secrets, browser sessions, Docker internals, and temporary analysis files are excluded.

By default, backup archives are not encrypted and should be protected as sensitive data. To create an encrypted backup, set `ELEVADR_BACKUP_PASSPHRASE` in the process/environment used for backup. Encrypted backups use the platform's authenticated encryption format and require the same passphrase for validation and restore.

Validate a backup without changing local state:

```powershell
.\validate_elevadr_backup.bat <backup-file>
```

Before restore, stop the eleVADR backend so users cannot mutate platform state, but leave MongoDB running. Restore is destructive and requires explicit acknowledgement:

```powershell
.\restore_elevadr.bat <backup-file> --yes
```

After restore, restart eleVADR and run the platform regression gate.

## 12. Health and regression checks

For a quick platform/security check:

```powershell
.\run_platform_regression_tests.bat
```

For the complete detector, PCAP, UI, compatibility, performance, and platform regression gate:

```powershell
.\run_regression_tests.bat
```

For deployment validation on an initialized workstation:

```powershell
.\validate_clean_install.bat
```

The backend also exposes a local health endpoint at `http://127.0.0.1:8765/health`.

## 13. Common troubleshooting

### MongoDB is unavailable

Run the database health helper and ensure Docker Desktop is running:

```powershell
.\check_elevadr_database.bat
```

If needed, start the local database with `start_elevadr_database.bat` or rerun `setup_elevadr_database.bat`. Do not use `docker compose down -v` unless the intent is to destroy the MongoDB volume.

### Authentication reports disabled or missing secrets

Confirm `.elevadr-platform.env` exists and restart through `start_elevadr.bat` so the backend environment loader reads it. Do not paste the JWT or MongoDB secrets into support logs.

### PCAP analysis cannot run

Confirm Docker is running and that the Zeek image/runtime reported by startup is available. JSON report viewing can still work when Zeek is unavailable, but PCAP discovery/analysis cannot.

### Browser reports `Failed to fetch`

Confirm the backend is running on port 8765 and the frontend on 5173. The default CORS allowlist permits the local frontend origins `http://127.0.0.1:5173` and `http://localhost:5173`; custom deployments must set `ELEVADR_CORS_ORIGINS` accordingly.

### A PCAP is rejected as too large

The default limit is 256 MiB. Adjust `ELEVADR_MAX_PCAP_UPLOAD_MB` deliberately rather than removing the bound.

### Backup validation fails

Do not restore the archive. A validation failure can indicate a missing/modified member, invalid manifest, unsafe path, wrong encryption passphrase, or corrupted BSON/storage payload. Create a new backup or investigate the failed archive first.

## 14. Security-sensitive configuration

The example platform configuration documents supported settings without real secrets. Common settings include:

```text
ELEVADR_AUTH_ENABLED=true
ELEVADR_JWT_EXPIRE_MINUTES=60
ELEVADR_CORS_ORIGINS=http://127.0.0.1:5173,http://localhost:5173
ELEVADR_MAX_PCAP_UPLOAD_MB=256
ELEVADR_PCAP_RETENTION_DAYS=0
ELEVADR_PCAP_STORAGE_LIMIT_GB=0
ELEVADR_BACKUP_PASSPHRASE=
```

Keep real secrets out of source control, release packages, screenshots, logs, and support transcripts.
