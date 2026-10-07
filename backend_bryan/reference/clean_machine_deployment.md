# Clean-machine deployment

For a new Windows workstation, install the supported prerequisites first: Python 3.12+, Node.js 22.22.3 (22.x), and Docker Desktop. Then extract the eleVADR release package and run:

```powershell
.\first_run_elevadr.bat
```

The first-run helper performs prerequisite checks, installs locked frontend dependencies, installs the Python platform dependencies, initializes the localhost-only MongoDB container and persistent volume, prompts for the first administrator account, and enables authentication.

Start eleVADR with:

```powershell
.\start_elevadr.bat
```

Validate an installed deployment with:

```powershell
.\validate_clean_install.bat
```

For release qualification, also run the normal full regression and release-candidate validation gates.

## Persistent state

MongoDB data is held in the Docker volume `elevadr-mongodb-data`. Saved reports and retained PCAPs are under `storage/users/`. Use the eleVADR backup/restore commands rather than copying only one of these locations.

## Secrets

`.elevadr-platform.env` is generated locally and must not be committed or included in release/upload bundles. It contains the MongoDB credential and JWT signing secret.
