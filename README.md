# EleVADR - OT Network Security Analysis Tool #

[![Latest Release](https://img.shields.io/github/v/release/cisagov/eleVADR?include_prereleases&sort=semver)](https://github.com/cisagov/eleVADR/releases)
![License: CC0](https://img.shields.io/badge/License-CC0-lightgrey.svg)
[![React Version](https://img.shields.io/badge/dynamic/json?url=https://raw.githubusercontent.com/cisagov/eleVADR/HEAD/frontend/package.json&query=$.dependencies.react&label=React&color=blue)](https://github.com/cisagov/eleVADR/blob/HEAD/frontend/package.json)
[![Frontend Build](https://github.com/cisagov/eleVADR/actions/workflows/build-frontend.yml/badge.svg?branch=develop)](https://github.com/cisagov/eleVADR/actions/workflows/build-frontend.yml)
[![CodeQL Status](https://github.com/cisagov/eleVADR/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/cisagov/eleVADR/actions/workflows/codeql-analysis.yml)
[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)](https://github.com/pre-commit/pre-commit)

EleVADR is a specialized network security analysis engine developed
for the Cybersecurity and Infrastructure Security Agency (CISA). It is
designed to assess Operational Technology (OT) systems by transforming
raw PCAP traffic into actionable security intelligence.

This repository contains both the Python/Zeek backend analysis engine
and the React/TypeScript frontend dashboard.

Advanced operational documentation can be found on our
[GitHub Pages site][docs-url].

---

## Local Windows Platform Quickstart ##

The supported workflow is the local authenticated platform on Windows.
The backend and frontend run directly on the workstation, and Docker
Desktop hosts the localhost-only MongoDB database (and Zeek, when it is
not installed natively).

### Prerequisites ###

- Git
- Python 3.12+ (available as `python`)
- Node.js 22.22.3+ within the Node 22 line (Node 23+ is rejected), with npm
- Docker Desktop, with the engine running

Zeek 8.0.5+ is optional. Without a native Zeek on `PATH`, eleVADR runs
the `zeek/zeek:9.0.0` Docker image.

### Fresh clone setup ###

Clone into a short path outside cloud-synced folders such as OneDrive,
which can disrupt `node_modules` installs. Then run first-run setup once
and start the app:

```powershell
git clone https://github.com/cisagov/eleVADR.git C:\dev\eleVADR
cd C:\dev\eleVADR
.\first_run_elevadr.bat
.\prepare_zeek_runtime.bat   # optional: pre-pull the Zeek image
.\start_elevadr.bat
```

Open `http://127.0.0.1:5173/` and sign in with the administrator
account created during first run.

`first_run_elevadr.bat` stops at the first failure. It:

1. Runs the deployment preflight (Python, Node, npm, Docker, package files).
2. Installs `backend/requirements-platform.txt` with `pip`.
3. Installs the frontend from `package-lock.json` with `npm ci`.
4. Generates `.elevadr-platform.env` (random MongoDB credentials and JWT
   secret), starts MongoDB, and waits until it is healthy.
5. Prompts for the first administrator (password of 12+ characters)
   when no users exist.
6. Enables authentication and reruns the preflight.

It is safe to rerun on an initialized installation.

### What a fresh clone does not contain ###

These are created on each machine and are intentionally not in git:

- `.elevadr-platform.env`: generated during first run. It holds secrets,
  so never commit it or copy it between machines. See
  `.elevadr-platform.env.example` for the supported settings.
- `frontend/node_modules/` and the installed Python packages: recreated by
  first-run setup.
- MongoDB data (Docker volume `elevadr-mongodb-data`) and `storage/`
  (retained PCAPs and saved report JSON): empty on a new clone. Use
  `backup_elevadr.bat` and `restore_elevadr.bat` to carry them over.

### Daily use ###

| Task | Command |
| --- | --- |
| Start or restart the backend and frontend | `.\start_elevadr.bat` |
| Stop the backend and frontend | `.\stop_elevadr.bat` |
| Start the database (not started by `start_elevadr.bat`) | `.\start_elevadr_database.bat` |
| Stop the database (data is preserved) | `.\stop_elevadr_database.bat` |
| Validate an initialized workstation | `.\validate_clean_install.bat` |

The backend listens on `127.0.0.1:8765` and the frontend on
`127.0.0.1:5173`. Never run `docker compose down -v`, which deletes the
MongoDB volume.

See [Install](docs/source/install.md) for full setup, backup/restore, and
troubleshooting, and the [Operator Guide](docs/source/operator-guide.md)
for operation, administration, security settings, and recovery.

---

## Repository Structure ##

The repository is structured as a monorepo containing the following
primary directories:

- **.github/**: Workflows for CI/CD, binary building, and releases.
- **backend/**: Python backend — detector module registry, auth, Detection Context compiler, and Zeek integration.
- **frontend/**: React dashboard built with Vite.
- **docs/**: Sphinx documentation source.
- **sample_data/**: Sample eleVADR reports and Detection Context files (JSON).
- **docker-compose.yml** and **docker-compose.mongodb.yml**: Local MongoDB service definitions used by the helper scripts.
- **\*.bat**: Windows helper scripts for setup, start/stop, backup/restore, and validation.

---

## Running the Complete App ##

`docker compose up -d` starts only the local MongoDB service; the backend
and frontend run directly on the host. Use the helper scripts rather than
calling `docker compose` yourself (they pass the generated
`.elevadr-platform.env`). See the
[Local Windows Platform Quickstart](#local-windows-platform-quickstart)
above for the full startup sequence.

---

## Development Environment ##

eleVADR is developed directly on the host. You must manually install
Zeek 8.0.5+, Node 22.22.3+, and Python 3.12+.

- **Backend Setup:**

  ```bash
  pip install -r backend/requirements-platform.txt
  ```

- **Frontend Setup:**

  ```bash
  cd frontend
  npm ci
  ```

  CI and the documentation build use pnpm and `pnpm-lock.yaml`. Use pnpm
  only if you need to match them, and do not mix installers in one
  `node_modules` folder.

---

## Testing & Quality Assurance ##

### Code Standards ###

Linting and formatting run automatically on commit once you've installed
the pre-commit hooks (`pre-commit install`). To run these validation
checks manually:

```bash
pre-commit run --all-files
```

### Running Tests ###

Test suites are separated by component:

- **Backend Tests:**

  ```bash
  python -m pytest backend/tests
  ```

- **Frontend Tests:**

  ```bash
  cd frontend
  npm test
  ```

---

### Building Docs ###

Build the documentation locally with:

```bash
# First, we need to install the docs dependencies. #
pip install -r docs/requirements.txt

# Finally we can build the docs #
sphinx-build -b html docs/source docs/_build/html

# To access them locally, you can just start a server #
python -m http.server --directory docs/_build/html 8010
```

### Finding provenance ###

Detector findings now include Zeek-record provenance (`log_type`, parsed `record_index`, and supporting field/value pairs). See `backend/reference/finding_provenance.md`.

### Dataset 19: multi-hour OT site simulation ###

The regression pack now includes Dataset 19, a deterministic four-hour site-like OT PCAP intended to measure false-positive behavior across the complete 75-detector registry. The full regression gate runs it after Datasets 15-17. Its normal traffic is explicitly represented in Detection Context policy, while two late deliberate anomalies verify that the site-like workload remains quiet except for the reviewed expected modules.

## Release-readiness preflight ##

Before running the full regression suite, you can run the fast release invariant check:

```bash
python -m backend.integration.release_preflight
```

The full `run_regression_tests.bat` gate runs this automatically as stage 1. The local reference backend also exposes `GET http://127.0.0.1:8765/health` for detector/contract/Zeek-runtime diagnostics.

## Release-candidate package validation ##

The release-readiness checklist is in `backend/reference/release_readiness.md`,
and clean-machine steps are in `backend/reference/clean_machine_deployment.md`.
After extracting a release/upload bundle into a clean directory, run
`run_release_candidate_validation.bat`. The default clean mode validates
package integrity, toolchain compatibility, release invariants, an isolated
frontend install/build/test, and a raw-PCAP smoke analysis when Zeek is
available. Add `--full` to run the complete regression gate as well.

---

## Public Domain ##

This project is in the public domain within the United States, and
copyright and related rights in the work worldwide are waived through
the [CC0 1.0 Universal public domain dedication][cc0-url].

[docs-url]: https://cisagov.github.io/eleVADR
[cc0-url]: https://creativecommons.org/publicdomain/zero/1.0/
