# EleVADR - OT Network Security Analysis Tool #

[![Latest Release](https://img.shields.io/github/v/release/cisagov/eleVADR?include_prereleases&sort=semver)](https://github.com/cisagov/eleVADR/releases)
![License: CC0](https://img.shields.io/badge/License-CC0-lightgrey.svg)
[![Python Version](https://img.shields.io/badge/dynamic/toml?url=https://raw.githubusercontent.com/cisagov/eleVADR/HEAD/backend/pyproject.toml&query=$.project.requires-python&label=Python&color=blue)](https://github.com/cisagov/eleVADR/blob/HEAD/backend/pyproject.toml)
[![React Version](https://img.shields.io/badge/dynamic/json?url=https://raw.githubusercontent.com/cisagov/eleVADR/HEAD/frontend/package.json&query=$.dependencies.react&label=React&color=blue)](https://github.com/cisagov/eleVADR/blob/HEAD/frontend/package.json)
[![Backend Build](https://github.com/cisagov/eleVADR/actions/workflows/build-backend.yml/badge.svg?branch=develop)](https://github.com/cisagov/eleVADR/actions/workflows/build-backend.yml)
[![Frontend Build](https://github.com/cisagov/eleVADR/actions/workflows/build-frontend.yml/badge.svg?branch=develop)](https://github.com/cisagov/eleVADR/actions/workflows/build-frontend.yml)
[![CodeQL Status](https://github.com/cisagov/eleVADR/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/cisagov/eleVADR/actions/workflows/codeql-analysis.yml)
[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)](https://github.com/pre-commit/pre-commit)
[![Open in Dev Containers](https://img.shields.io/static/v1?label=Dev%20Containers&message=Open&color=blue)](https://vscode.dev/redirect?url=vscode://ms-vscode-remote.remote-containers/cloneInVolume?url=https://github.com/cisagov/eleVADR)

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

The current local authenticated platform workflow uses Python 3.12+, Node.js 22.22.3+ (Node 22), npm, and Docker Desktop. From a clean extracted package, run:

```powershell
.\first_run_elevadr.bat
.\start_elevadr.bat
```

`first_run_elevadr.bat` validates prerequisites, installs locked dependencies, initializes the localhost-only MongoDB runtime, creates the first administrator when needed, and enables authentication. The application then provides owner-scoped saved reports and retained PCAPs, re-analysis/history/comparison, roles, audit history, storage/retention controls, and backup/restore.

See the [Operator Guide](docs/source/operator-guide.md) for daily operation, administration, security settings, troubleshooting, and recovery. Validate an installed workstation with `validate_clean_install.bat`.

For the current local workflow, use npm commands from the supplied lockfile; older pnpm-oriented development instructions below apply to the upstream/container development environment and not to this local platform launcher.

## Repository Structure ##

The repository is structured as a monorepo containing the following
primary directories:

- **.devcontainer/**: Configuration files for the VS Code Dev Container.
- **.github/**: Workflows for CI/CD, binary building, and releases.
- **backend/**: Python FastAPI backend, Pandas code, and Zeek scripts.
- **frontend/**: React dashboard managed with pnpm and built with Vite.
- **docker-compose.yml**: Local multi-service orchestration file.

---

## Running the Complete App ##

To start both the backend API and the frontend dashboard locally, use
the local container orchestration:

```bash
docker compose up --build
```

Once running:

- **Frontend Dashboard:** Accessible at `http://localhost:8080`
- **Backend API:** Accessible at `http://localhost:8000` (but there
is no reason to interact directly)

---

## Development Environment ##

To avoid local dependency drift, all development should happen inside
containers.

### 1. VS Code Dev Containers (Recommended) ###

- **Step 1:** Open the repository directory in **VS Code**.
- **Step 2:** Click **Reopen in Container** when prompted.
- **Step 3:** If the prompt does not appear, press `Ctrl+Shift+P` and
  choose `Dev Containers: Rebuild and Reopen in Container`.

All necessary tools including `zeek`, `uv`, `pnpm`, and linting utilities
are pre-configured inside the environment.

### 2. Manual Host Setup (Alternative) ###

If you cannot use Dev Containers, you must manually install Zeek 8.0.5+,
Node 22+, and Python 3.14+.

- **Backend Setup:**

  ```bash
  cd backend
  uv sync
  ```

- **Frontend Setup:**

  ```bash
  cd frontend
  pnpm install
  ```

---

## Testing & Quality Assurance ##

### Code Standards ###

Linting, formatting, and security analysis are run automatically on
commit when developing inside the Dev Container. To run these validation
checks manually:

```bash
pre-commit run --all-files
```

### Running Tests ###

Test suites are separated by component:

- **Backend Tests:**

  ```bash
  cd backend
  uv run pytest
  ```

- **Frontend Tests:**

  ```bash
  cd frontend
  pnpm test
  ```

---

### Building Docs ###

Build the documentation locally with:

```bash
# First, we need to install the docs dependencies. #
uv sync --group docs --directory backend/

# Then, we need to install the backend for the source to be importable #
uv pip install -e ./backend

# Finally we can build the docs #
sphinx-build -b html docs/source docs/_build/html

# To access them locally, you can just start a server #
python -m http.server --directory docs/_build/html 8010
```

## Public Domain ##

This project is in the public domain within the United States, and
copyright and related rights in the work worldwide are waived through
the [CC0 1.0 Universal public domain dedication][cc0-url].

[docs-url]: https://cisagov.github.io/eleVADR
[cc0-url]: https://creativecommons.org/publicdomain/zero/1.0/

### Finding provenance ###

Detector findings now include Zeek-record provenance (`log_type`, parsed `record_index`, and supporting field/value pairs). See `backend_bryan/reference/finding_provenance.md`.

### Dataset 19: multi-hour OT site simulation ###

The regression pack now includes Dataset 19, a deterministic four-hour site-like OT PCAP intended to measure false-positive behavior across the complete 75-detector registry. The full regression gate runs it after Datasets 15-17. Its normal traffic is explicitly represented in Detection Context policy, while two late deliberate anomalies verify that the site-like workload remains quiet except for the reviewed expected modules.

## Release-readiness preflight ##

Before running the full regression suite, you can run the fast release invariant check:

```bash
python -m backend_bryan.integration.release_preflight
```

The full `run_regression_tests.bat` / `run_regression_tests.sh` gate runs this automatically as stage 1. The local reference backend also exposes `GET http://127.0.0.1:8765/health` for detector/contract/Zeek-runtime diagnostics.

## Release-candidate package validation ##

The known-good release checkpoint and clean-package gate are documented in
`RELEASE_CANDIDATE_CHECKPOINT.md`. After extracting a release/upload bundle into
a clean directory, run `run_release_candidate_validation.bat` on Windows or
`run_release_candidate_validation.sh` on Linux/macOS. The default clean mode
validates package integrity, toolchain compatibility, release invariants, an
isolated frontend install/build/test, and a raw-PCAP smoke analysis when Zeek is
available. Add `--full` to run the complete regression gate as well.
