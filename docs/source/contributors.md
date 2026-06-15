# Development Environment Setup #

To eliminate configuration drift and avoid complex manual toolchain installations,
the eleVADR repository provides a fully integrated VS Code Dev Container.

## Dev Container Architecture ##

The continuous integration environment is declared in `.devcontainer/Dockerfile.dev`
and managed through `devcontainer.json`. The environment features:

* **Base Layer:** Ubuntu 26.04 (LTS)
* **Default Shell:** Bash 5.2+ (configured with UTF-8 locale handling)
* **Core Toolchains:**
  * **Zeek 8.0.5:** Built and surgeon-copied along with
  required `libnode.so` and `libicu` libraries.
  * **Python 3.14:** Managed via `uv` package manager.
  * **Node 22 (LTS):** Managed via `pnpm` workspace tools.
  * **Rust Toolchain:** Stable release for compiling native modules.

---

## Workspace Initialization ##

Follow these steps to initialize your VS Code environment:

1. Clone the repository to your host machine.
2. Open the repository directory in VS Code.
3. When prompted, select **Reopen in Container**. If the prompt does not appear,
open the command palette (`Ctrl+Shift+P`) and choose
`Dev Containers: Rebuild and Reopen in Container`.
4. The environment's post-creation script (`post-create.sh`) automatically executes
to run the following initializations:
   * Sets local Git configurations.
   * Installs python backend environments via `uv sync`.
   * Installs frontend node dependencies via `pnpm install`.
   * Installs pre-commit testing framework.

---

## Quality Assurance & Formatting ##

eleVADR maintains strict quality checks. All pull requests are evaluated against
linting and security scanners using a pre-commit hook framework.

To execute standard lints, formatting, and type checks manually:

```bash
pre-commit run --all-files
```

The hook pipeline executes the following checks:

* **Python:** Ruff (formatting and lint), mypy (static type audits), bandit
(security scanning), deptry (dependency audits).
* **TypeScript:** ESLint (React code checking), `tsc --noEmit` (TypeScript
compilation checks).
* **Configuration:** yamllint (YAML files), codespell (typo checks).

---

## Running Component Test Suites ##

Test pipelines are decoupled to allow execution within individual components.

### 1. Backend Python Tests ###

The backend test suite is powered by `pytest` and processes mock analytical inputs.
To execute tests:

```bash
cd backend
uv run pytest
```

### 2. Frontend React Tests ###

The frontend test suite is powered by `vitest` and operates in an emulated DOM
environment (`jsdom`). To execute tests:

```bash
cd frontend
pnpm run test
```

### 3. Building Documentation ###

This documentation lives in `docs/`. To build the documentation:

```bash
# First, we need to install the docs dependencies.
uv sync --group docs --directory backend/

# Then, we need to install the backend for the source to be importable
uv pip install -e ./backend

# Finally we can build the docs
sphinx-build -b html docs/source docs/_build/html

# To access them locally, you can juse start a server
python -m http.server --directory docs/_build/html 8010
```
