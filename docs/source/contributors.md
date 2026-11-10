# Development Environment Setup #

eleVADR is developed directly on the host — there is no container-based
development environment. You need Zeek 8.0.5+, Node 22.22.3+, and
Python 3.12+ installed locally.

## Workspace Initialization ##

1. Clone the repository to your host machine.
2. Install backend dependencies:

   ```bash
   pip install -r backend/requirements-platform.txt
   ```

3. Install frontend dependencies. To run the local platform, use
   `first_run_elevadr.bat` (see [Install](install.md)), which installs
   from `package-lock.json` with npm:

   ```bash
   cd frontend
   npm ci
   ```

   CI and the documentation build use pnpm and `pnpm-lock.yaml`. If you
   need to match them, run `pnpm install` instead. Do not mix the two
   installers in the same `node_modules` folder.

4. Install the pre-commit hook framework:

   ```bash
   pip install pre-commit
   pre-commit install
   ```

---

## Quality Assurance & Formatting ##

eleVADR maintains strict quality checks. All pull requests are evaluated against
linting and security scanners using a pre-commit hook framework.

To execute standard lints, formatting, and type checks manually:

```bash
pre-commit run --all-files
```

The hook pipeline executes the following checks:

* **TypeScript:** ESLint (React code checking), `tsc --noEmit` (TypeScript
compilation checks).
* **Configuration:** yamllint (YAML files), codespell (typo checks), Docker
Compose validation, text-encoding validation.
* **General:** markdownlint, Prettier, shfmt/shellcheck, conventional commit
messages.

---

## Running Component Test Suites ##

Test pipelines are decoupled to allow execution within individual components.

### 1. Backend Python Tests ###

The backend test suite is powered by `pytest` and processes mock analytical inputs.
To execute tests (from the repository root, so the `backend` package resolves):

```bash
pip install -r backend/requirements-platform.txt
python -m pytest backend/tests
```

### 2. Frontend React Tests ###

The frontend test suite is powered by `vitest` and operates in an emulated DOM
environment (`jsdom`). To execute tests:

```bash
cd frontend
npm run test
```

### 3. Building Documentation ###

This documentation lives in `docs/`. To build the documentation:

```bash
# First, we need to install the docs dependencies.
pip install -r docs/requirements.txt

# Finally we can build the docs
sphinx-build -b html docs/source docs/_build/html

# To access them locally, you can just start a server
python -m http.server --directory docs/_build/html 8010
```
