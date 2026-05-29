# Contributing to EleVADR #

We're glad you're thinking about contributing to this project.
Whether you are reporting a bug, suggesting a feature, or
submitting a code change, we appreciate your help.

Before contributing, please read the [LICENSE](LICENSE) and
[README](README.md).

## How to Contribute ##

EleVADR is an open-source project, and we welcome community
contributions. Here is the recommended workflow:

### 1. Track the Work ###

Submit bug reports or feature requests through the
[issue tracker](https://github.com/cisagov/elevadr-web-backend/issues)
or [discussions](https://github.com/cisagov/elevadr-web-backend/discussions)
on GitHub. For complex ideas, discuss them in an issue before
implementation so there is agreement on direction.

### 2. Create a Fork and Branch ###

Make changes on a personal fork of the repository. Use descriptive
branch names such as `fix/slow-analysis-processing` or
`feat/new-ot-protocol`.

### 3. Commit with Conventional Commits ###

We follow the
[Conventional Commits](https://www.conventionalcommits.org/)
specification. This helps automate changelogs and versioning.

**Format:** `<type>(optional-scope): <description>`

**Common Types:**

- `feat`: A new feature
- `fix`: A bug fix
- `docs`: Documentation changes
- `style`: Formatting or similar changes with no code impact
- `refactor`: A code change that neither fixes a bug nor adds a feature
- `perf`: A code change that improves performance
- `test`: Adding missing tests or correcting existing tests
- `ci`: Changes to CI configuration files and scripts
- `chore`: Other changes that do not modify source or test files
- `sec`: Changes that impact system security

### 4. Lint, Format, and Test ###

Ensure your code is clean and functional before submitting.

- **Format and lint:** If you are in the Dev Container,
  `pre-commit` handles this automatically. To run it manually:

  ```bash
  pre-commit run --all-files
  ```

- **Test:** Run the test suite to ensure there are no regressions:

  ```bash
  pytest
  ```

### 5. Document Your Changes ###

If your change introduces a feature or modifies existing behavior,
update the documentation. Documentation drifts quickly, so we place a
high emphasis on keeping the `/docs` folder and the README current.

### 6. Submit a Pull Request (PR) ###

Follow the PR template. If your code is not ready for merge but you
want feedback, open the PR as a **Draft** so maintainers know the work
is still in progress.

---

## Development Environment ##

To avoid "it works on my machine" issues and the complexity of local
setup, all development should happen inside the VS Code Dev Container.

### Dev Container Setup ###

1. Open the repository in **VS Code**.
1. Click **Reopen in Container** when prompted, or run
   `Ctrl+Shift+P` and select
   `Dev Containers: Rebuild and Reopen in Container`.

### Tooling inside the Container ###

- **Package management:** We use [`uv`](https://github.com/astral-sh/uv).
  - Use `uv sync` to update dependencies.
  - Use `uv run <command>` to execute scripts in the environment.
- **Git hooks:** Run `pre-commit install` once inside the container to
  enable automatic linting on every commit.

### Manual Setup (Not Recommended) ###

If you cannot use Dev Containers, you can set up the environment
manually. You are responsible for installing system-level dependencies
such as Zeek and libpcap, which can be difficult across operating
systems.

#### 1. System Dependencies ####

Install the following on your host machine before proceeding:

- **Python 3.14+**
- **Zeek 8.0.5** in your system `PATH`
- **libpcap** for Zeek PCAP support
- **`uv`** as the Python package manager
  - Install with:
    `curl -LsSf https://astral.sh/uv/install.sh | sh`

#### 2. Clone and Configure ####

```bash
# Clone the repository
git clone https://github.com/cisagov/elevadr-web-backend.git
cd elevadr-web-backend

# Install dependencies using uv
uv sync
```

#### 3. Setup Git Hooks ####

To ensure your code passes CI, install the pre-commit hooks:

```bash
uv run pre-commit install
```

#### 4. Validation ####

Verify that the environment is working by running the tests:

```bash
uv run pytest
```

**Common Manual Setup Issues:**

- **Zeek path:** If `pytest` fails with a "Zeek not found" error,
  ensure `/opt/zeek/bin` or your install path is included in `PATH`.
- **Library mismatches:** If you encounter `ImportError` related to
  `libpcap` or `libmaxminddb`, install the appropriate development
  headers through your package manager.

---

## PR Review Guidelines ##

Maintainers review all changes through the lens of critical
infrastructure safety. Because EleVADR is deployed on sensitive OT
networks, we prioritize:

1. **Trustworthiness:** Scrutinize changes for backdoors or malicious
   logic, especially from new contributors.
1. **Correctness:** Ensure changes use the correct internal APIs, such as
   `utils` for file I/O rather than raw Python calls.
1. **Stability:** Treat changes to core data models in
   `src/app/data/` as high risk because they can affect every module.

---

## Public Domain ##

This project is in the public domain within the United States, and
copyright and related rights in the work worldwide are waived through
the [CC0 1.0 Universal public domain dedication](https://creativecommons.org/publicdomain/zero/1.0/).

All contributions to this project will be released under the CC0
 dedication. By submitting a pull request, you agree to comply with
this waiver of copyright interest.
