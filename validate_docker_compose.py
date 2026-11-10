from __future__ import annotations

import os
import subprocess
import sys

COMPOSE_FILES = (
    "docker-compose.yml",
)

# Compose requires these (${VAR:?...}). Placeholders let the check run without
# a real .elevadr-platform.env.
PLACEHOLDER_ENV = {
    "ELEVADR_MONGO_ROOT_USERNAME": "placeholder",
    "ELEVADR_MONGO_ROOT_PASSWORD": "placeholder",
    "ELEVADR_JWT_SECRET": "placeholder-placeholder-placeholder-00",
}


def main() -> int:
    env = {**PLACEHOLDER_ENV, **os.environ}

    for compose_file in COMPOSE_FILES:
        print(f"Validating {compose_file}...")

        result = subprocess.run(
            [
                "docker",
                "compose",
                "-f",
                compose_file,
                "config",
                "--quiet",
            ],
            check=False,
            env=env,
        )

        if result.returncode != 0:
            return result.returncode

    return 0


if __name__ == "__main__":
    sys.exit(main())
