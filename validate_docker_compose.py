from __future__ import annotations

import subprocess
import sys

COMPOSE_FILES = (
    "docker-compose.yml",
    "docker-compose.mongodb.yml",
)


def main() -> int:
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
        )

        if result.returncode != 0:
            return result.returncode

    return 0


if __name__ == "__main__":
    sys.exit(main())
