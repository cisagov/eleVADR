from __future__ import annotations

import sys
from pathlib import Path

ROOTS = (
    Path("frontend"),
    Path("backend"),
    Path("backend_bryan"),
    Path("docs"),
    Path("elevadr_app_regression_test_pack"),
)

EXCLUDED_DIRS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "coverage",
    "dist",
    "build",
    "node_modules",
}

TEXT_SUFFIXES = {
    ".cjs",
    ".css",
    ".html",
    ".js",
    ".json",
    ".md",
    ".mjs",
    ".py",
    ".ts",
    ".tsx",
    ".txt",
    ".yml",
    ".yaml",
}

# Common signatures produced when UTF-8 text is decoded incorrectly and
# subsequently written back as Windows-1252/Latin-1-like text.
SUSPICIOUS = (
    "\u00c3",       # capital A with tilde
    "\u00c2",       # capital A with circumflex
    "\u00e2\u20ac", # common corrupted UTF-8 punctuation prefix
    "\u00e2\u2020", # common corrupted UTF-8 arrow prefix
    "\u00f0\u0178", # common corrupted UTF-8 emoji prefix
    "\ufffd",       # Unicode replacement character
)


def excluded(path: Path) -> bool:
    return any(part in EXCLUDED_DIRS for part in path.parts)


def main() -> int:
    findings: list[tuple[Path, int, str]] = []
    invalid_utf8: list[tuple[Path, str]] = []

    for root in ROOTS:
        if not root.exists():
            continue

        for path in root.rglob("*"):
            if (
                not path.is_file()
                or excluded(path)
                or path.suffix.lower() not in TEXT_SUFFIXES
            ):
                continue

            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError as exc:
                invalid_utf8.append((path, str(exc)))
                continue

            for line_number, line in enumerate(text.splitlines(), 1):
                if any(marker in line for marker in SUSPICIOUS):
                    findings.append((path, line_number, line.strip()))

    if invalid_utf8:
        print("Invalid UTF-8 detected in repository text files:", file=sys.stderr)
        for path, error in invalid_utf8:
            print(f"  {path}: {error}", file=sys.stderr)

    if findings:
        print("Possible mojibake/encoding corruption detected:", file=sys.stderr)
        for path, line_number, line in findings:
            print(
                f"  {path}:{line_number}: {line[:160]}",
                file=sys.stderr,
            )

    if invalid_utf8 or findings:
        return 1

    print("No mojibake signatures or invalid UTF-8 detected.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
