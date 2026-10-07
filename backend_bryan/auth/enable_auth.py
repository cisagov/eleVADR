"""Enable authentication in the generated local platform environment file."""
from __future__ import annotations
from pathlib import Path
from .local_runtime import ENV_PATH

def main() -> int:
    path = Path(ENV_PATH)
    if not path.is_file():
        print("ERROR: .elevadr-platform.env does not exist; run setup_elevadr_database.bat first")
        return 1
    lines = path.read_text(encoding="utf-8").splitlines()
    out: list[str] = []
    found = False
    for line in lines:
        if line.startswith("ELEVADR_AUTH_ENABLED="):
            out.append("ELEVADR_AUTH_ENABLED=true")
            found = True
        else:
            out.append(line)
    if not found:
        out.append("ELEVADR_AUTH_ENABLED=true")
    path.write_text("\n".join(out) + "\n", encoding="utf-8")
    print("Authentication enabled in .elevadr-platform.env")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
