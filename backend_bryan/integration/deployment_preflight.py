"""Clean-machine prerequisite and deployment checks for eleVADR."""
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REQUIRED_DEPLOYMENT_FILES = (
    "start_elevadr.bat",
    "setup_elevadr_database.bat",
    "create_elevadr_user.bat",
    "docker-compose.mongodb.yml",
    "backend_bryan/requirements-platform.txt",
    "backend_bryan/auth/local_runtime.py",
    "backend_bryan/auth/env_runner.py",
    "frontend/package.json",
    "frontend/package-lock.json",
)

@dataclass(frozen=True, slots=True)
class Check:
    name: str
    status: str
    detail: str

    @property
    def failed(self) -> bool:
        return self.status == "FAIL"


def _tool(name: str, *args: str) -> tuple[bool, str]:
    exe = shutil.which(name)
    if not exe:
        return False, "missing"
    result = subprocess.run([exe, *args], capture_output=True, text=True, check=False)
    first = (result.stdout or result.stderr).strip().splitlines()
    return result.returncode == 0, (first[0] if first else exe)


def collect(*, require_initialized: bool = False) -> list[Check]:
    checks: list[Check] = []
    missing = [p for p in REQUIRED_DEPLOYMENT_FILES if not (ROOT / p).is_file()]
    checks.append(Check("deployment package files", "PASS" if not missing else "FAIL", f"missing={missing or 'none'}"))

    py_ok = sys.version_info >= (3, 12)
    checks.append(Check("Python", "PASS" if py_ok else "FAIL", f"{platform.python_version()} (requires 3.12+)"))

    node_ok, node = _tool("node", "--version")
    if node_ok:
        import re
        m = re.search(r"(\d+)\.(\d+)\.(\d+)", node)
        node_ok = bool(m and (int(m.group(1)), int(m.group(2)), int(m.group(3))) >= (22, 22, 3) and int(m.group(1)) < 23)
    checks.append(Check("Node.js", "PASS" if node_ok else "FAIL", f"{node} (requires ^22.22.3)"))

    npm_ok, npm = _tool("npm", "--version")
    checks.append(Check("npm", "PASS" if npm_ok else "FAIL", npm))

    docker_ok, docker = _tool("docker", "--version")
    if docker_ok:
        info = subprocess.run([shutil.which("docker") or "docker", "info"], capture_output=True, text=True, check=False)
        engine_ok = info.returncode == 0
    else:
        engine_ok = False
    checks.append(Check("Docker", "PASS" if docker_ok and engine_ok else "FAIL", f"{docker}; engine={'running' if engine_ok else 'unavailable'}"))

    env_path = ROOT / ".elevadr-platform.env"
    if require_initialized:
        checks.append(Check("platform configuration", "PASS" if env_path.is_file() else "FAIL", ".elevadr-platform.env present" if env_path.is_file() else "run setup_elevadr_database.bat"))
    else:
        checks.append(Check("platform configuration", "PASS" if env_path.is_file() else "INFO", "already initialized" if env_path.is_file() else "will be created during first-run setup"))

    node_modules = ROOT / "frontend" / "node_modules"
    checks.append(Check("frontend dependencies", "PASS" if node_modules.is_dir() else "INFO", "installed" if node_modules.is_dir() else "first-run setup will run npm ci"))
    return checks


def main() -> int:
    parser = argparse.ArgumentParser(description="Check whether this machine is ready to run eleVADR")
    parser.add_argument("--initialized", action="store_true", help="require completed platform initialization")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    checks = collect(require_initialized=args.initialized)
    failed = [c for c in checks if c.failed]
    if args.json:
        print(json.dumps({"status": "pass" if not failed else "fail", "checks": [asdict(c) for c in checks]}, indent=2))
    else:
        print("eleVADR deployment preflight")
        print("----------------------------")
        for c in checks:
            print(f"{c.status:<4}  {c.name}: {c.detail}")
        print(f"\n{'PASS' if not failed else 'FAIL'}: deployment preflight")
    return 0 if not failed else 1

if __name__ == "__main__":
    raise SystemExit(main())
