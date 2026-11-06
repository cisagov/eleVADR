"""Run an eleVADR Python module after loading the local platform environment.

This keeps generated MongoDB/JWT secrets out of batch command lines and avoids
cmd.exe parsing problems with connection strings. Existing process environment
file is authoritative for local launcher runs; CI without the file continues to use process settings.
"""
from __future__ import annotations

import argparse
import os
import runpy
import sys
from pathlib import Path

from .local_runtime import ENV_PATH, load_env


def apply_platform_env(path: Path = ENV_PATH, *, override: bool = True) -> bool:
    if not path.is_file():
        return False
    for key, value in load_env(path).items():
        if override or key not in os.environ:
            os.environ[key] = value
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a module with eleVADR platform configuration")
    parser.add_argument("module", help="Python module to execute")
    parser.add_argument("args", nargs=argparse.REMAINDER)
    ns = parser.parse_args()
    loaded = apply_platform_env()
    print(f"Platform environment: {'loaded' if loaded else 'not present (using process/default settings)'}")
    sys.argv = [ns.module, *ns.args]
    try:
        runpy.run_module(ns.module, run_name="__main__", alter_sys=False)
    except SystemExit as exc:
        code = exc.code
        if code is None:
            return 0
        if isinstance(code, int):
            return code
        print(code)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
