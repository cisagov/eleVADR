"""Release-candidate package and clean-install validation for eleVADR.

The gate is intentionally stdlib-only.  It validates the extracted release tree,
checks toolchain compatibility, and can exercise a clean frontend install plus
raw-PCAP analysis without relying on an existing frontend/node_modules tree.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[2]
RC_ID = "elevadr-rc-2026-10-02"
EXPECTED_DETECTORS = 75
ZEEK_IMAGE = "zeek/zeek:9.0.0"

REQUIRED_FILES = (
    "RELEASE_CANDIDATE_CHECKPOINT.md",
    "RELEASE_CANDIDATE_MANIFEST.json",
    "run_release_candidate_validation.bat",
    "run_release_candidate_validation.sh",
    "run_regression_tests.bat",
    "run_regression_tests.sh",
    "start_elevadr.bat",
    "stop_elevadr.bat",
    "backend_bryan/integration/release_preflight.py",
    "backend_bryan/integration/release_candidate_gate.py",
    "backend_bryan/vendor/elevadr_modules/modules/cleartext_credentials.py",
    "backend_bryan/reference/module_registry_snapshot.json",
    "backend_bryan/regression/fixtures/15_new_detector_raw_pcap.pcap",
    "backend_bryan/regression/fixtures/15_new_detector_raw_pcap_context.json",
    "backend_bryan/regression/fixtures/19_site_like_multi_hour_ot.pcap",
    "backend_bryan/regression/fixtures/19_site_like_multi_hour_ot_manifest.json",
    "frontend/package.json",
    "frontend/package-lock.json",
    "frontend/pnpm-lock.yaml",
    "frontend/src/app/App.tsx",
    "frontend/src/tests/NetworkTopologyInteraction.test.tsx",
)

FORBIDDEN_PARTS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".venv",
    "venv",
    "dist",
    "coverage",
}


@dataclass(frozen=True, slots=True)
class Check:
    name: str
    status: str
    detail: str

    @property
    def ok(self) -> bool:
        return self.status in {"PASS", "WARN", "SKIP"}


def _check(name: str, status: str, detail: str) -> Check:
    return Check(name=name, status=status, detail=detail)


def _run(command: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    print("$ " + " ".join(command), flush=True)
    return subprocess.run(command, cwd=cwd, env=env, text=True, check=False)


def _version_tuple(text: str) -> tuple[int, ...]:
    match = re.search(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", text)
    if not match:
        return ()
    return tuple(int(item or 0) for item in match.groups())


def _tool_version(command: str, args: list[str]) -> tuple[str | None, Path | None]:
    resolved = shutil.which(command)
    if not resolved:
        return None, None
    result = subprocess.run([resolved, *args], text=True, capture_output=True, check=False)
    text = (result.stdout or result.stderr).strip().splitlines()
    return (text[0] if text else "unknown"), Path(resolved)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_tree() -> list[Check]:
    missing = [item for item in REQUIRED_FILES if not (ROOT / item).is_file()]
    checks = [
        _check(
            "release tree required files",
            "PASS" if not missing else "FAIL",
            f"required={len(REQUIRED_FILES)} missing={missing or 'none'}",
        )
    ]

    forbidden: list[str] = []
    for path in ROOT.rglob("*"):
        try:
            rel = path.relative_to(ROOT)
        except ValueError:
            continue
        if any(part in FORBIDDEN_PARTS for part in rel.parts):
            forbidden.append(rel.as_posix())
            if len(forbidden) >= 20:
                break
    checks.append(
        _check(
            "package hygiene",
            "PASS" if not forbidden else "FAIL",
            f"forbidden entries={forbidden or 'none'}",
        )
    )

    manifest_path = ROOT / "RELEASE_CANDIDATE_MANIFEST.json"
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        expected = manifest.get("critical_sha256", {})
        mismatches: list[str] = []
        for rel, expected_digest in expected.items():
            path = ROOT / rel
            if not path.is_file():
                mismatches.append(f"{rel}:missing")
            elif _sha256(path) != expected_digest:
                mismatches.append(f"{rel}:sha256")
        checks.append(
            _check(
                "release-candidate critical hashes",
                "PASS" if not mismatches else "FAIL",
                f"checked={len(expected)} mismatches={mismatches or 'none'}",
            )
        )
    else:
        checks.append(_check("release-candidate critical hashes", "FAIL", "manifest missing"))
    return checks


def check_toolchain() -> list[Check]:
    checks: list[Check] = []
    python_version = platform.python_version()
    checks.append(
        _check(
            "reference Python runtime",
            "PASS" if sys.version_info >= (3, 12) else "FAIL",
            f"python={python_version}; regression baseline is Python 3.12+",
        )
    )

    node_text, _ = _tool_version("node", ["--version"])
    node_version = _version_tuple(node_text or "")
    node_ok = node_version >= (22, 22, 3) and node_version < (23, 0, 0)
    checks.append(
        _check(
            "frontend Node runtime",
            "PASS" if node_ok else "FAIL",
            f"node={node_text or 'missing'}; package devEngine requires ^22.22.3",
        )
    )

    npm_text, _ = _tool_version("npm", ["--version"])
    checks.append(_check("npm availability", "PASS" if npm_text else "FAIL", f"npm={npm_text or 'missing'}"))

    docker_text, _ = _tool_version("docker", ["--version"])
    zeek_text, _ = _tool_version("zeek", ["--version"])
    if zeek_text:
        checks.append(_check("Zeek execution runtime", "PASS", f"native Zeek={zeek_text}"))
    elif docker_text:
        info = subprocess.run([shutil.which("docker") or "docker", "info"], capture_output=True, text=True, check=False)
        status = "PASS" if info.returncode == 0 else "WARN"
        detail = f"Docker={docker_text}; engine={'running' if info.returncode == 0 else 'not reachable'}; Zeek fallback={ZEEK_IMAGE}"
        checks.append(_check("Zeek execution runtime", status, detail))
    else:
        checks.append(_check("Zeek execution runtime", "WARN", "native Zeek and Docker are both unavailable; PCAP smoke test will be skipped"))

    pyproject = (ROOT / "backend/pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'requires-python\s*=\s*"([^"]+)"', pyproject)
    declared = match.group(1) if match else "unknown"
    if sys.version_info >= (3, 14):
        status = "PASS"
    else:
        status = "WARN"
    checks.append(
        _check(
            "production backend interpreter declaration",
            status,
            f"backend/pyproject.toml declares {declared}; current={python_version}. The reference backend_bryan regression path is distinct from this package declaration.",
        )
    )
    return checks


def run_preflight() -> Check:
    result = _run([sys.executable, "-m", "backend_bryan.integration.release_preflight"], cwd=ROOT)
    return _check("release-readiness preflight", "PASS" if result.returncode == 0 else "FAIL", f"exit={result.returncode}")


def clean_frontend_validation() -> list[Check]:
    npm = shutil.which("npm")
    if not npm:
        return [_check("clean frontend install/build", "FAIL", "npm is unavailable")]

    with tempfile.TemporaryDirectory(prefix="elevadr-rc-frontend-") as temp_dir:
        temp = Path(temp_dir) / "frontend"
        shutil.copytree(ROOT / "frontend", temp, ignore=shutil.ignore_patterns("node_modules", "dist", "coverage"))
        install = _run([npm, "ci", "--ignore-scripts"], cwd=temp)
        if install.returncode != 0:
            return [_check("clean frontend install", "FAIL", f"npm ci exit={install.returncode}")]
        build = _run([npm, "run", "build"], cwd=temp)
        if build.returncode != 0:
            return [
                _check("clean frontend install", "PASS", "npm ci completed in isolated copy"),
                _check("clean frontend build", "FAIL", f"npm run build exit={build.returncode}"),
            ]
        topology = _run([npm, "test", "--", "src/tests/NetworkTopologyInteraction.test.tsx"], cwd=temp)
        return [
            _check("clean frontend install", "PASS", "npm ci completed in isolated copy"),
            _check("clean frontend build", "PASS", "vite production build completed"),
            _check("clean topology interaction test", "PASS" if topology.returncode == 0 else "FAIL", f"exit={topology.returncode}"),
        ]


def pcap_smoke_validation() -> Check:
    native_zeek = shutil.which("zeek")
    docker = shutil.which("docker")
    if not native_zeek:
        if not docker:
            return _check("raw-PCAP smoke analysis", "SKIP", "no Zeek runtime is available")
        info = subprocess.run([docker, "info"], capture_output=True, text=True, check=False)
        if info.returncode != 0:
            return _check("raw-PCAP smoke analysis", "SKIP", "Docker is installed but the engine is not reachable")
    result = _run([sys.executable, "-m", "backend_bryan.regression.dataset15_runner"], cwd=ROOT)
    return _check("raw-PCAP smoke analysis", "PASS" if result.returncode == 0 else "FAIL", f"Dataset 15 exit={result.returncode}")


def full_regression_validation() -> Check:
    if os.name == "nt":
        command = ["cmd.exe", "/c", "run_regression_tests.bat"]
    else:
        command = ["bash", "run_regression_tests.sh"]
    result = _run(command, cwd=ROOT)
    return _check("full 26-stage regression gate", "PASS" if result.returncode == 0 else "FAIL", f"exit={result.returncode}")


def summarize(checks: Iterable[Check], *, json_output: bool) -> int:
    checks = list(checks)
    failures = [item for item in checks if item.status == "FAIL"]
    if json_output:
        print(json.dumps({"release_candidate": RC_ID, "status": "pass" if not failures else "fail", "checks": [asdict(item) for item in checks]}, indent=2))
    else:
        print("\neleVADR release-candidate validation")
        print("------------------------------------")
        print(f"Checkpoint: {RC_ID}")
        for item in checks:
            print(f"{item.status:<4}  {item.name}: {item.detail}")
        print(f"\n{'PASS' if not failures else 'FAIL'}: {len(checks) - len(failures)}/{len(checks)} checks non-failing ({len(failures)} failure(s)).")
    return 0 if not failures else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate an extracted eleVADR release candidate")
    parser.add_argument("--clean", action="store_true", help="perform isolated npm ci/build/topology test and raw-PCAP smoke analysis")
    parser.add_argument("--full", action="store_true", help="run clean validation plus the complete 26-stage regression gate")
    parser.add_argument("--json", action="store_true", help="emit final machine-readable summary")
    args = parser.parse_args()

    checks: list[Check] = []
    checks.extend(check_tree())
    checks.extend(check_toolchain())
    checks.append(run_preflight())
    if args.clean or args.full:
        checks.extend(clean_frontend_validation())
        checks.append(pcap_smoke_validation())
    if args.full:
        checks.append(full_regression_validation())
    return summarize(checks, json_output=args.json)


if __name__ == "__main__":
    raise SystemExit(main())
