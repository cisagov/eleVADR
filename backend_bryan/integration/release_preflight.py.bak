"""Executable release-readiness checks for the eleVADR handoff build."""
from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

from backend_bryan.integration.api_contract import REQUEST_CONTRACT_VERSION, RESPONSE_CONTRACT_VERSION
from backend_bryan.integration.detector_runtime import ensure_detector_package
from backend_bryan.integration.finding_calibration import CALIBRATION_PROFILES
from backend_bryan.runtime.zeek_runtime import DEFAULT_ZEEK_DOCKER_IMAGE

ROOT = Path(__file__).resolve().parents[2]
EXPECTED_DETECTOR_COUNT = 75
REFERENCE_PORT = 8765


@dataclass(frozen=True, slots=True)
class CheckResult:
    name: str
    ok: bool
    detail: str


def _result(name: str, ok: bool, detail: str) -> CheckResult:
    return CheckResult(name=name, ok=ok, detail=detail)


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def _json(path: str):
    return json.loads(_read(path))


def _registry_ids() -> list[str]:
    _context_type, modules, _module_file = ensure_detector_package()
    return sorted(str(module_id) for module_id in modules)


def _check_registry() -> CheckResult:
    ids = _registry_ids()
    snapshot = _json("backend_bryan/reference/module_registry_snapshot.json")
    snapshot_ids = sorted(str(item["id"]) for item in snapshot)
    ok = len(ids) == EXPECTED_DETECTOR_COUNT and ids == snapshot_ids
    return _result(
        "detector registry snapshot",
        ok,
        f"runtime={len(ids)} snapshot={len(snapshot_ids)} expected={EXPECTED_DETECTOR_COUNT}",
    )


def _check_calibration() -> CheckResult:
    ids = set(_registry_ids())
    calibrated = set(CALIBRATION_PROFILES)
    missing = sorted(ids - calibrated)
    extra = sorted(calibrated - ids)
    return _result(
        "calibration coverage",
        not missing and not extra,
        f"profiles={len(calibrated)} missing={missing or 'none'} extra={extra or 'none'}",
    )


def _schema_const(path: str) -> str | None:
    schema = _json(path)
    props = schema.get("properties", {})
    version = props.get("contractVersion", {}) if isinstance(props, dict) else {}
    return version.get("const") if isinstance(version, dict) else None


def _check_contract_versions() -> CheckResult:
    request_schema = _schema_const("backend_bryan/reference/api_contract/detection_analysis_request.schema.json")
    response_schema = _schema_const("backend_bryan/reference/api_contract/detection_analysis_response.schema.json")
    ok = request_schema == REQUEST_CONTRACT_VERSION and response_schema == RESPONSE_CONTRACT_VERSION
    return _result(
        "API schema/version parity",
        ok,
        f"request={request_schema!r} response={response_schema!r}",
    )


def _check_zeek_pin() -> CheckResult:
    dockerfile = _read("backend/Dockerfile")
    start_bat = _read("start_elevadr.bat")
    prepare_bat = _read("prepare_zeek_runtime.bat")
    docker_match = re.search(r"^FROM\s+docker\.io/(zeek/zeek:[^\s]+)", dockerfile, re.MULTILINE)
    docker_image = docker_match.group(1) if docker_match else None
    bat_match = re.search(r"set \"ZEEK_IMAGE=([^\"]+)\"", start_bat)
    bat_image = bat_match.group(1) if bat_match else None
    prepare_match = re.search(r'set "ZEEK_IMAGE=([^"]+)"', prepare_bat)
    prepare_image = prepare_match.group(1) if prepare_match else None
    ok = docker_image == DEFAULT_ZEEK_DOCKER_IMAGE and bat_image == DEFAULT_ZEEK_DOCKER_IMAGE and prepare_image == DEFAULT_ZEEK_DOCKER_IMAGE
    return _result(
        "Zeek runtime pin parity",
        ok,
        f"runtime={DEFAULT_ZEEK_DOCKER_IMAGE} backend={docker_image} launcher={bat_image} prepare={prepare_image}",
    )


def _check_local_ports() -> CheckResult:
    start_bat = _read("start_elevadr.bat")
    stop_bat = _read("stop_elevadr.bat")
    env_local = _read("frontend/.env.local")
    env_example = _read("frontend/.env.example")
    expected = str(REFERENCE_PORT)
    bad_ports = sorted(set(re.findall(r"127\.0\.0\.1:(\d+)|localhost:(\d+)|:(\d+) .*LISTENING", start_bat + stop_bat + env_local + env_example)))
    # Flatten regex tuple results and ignore unrelated values if none exist.
    observed = sorted({part for triple in bad_ports for part in triple if part}) if bad_ports else []
    ok = "8770" not in observed and expected in observed
    return _result("local launcher/API port parity", ok, f"reference={REFERENCE_PORT} observed={observed}")


def _check_required_release_files() -> CheckResult:
    required = (
        "README.md",
        "HANDOFF.md",
        "run_regression_tests.bat",
        "run_regression_tests.sh",
        "run_release_candidate_validation.bat",
        "run_release_candidate_validation.sh",
        "RELEASE_CANDIDATE_CHECKPOINT.md",
        "RELEASE_CANDIDATE_MANIFEST.json",
        "backend_bryan/integration/release_candidate_gate.py",
        "backend_bryan/vendor/elevadr_modules/modules/cleartext_credentials.py",
        "backend_bryan/reference/release_readiness.md",
        "backend_bryan/reference/elevadr_report_v2.schema.json",
        "backend_bryan/regression/fixtures/19_site_like_multi_hour_ot.pcap",
        "backend_bryan/regression/fixtures/19_site_like_multi_hour_ot_context.json",
        "backend_bryan/regression/fixtures/19_site_like_multi_hour_ot_manifest.json",
    )
    missing = [item for item in required if not (ROOT / item).exists()]
    return _result("release package required files", not missing, f"missing={missing or 'none'}")


def _check_dataset19_manifest() -> CheckResult:
    manifest = _json("backend_bryan/regression/fixtures/19_site_like_multi_hour_ot_manifest.json")
    required = set(manifest.get("required_finding_modules", []))
    allowed = set(manifest.get("allowed_finding_modules", []))
    anomalies = manifest.get("deliberate_anomalies", [])
    anomaly_modules = {
        module
        for item in anomalies if isinstance(item, dict)
        for module in item.get("expected_modules", []) if isinstance(module, str)
    }
    ok = required and required <= allowed and required <= anomaly_modules and int(manifest.get("duration_seconds", 0)) >= 14400
    return _result(
        "Dataset 19 release tripwire",
        bool(ok),
        f"required={sorted(required)} allowed={sorted(allowed)} duration={manifest.get('duration_seconds')}",
    )


def run_checks() -> list[CheckResult]:
    return [
        _check_required_release_files(),
        _check_registry(),
        _check_calibration(),
        _check_contract_versions(),
        _check_zeek_pin(),
        _check_local_ports(),
        _check_dataset19_manifest(),
    ]


def failed(results: Iterable[CheckResult]) -> list[CheckResult]:
    return [item for item in results if not item.ok]


def main() -> int:
    parser = argparse.ArgumentParser(description="Run eleVADR release-readiness preflight checks")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = parser.parse_args()
    results = run_checks()
    failures = failed(results)
    if args.json:
        print(json.dumps({"status": "pass" if not failures else "fail", "checks": [asdict(item) for item in results]}, indent=2))
    else:
        print("eleVADR release-readiness preflight")
        print("---------------------------------")
        for item in results:
            print(f"{'PASS' if item.ok else 'FAIL'}  {item.name}: {item.detail}")
        print(f"\n{'PASS' if not failures else 'FAIL'}: {len(results) - len(failures)}/{len(results)} release checks passed.")
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
