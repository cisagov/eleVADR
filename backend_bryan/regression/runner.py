"""Run the three canonical eleVADR PCAP regression datasets.

Live mode executes the same backend_bryan PCAP -> Zeek -> detector -> report
pipeline used by the frontend PCAP workflow. Fixture mode validates the
manifests against the last known-good reference reports without requiring Zeek.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from backend_bryan.integration.pcap_analysis import analyze_pcap_to_report

ROOT = Path(__file__).resolve().parent
MANIFEST_DIR = ROOT / "manifests"
FIXTURE_DIR = ROOT / "fixtures"
REFERENCE_REPORT_DIR = ROOT / "reference_reports"


@dataclass
class CheckFailure:
    dataset: str
    message: str


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object in {path}")
    return value


def load_manifests() -> list[dict[str, Any]]:
    manifests = [_load_json(path) for path in sorted(MANIFEST_DIR.glob("*.json"))]
    if not manifests:
        raise RuntimeError(f"No regression manifests found in {MANIFEST_DIR}")
    return manifests


def _detector_index(report: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    rows = report.get("arch_insights", {}).get("detector_results", [])
    return {str(row.get("module_id")): row for row in rows if isinstance(row, Mapping)}


def _deep_get(value: Any, path: str) -> Any:
    current = value
    for token in path.split("."):
        if isinstance(current, Mapping) and token in current:
            current = current[token]
            continue
        if isinstance(current, list) and token.isdigit():
            index = int(token)
            if 0 <= index < len(current):
                current = current[index]
                continue
        raise KeyError(path)
    return current


def validate_report(manifest: Mapping[str, Any], report: Mapping[str, Any]) -> list[CheckFailure]:
    dataset = str(manifest.get("id", "unknown"))
    expected = manifest.get("expected", {})
    failures: list[CheckFailure] = []

    def fail(message: str) -> None:
        failures.append(CheckFailure(dataset, message))

    report_version = str(report.get("report_version", ""))
    if not report_version.startswith("2."):
        fail(f"report_version expected 2.x, got {report_version!r}")

    arch = report.get("arch_insights", {})
    provenance = arch.get("analysis_provenance", {})
    detector_errors = arch.get("detector_errors", [])
    if detector_errors:
        fail(f"expected zero detector errors, got {len(detector_errors)}")

    requested = expected.get("detectorModulesRequested", 60)
    completed = expected.get("detectorModulesCompleted", 60)
    failed = expected.get("detectorModulesFailed", 0)
    if provenance.get("detector_modules_requested") != requested:
        fail(f"requested modules expected {requested}, got {provenance.get('detector_modules_requested')}")
    if provenance.get("detector_modules_completed") != completed:
        fail(f"completed modules expected {completed}, got {provenance.get('detector_modules_completed')}")
    if provenance.get("detector_modules_failed") != failed:
        fail(f"failed modules expected {failed}, got {provenance.get('detector_modules_failed')}")

    all_findings = arch.get("detector_findings", [])
    expected_count = expected.get("findingCount")
    if expected_count is not None and len(all_findings) != expected_count:
        fail(f"finding count expected {expected_count}, got {len(all_findings)}")

    index = _detector_index(report)
    if len(index) != completed:
        fail(f"detector result records expected {completed}, got {len(index)}")

    with_findings = expected.get("modulesWithFindings", {})
    for module_id, count in with_findings.items():
        row = index.get(module_id)
        if row is None:
            fail(f"missing detector result for {module_id}")
            continue
        actual = len(row.get("findings", []) or [])
        if actual != count:
            fail(f"{module_id} finding count expected {count}, got {actual}")

    for module_id in expected.get("modulesWithoutFindings", []):
        row = index.get(module_id)
        if row is None:
            fail(f"missing detector result for {module_id}")
            continue
        actual = len(row.get("findings", []) or [])
        if actual != 0:
            fail(f"{module_id} expected no findings, got {actual}")

    for module_id, metric_expectations in expected.get("moduleMetrics", {}).items():
        row = index.get(module_id)
        if row is None:
            fail(f"missing detector result for {module_id}")
            continue
        metrics = row.get("metrics", {})
        for metric_name, want in metric_expectations.items():
            got = metrics.get(metric_name)
            if got != want:
                fail(f"{module_id}.metrics.{metric_name} expected {want!r}, got {got!r}")

    device_expected = expected.get("devicePanel", {})
    device_actual = report.get("modules", {}).get("device_panel", {})
    for key, value in device_expected.items():
        if device_actual.get(key) != value:
            fail(f"device_panel.{key} expected {value!r}, got {device_actual.get(key)!r}")

    for assertion in expected.get("assertions", []):
        path = str(assertion["path"])
        want = assertion.get("equals")
        try:
            got = _deep_get(report, path)
        except KeyError:
            fail(f"missing asserted path {path}")
            continue
        if got != want:
            fail(f"{path} expected {want!r}, got {got!r}")

    return failures


def _progress(dataset: str):
    last_message = {"value": None}

    def emit(stage: str, value: int | None, message: str, detail: str | None) -> None:
        rendered = f"[{dataset}] {message}"
        if detail:
            rendered += f" ({detail})"
        if rendered != last_message["value"]:
            print(rendered, flush=True)
            last_message["value"] = rendered

    return emit


def run_manifest(manifest: Mapping[str, Any], mode: str) -> tuple[Mapping[str, Any], float]:
    started = time.perf_counter()
    dataset = str(manifest["id"])
    if mode == "fixture":
        report_path = REFERENCE_REPORT_DIR / str(manifest["referenceReport"])
        report = _load_json(report_path)
    else:
        pcap = FIXTURE_DIR / str(manifest["pcap"])
        context = _load_json(FIXTURE_DIR / str(manifest["context"]))
        if not pcap.exists():
            raise FileNotFoundError(pcap)
        report = analyze_pcap_to_report(
            pcap,
            context,
            source_filename=pcap.name,
            progress=_progress(dataset),
        )
    return report, time.perf_counter() - started


def _print_summary(rows: Iterable[tuple[str, str, float, int]]) -> None:
    rows = list(rows)
    print("\nRegression summary")
    print("------------------")
    for dataset, status, seconds, finding_count in rows:
        print(f"{status:4}  {dataset:28} {finding_count:3} finding(s)  {seconds:6.2f}s")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run eleVADR canonical PCAP regressions.")
    parser.add_argument(
        "--mode",
        choices=("live", "fixture"),
        default="live",
        help="live runs Zeek+detectors; fixture validates manifests against known-good reports",
    )
    parser.add_argument("--dataset", action="append", help="Run only the named dataset id; may be repeated")
    args = parser.parse_args(argv)

    selected = set(args.dataset or [])
    manifests = [m for m in load_manifests() if not selected or str(m.get("id")) in selected]
    if selected and len(manifests) != len(selected):
        known = {str(m.get("id")) for m in load_manifests()}
        missing = sorted(selected - known)
        print(f"Unknown dataset id(s): {', '.join(missing)}", file=sys.stderr)
        return 2

    failures: list[CheckFailure] = []
    summary: list[tuple[str, str, float, int]] = []
    for manifest in manifests:
        dataset = str(manifest["id"])
        print(f"\n=== {dataset}: {manifest.get('name', dataset)} ===", flush=True)
        try:
            report, elapsed = run_manifest(manifest, args.mode)
            current_failures = validate_report(manifest, report)
            failures.extend(current_failures)
            finding_count = len(report.get("arch_insights", {}).get("detector_findings", []))
            status = "PASS" if not current_failures else "FAIL"
            summary.append((dataset, status, elapsed, finding_count))
            if current_failures:
                for failure in current_failures:
                    print(f"  FAIL: {failure.message}")
            else:
                print(f"  PASS: {finding_count} findings; manifest expectations satisfied")
        except Exception as exc:
            failures.append(CheckFailure(dataset, f"runner error: {type(exc).__name__}: {exc}"))
            summary.append((dataset, "FAIL", 0.0, 0))
            print(f"  FAIL: {type(exc).__name__}: {exc}")

    _print_summary(summary)
    if failures:
        print(f"\nFAILED: {len(failures)} regression check(s) failed.")
        return 1
    print(f"\nPASSED: {len(manifests)} dataset(s) matched their manifests.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
