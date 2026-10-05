from __future__ import annotations

import json
import time
import tracemalloc
from types import SimpleNamespace
from typing import Any, Callable

from backend_bryan.adapters.detection_context_adapter import compile_detection_context_metadata
from backend_bryan.integration.detector_runtime import ensure_detector_package
from backend_bryan.integration.report_builder import build_elevadr_report


CONNECTION_COUNT = 12_000
ASSET_COUNT = 3_000
COMMUNICATION_PAIR_COUNT = 4_000
FINDINGS_PER_MODULE = 100
MODULE_COUNT = 75


def _profile(*, assets: int = ASSET_COUNT, communication_pairs: int = COMMUNICATION_PAIR_COUNT) -> dict[str, Any]:
    asset_rows: list[dict[str, Any]] = []
    for i in range(assets):
        third = (i // 250) % 250
        fourth = (i % 250) + 1
        ip = f"10.{100 + (i // 62500)}.{third}.{fourth}"
        is_ot = (i % 2) == 0
        asset_rows.append({
            "ip": ip,
            "segment": "OT" if is_ot else "IT",
            "role": "OT" if is_ot else "IT",
            "assetType": "PLC" if is_ot else "Workstation",
            "source": "user",
        })

    pairs: list[dict[str, Any]] = []
    for i in range(communication_pairs):
        src = asset_rows[i % len(asset_rows)]["ip"] if asset_rows else f"10.100.0.{(i % 250) + 1}"
        dst = asset_rows[(i + 1) % len(asset_rows)]["ip"] if asset_rows else f"10.101.0.{(i % 250) + 1}"
        pairs.append({
            "sourceIp": src,
            "destinationIp": dst,
            "protocol": "tcp",
            "destinationPort": 502 if i % 3 == 0 else 443,
            "service": "modbus" if i % 3 == 0 else "ssl",
            "source": "user",
        })

    return {
        "schemaVersion": 3,
        "id": "regression-10",
        "name": "Regression 10 - Performance and Scale",
        "segments": [
            {"name": "OT", "cidr": "10.100.0.0/16", "role": "OT", "purdueLevel": "Level 2"},
            {"name": "IT", "cidr": "10.101.0.0/16", "role": "IT", "purdueLevel": "Level 4"},
        ],
        "assets": asset_rows,
        "infrastructure": [],
        "communicationPairs": pairs,
        "allowedHosts": [f"192.0.2.{(i % 250) + 1}" for i in range(2_000)],
        "allowedSegmentPairs": [],
        "approvedExternalDestinations": [f"198.51.100.{(i % 250) + 1}" for i in range(2_000)],
        "captureScope": {
            "internalIcsOnlyExpected": False,
            "dedicatedOtSensor": True,
            "ipv4OnlyExpected": True,
        },
        "authorizedControlActions": [],
        "modulePolicies": {},
        "selectedModules": [],
        "scan": {},
    }


def _connections(count: int = CONNECTION_COUNT) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    services = (("modbus", 502), ("ssl", 443), ("dns", 53), ("ntp", 123), ("http", 80))
    for i in range(count):
        service, port = services[i % len(services)]
        src_segment = 100 if i % 2 == 0 else 101
        dst_segment = 101 if i % 4 < 2 else 100
        src = f"10.{src_segment}.{(i // 250) % 12}.{(i % 250) + 1}"
        if i % 10 == 0:
            dst = f"203.0.113.{(i % 250) + 1}"
        else:
            dst = f"10.{dst_segment}.{((i + 17) // 250) % 12}.{((i + 17) % 250) + 1}"
        rows.append({
            "uid": f"SCALE-{i:06d}",
            "timestamp": 1_800_000_000.0 + (i * 0.01),
            "source_ip": src,
            "source_port": 30_000 + (i % 20_000),
            "destination_ip": dst,
            "destination_port": port,
            "protocol": "udp" if service in {"dns", "ntp"} else "tcp",
            "service": service,
            "zeek_state": "SF" if i % 7 else "REJ",
            "duration": (i % 100) / 10.0,
            "source_bytes": i % 65_536,
            "destination_bytes": (i * 3) % 65_536,
        })
    return rows


def _module_results(*, modules: int = MODULE_COUNT, findings_per_module: int = FINDINGS_PER_MODULE) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for module_index in range(modules):
        module_id = f"scale_detector_{module_index:02d}"
        findings = []
        for finding_index in range(findings_per_module):
            findings.append({
                "title": f"Finding {finding_index:03d}",
                "severity": ("low", "medium", "high", "critical")[finding_index % 4],
                "summary": f"Synthetic scale finding {finding_index}",
                "services": [("modbus", "ssl", "dns", "http")[finding_index % 4]],
                "evidence_count": finding_index + 1,
            })
        results.append({
            "module_id": module_id,
            "findings": findings,
            "metrics": {"rows_evaluated": CONNECTION_COUNT, "finding_count": len(findings)},
            "evidence": {"sampled": min(25, len(findings))},
        })
    return results


def _build_scaled_report() -> tuple[dict[str, Any], float, int]:
    profile = _profile()
    context = SimpleNamespace(connections=_connections())
    module_results = _module_results()
    tracemalloc.start()
    started = time.perf_counter()
    report = build_elevadr_report(
        source_filename="10_scale_workload.pcap",
        profile=profile,
        context=context,
        module_results=module_results,
        module_errors=[],
        zeek_log_types={"conn": CONNECTION_COUNT, "dns": CONNECTION_COUNT // 5, "http": CONNECTION_COUNT // 5},
        zeek_runtime="Synthetic regression workload",
        detector_modules_requested=MODULE_COUNT,
    )
    elapsed = time.perf_counter() - started
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return report, elapsed, peak


def run_cases(verbose: bool = True) -> list[str]:
    failures: list[str] = []
    passed = 0

    def check(label: str, fn: Callable[[], None]) -> None:
        nonlocal passed
        try:
            fn()
        except Exception as exc:
            failures.append(f"{label}: {type(exc).__name__}: {exc}")
            if verbose:
                print(f"FAIL  {label} ({type(exc).__name__}: {exc})")
        else:
            passed += 1
            if verbose:
                print(f"PASS  {label}")

    if verbose:
        print("\n=== 10_performance_scale: Large-volume report and Detection Context behavior ===")

    report, elapsed, peak = _build_scaled_report()
    serialized = json.dumps(report, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    def report_build_responsive() -> None:
        # Deliberately generous ceiling: this is a regression tripwire, not a benchmark.
        assert elapsed < 15.0, f"scaled report build took {elapsed:.2f}s"
    check(f"12,000-connection / 3,000-asset report builds within 15s ceiling ({elapsed:.2f}s)", report_build_responsive)

    def memory_bounded() -> None:
        assert peak < 512 * 1024 * 1024, f"peak traced memory was {peak / 1024 / 1024:.1f} MiB"
    check(f"Scaled report build stays below 512 MiB traced peak ({peak / 1024 / 1024:.1f} MiB)", memory_bounded)

    def connection_semantics_preserved() -> None:
        rows = report["modules"]["connection_success_panel"]["connections"]
        assert len(rows) == CONNECTION_COUNT
        summary = report["modules"]["connection_success_panel"]["summary"]
        assert summary["successful_count"] + summary["unsuccessful_count"] == CONNECTION_COUNT
    check("All 12,000 connection records are retained with exact success totals", connection_semantics_preserved)

    def asset_semantics_preserved() -> None:
        device_panel = report["modules"]["device_panel"]
        assert device_panel["hosts"] >= ASSET_COUNT
        assert len(report["arch_insights"]["detection_context_snapshot"]["assets"]) == ASSET_COUNT
    check("Large authoritative asset inventory survives report generation without row loss", asset_semantics_preserved)

    def finding_semantics_preserved() -> None:
        findings = report["arch_insights"]["detector_findings"]
        assert len(findings) == MODULE_COUNT * FINDINGS_PER_MODULE
        assert len(report["arch_insights"]["detector_results"]) == MODULE_COUNT
        assert report["arch_insights"]["analysis_provenance"]["detector_modules_completed"] == MODULE_COUNT
    check("7,500 findings across 75 detector results are retained exactly", finding_semantics_preserved)

    def context_snapshot_preserved() -> None:
        snapshot = report["arch_insights"]["detection_context_snapshot"]
        assert len(snapshot["communicationPairs"]) == COMMUNICATION_PAIR_COUNT
        assert len(snapshot["allowedHosts"]) == 2_000
        assert len(snapshot["approvedExternalDestinations"]) == 2_000
        assert snapshot["authorizedControlActions"] == []
    check("Oversized Detection Context snapshot preserves policy collections without inventing authorization", context_snapshot_preserved)

    def serialized_size_reasonable() -> None:
        # A linear-size guard against accidental explosive duplication in nested report structures.
        assert len(serialized) < 64 * 1024 * 1024, f"serialized report is {len(serialized) / 1024 / 1024:.1f} MiB"
    check(f"Serialized scaled report remains below 64 MiB ({len(serialized) / 1024 / 1024:.1f} MiB)", serialized_size_reasonable)

    def deterministic_scaled_rebuild() -> None:
        second, second_elapsed, _second_peak = _build_scaled_report()
        first_copy = dict(report)
        second_copy = dict(second)
        first_copy.pop("report_id", None)
        second_copy.pop("report_id", None)
        first_provenance = first_copy["arch_insights"]["analysis_provenance"]
        second_provenance = second_copy["arch_insights"]["analysis_provenance"]
        first_provenance = dict(first_provenance)
        second_provenance = dict(second_provenance)
        first_provenance.pop("generated_at", None)
        second_provenance.pop("generated_at", None)
        first_copy["arch_insights"] = dict(first_copy["arch_insights"])
        second_copy["arch_insights"] = dict(second_copy["arch_insights"])
        first_copy["arch_insights"]["analysis_provenance"] = first_provenance
        second_copy["arch_insights"]["analysis_provenance"] = second_provenance
        assert json.dumps(first_copy, sort_keys=False, separators=(",", ":"), ensure_ascii=False) == json.dumps(second_copy, sort_keys=False, separators=(",", ":"), ensure_ascii=False)
        assert second_elapsed < 15.0
    check("Repeated scaled builds remain semantically byte-identical outside volatile fields", deterministic_scaled_rebuild)

    def large_context_compiles_responsively() -> None:
        profile = _profile(assets=5_000, communication_pairs=8_000)
        started = time.perf_counter()
        metadata = compile_detection_context_metadata(profile)
        compile_elapsed = time.perf_counter() - started
        assert compile_elapsed < 10.0, f"context compilation took {compile_elapsed:.2f}s"
        assert len(metadata.get("detection_context_observations", {}).get("communications", [])) == 8_000
        # Communication observations remain observations and do not authorize control actions.
        for key, value in metadata.items():
            if isinstance(value, dict) and "allowed_paths" in value:
                assert not value.get("allowed_paths"), f"{key} unexpectedly gained allowed_paths"
    check("5,000-asset / 8,000-pair Detection Context compiles within 10s and keeps observations non-authoritative", large_context_compiles_responsively)

    def detector_runtime_handles_benign_scale() -> None:
        AnalysisContext, MODULES, _module_file = ensure_detector_package()
        # Keep this workload large enough to expose accidental quadratic behavior but small enough for the standard gate.
        context = AnalysisContext(metadata={}, connections=_connections(2_000))
        started = time.perf_counter()
        completed = 0
        for module in MODULES.values():
            module.analyze(context)
            completed += 1
        detector_elapsed = time.perf_counter() - started
        assert completed == 75
        assert detector_elapsed < 20.0, f"75-detector scale pass took {detector_elapsed:.2f}s"
    check("All 75 detectors complete a 2,000-connection workload within 20s ceiling", detector_runtime_handles_benign_scale)

    if verbose:
        if failures:
            print(f"FAIL: Dataset 10 had {len(failures)} failure(s).")
        else:
            print(f"PASS: Dataset 10 verified {passed} performance/scale cases.")
    return failures


def main() -> int:
    return 1 if run_cases(verbose=True) else 0


if __name__ == "__main__":
    raise SystemExit(main())
