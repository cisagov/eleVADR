from __future__ import annotations

import hashlib
import json
from collections import OrderedDict
from copy import deepcopy
from types import SimpleNamespace
from typing import Any, Callable, Mapping

from backend_bryan.integration.report_builder import build_elevadr_report


def _profile() -> dict[str, Any]:
    return {
        "schemaVersion": 3,
        "id": "regression-09",
        "name": "Regression 09 - Report Determinism",
        "segments": [
            {"name": "OT", "cidr": "10.90.0.0/24", "role": "OT", "purdueLevel": "Level 2"},
            {"name": "IT", "cidr": "10.91.0.0/24", "role": "IT", "purdueLevel": "Level 4"},
        ],
        "assets": [
            {"ip": "10.90.0.10", "segment": "OT", "role": "OT", "assetType": "PLC", "source": "user"},
            {"ip": "10.91.0.20", "segment": "IT", "role": "IT", "assetType": "Workstation", "source": "user"},
        ],
        "infrastructure": [],
        "communicationPairs": [],
        "allowedHosts": [],
        "allowedSegmentPairs": [],
        "approvedExternalDestinations": [],
        "captureScope": {
            "internalIcsOnlyExpected": False,
            "dedicatedOtSensor": True,
            "ipv4OnlyExpected": True,
        },
        "authorizedControlActions": [],
        "modulePolicies": {},
        "selectedModules": ["alpha_detector", "zeta_detector"],
        "scan": {},
    }


def _connections() -> list[dict[str, Any]]:
    return [
        {
            "uid": "C3",
            "timestamp": 103.0,
            "source_ip": "10.90.0.10",
            "source_port": 40003,
            "destination_ip": "8.8.8.8",
            "destination_port": 443,
            "protocol": "tcp",
            "service": "ssl",
            "zeek_state": "REJ",
            "source_bytes": 30,
            "destination_bytes": 0,
        },
        {
            "uid": "C1",
            "timestamp": 101.0,
            "source_ip": "10.90.0.10",
            "source_port": 40001,
            "destination_ip": "10.91.0.20",
            "destination_port": 502,
            "protocol": "tcp",
            "service": "modbus",
            "zeek_state": "SF",
            "source_bytes": 100,
            "destination_bytes": 200,
        },
        {
            "uid": "C2",
            "timestamp": 102.0,
            "source_ip": "10.91.0.20",
            "source_port": 40002,
            "destination_ip": "1.1.1.1",
            "destination_port": 53,
            "protocol": "udp",
            "service": "dns",
            "zeek_state": "SF",
            "source_bytes": 50,
            "destination_bytes": 80,
        },
    ]


def _module_results() -> list[dict[str, Any]]:
    return [
        {
            "module_id": "zeta_detector",
            "findings": [
                {"title": "Z second", "severity": "high", "summary": "second", "services": ["ssl"]},
                {"title": "A first", "severity": "medium", "summary": "first", "services": ["dns"]},
            ],
            "metrics": {"b": 2, "a": 1},
            "evidence": {"rows": 2},
        },
        {
            "module_id": "alpha_detector",
            "findings": [
                {"title": "Alpha", "severity": "low", "summary": "alpha", "services": ["modbus"]}
            ],
            "metrics": {"count": 1},
            "evidence": {"rows": 1},
        },
    ]


def _errors() -> list[dict[str, Any]]:
    return [
        {"moduleId": "zeta_detector", "code": "z", "message": "later"},
        {"moduleId": "alpha_detector", "code": "a", "message": "earlier"},
    ]


def _build(*, reverse_connections: bool = False, reverse_modules: bool = False,
           reverse_findings: bool = False, reverse_errors: bool = False,
           reverse_logs: bool = False, reverse_profile_keys: bool = False) -> dict[str, Any]:
    profile: Mapping[str, Any] = _profile()
    if reverse_profile_keys:
        profile = OrderedDict(reversed(list(profile.items())))

    connections = _connections()
    if reverse_connections:
        connections.reverse()

    module_results = _module_results()
    if reverse_findings:
        for result in module_results:
            if isinstance(result.get("findings"), list):
                result["findings"].reverse()
    if reverse_modules:
        module_results.reverse()

    errors = _errors()
    if reverse_errors:
        errors.reverse()

    logs: Mapping[str, int] = OrderedDict([("weird", 1), ("conn", 1), ("dns", 1)])
    if reverse_logs:
        logs = OrderedDict(reversed(list(logs.items())))

    return build_elevadr_report(
        source_filename="09_determinism.pcap",
        profile=profile,
        context=SimpleNamespace(connections=connections),
        module_results=module_results,
        module_errors=errors,
        zeek_log_types=logs,
        zeek_runtime="Docker (zeek/zeek:9.0.0)",
        detector_modules_requested=2,
    )


def _semantic_view(report: Mapping[str, Any]) -> dict[str, Any]:
    value = deepcopy(dict(report))
    value.pop("report_id", None)
    provenance = value.get("arch_insights", {}).get("analysis_provenance", {})
    if isinstance(provenance, dict):
        provenance.pop("generated_at", None)
    return value


def _semantic_bytes(report: Mapping[str, Any]) -> bytes:
    return json.dumps(_semantic_view(report), sort_keys=False, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _semantic_digest(report: Mapping[str, Any]) -> str:
    return hashlib.sha256(_semantic_bytes(report)).hexdigest()


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
        print("\n=== 09_report_determinism: Stable semantic reports across ordering and run variance ===")

    baseline = _build()
    baseline_digest = _semantic_digest(baseline)
    baseline_bytes = _semantic_bytes(baseline)

    def repeated_runs_semantically_identical() -> None:
        second = _build()
        assert baseline["report_id"] != second["report_id"]
        assert baseline["arch_insights"]["analysis_provenance"]["generated_at"] != second["arch_insights"]["analysis_provenance"]["generated_at"] or baseline["report_id"] != second["report_id"]
        assert _semantic_digest(second) == baseline_digest
    check("Repeated builds differ only in volatile identity/time fields", repeated_runs_semantically_identical)

    def connection_order_invariant() -> None:
        assert _semantic_bytes(_build(reverse_connections=True)) == baseline_bytes
    check("Connection input ordering does not change report semantics or serialized list ordering", connection_order_invariant)

    def module_order_invariant() -> None:
        assert _semantic_bytes(_build(reverse_modules=True)) == baseline_bytes
    check("Detector result iteration ordering does not change report output", module_order_invariant)

    def finding_order_invariant() -> None:
        assert _semantic_bytes(_build(reverse_findings=True)) == baseline_bytes
    check("Detector finding iteration ordering is canonicalized", finding_order_invariant)

    def error_order_invariant() -> None:
        assert _semantic_bytes(_build(reverse_errors=True)) == baseline_bytes
    check("Detector error ordering is canonicalized", error_order_invariant)

    def zeek_log_order_invariant() -> None:
        candidate = _build(reverse_logs=True)
        assert _semantic_bytes(candidate) == baseline_bytes
        assert list(candidate["arch_insights"]["analysis_provenance"]["zeek_log_types"].keys()) == ["conn", "dns", "weird"]
    check("Zeek log-type map insertion order cannot change report serialization", zeek_log_order_invariant)

    def profile_key_order_invariant() -> None:
        assert _semantic_bytes(_build(reverse_profile_keys=True)) == baseline_bytes
    check("Detection Context mapping key order is normalized in the report snapshot", profile_key_order_invariant)

    def combined_permutation_invariant() -> None:
        candidate = _build(
            reverse_connections=True,
            reverse_modules=True,
            reverse_findings=True,
            reverse_errors=True,
            reverse_logs=True,
            reverse_profile_keys=True,
        )
        assert _semantic_bytes(candidate) == baseline_bytes
    check("Combined ordering permutations yield byte-identical normalized report content", combined_permutation_invariant)

    def canonical_detector_order() -> None:
        rows = baseline["arch_insights"]["detector_results"]
        assert [row["module_id"] for row in rows] == ["alpha_detector", "zeta_detector"]
        findings = baseline["arch_insights"]["detector_findings"]
        assert [row["module_id"] for row in findings] == ["alpha_detector", "zeta_detector", "zeta_detector"]
        assert [row["title"] for row in findings[1:]] == ["A first", "Z second"]
    check("Detector results and findings have deterministic canonical ordering", canonical_detector_order)

    def canonical_connection_order() -> None:
        rows = baseline["modules"]["connection_success_panel"]["connections"]
        assert [row["dst_endpoint.ip"] for row in rows] == ["10.91.0.20", "1.1.1.1", "8.8.8.8"]
        outbound = baseline["modules"]["suspicious_outbound_connections_panel"]
        assert [(row["src_endpoint.ip"], row["dst_endpoint.ip"]) for row in outbound] == [
            ("10.90.0.10", "8.8.8.8"),
            ("10.91.0.20", "1.1.1.1"),
        ]
    check("Connection and outbound summary lists have deterministic ordering", canonical_connection_order)

    def volatile_fields_are_explicitly_scoped() -> None:
        first = _build()
        second = _build()
        differing_top = {key for key in first if first.get(key) != second.get(key)}
        assert differing_top <= {"report_id", "arch_insights"}
        first_arch = deepcopy(first["arch_insights"])
        second_arch = deepcopy(second["arch_insights"])
        first_time = first_arch["analysis_provenance"].pop("generated_at")
        second_time = second_arch["analysis_provenance"].pop("generated_at")
        assert first_time and second_time
        assert first_arch == second_arch
    check("Volatile run metadata is limited to report identity and generation time", volatile_fields_are_explicitly_scoped)

    if verbose:
        if failures:
            print(f"FAIL: Dataset 09 had {len(failures)} failure(s).")
        else:
            print(f"PASS: Dataset 09 verified {passed} determinism/reproducibility cases.")
    return failures


def main() -> int:
    return 1 if run_cases(verbose=True) else 0


if __name__ == "__main__":
    raise SystemExit(main())
