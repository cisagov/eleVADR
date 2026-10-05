from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from backend_bryan.integration.detector_runtime import ensure_detector_package

MIB = 1024 * 1024


@dataclass(frozen=True)
class BoundaryCase:
    name: str
    module_id: str
    expected_findings: int
    build_context: Callable[[type], object]
    check: Callable[[object], None] | None = None


def _segments_metadata() -> dict:
    return {
        "segments": [
            {"name": "OT", "cidr": "10.60.0.0/24", "role": "OT", "trust_zone": "ot"},
            {"name": "Enterprise", "cidr": "10.70.0.0/24", "role": "IT", "trust_zone": "enterprise"},
        ]
    }


def _http_upload_context(AnalysisContext: type, size: int):
    return AnalysisContext(
        connections=[{
            "uid": "H1", "source_ip": "10.60.0.10", "destination_ip": "1.1.1.1",
            "destination_port": 80, "protocol": "tcp", "service": "http", "local_resp": False,
            "source_bytes": size, "timestamp": 100.0,
        }],
        http=[{
            "uid": "H1", "source_ip": "10.60.0.10", "destination_ip": "1.1.1.1",
            "destination_port": 80, "method": "POST", "host": "upload.example",
            "request_body_len": size, "timestamp": 100.0,
        }],
        metadata=_segments_metadata(),
    )


def _outbound_volume_context(AnalysisContext: type, size: int):
    return AnalysisContext(
        connections=[{
            "uid": "V1", "source_ip": "10.60.0.10", "destination_ip": "1.1.1.1",
            "destination_port": 443, "protocol": "tcp", "service": "ssl", "local_resp": False,
            "source_bytes": size, "timestamp": 100.0,
        }],
        metadata=_segments_metadata(),
    )


def _icmp_context(AnalysisContext: type, count: int, span: float):
    if count <= 1:
        timestamps = [0.0]
    else:
        step = span / (count - 1)
        timestamps = [round(index * step, 9) for index in range(count)]
    rows = []
    for index, ts in enumerate(timestamps):
        rows.append({
            "uid": f"I{index}", "source_ip": "10.60.0.10", "destination_ip": "8.8.8.8",
            "protocol": "icmp", "proto": "icmp", "icmp_type": 8, "timestamp": ts,
            "orig_ip_bytes": 128, "source_bytes": 128, "local_resp": False,
        })
    return AnalysisContext(connections=rows, metadata=_segments_metadata())


def _http_auth_context(AnalysisContext: type, timestamps: list[float]):
    rows = []
    for index, ts in enumerate(timestamps):
        rows.append({
            "uid": f"A{index}", "source_ip": "10.60.0.20", "destination_ip": "10.70.0.20",
            "destination_port": 80, "status_code": 401, "method": "GET", "timestamp": ts,
            "username": "operator",
        })
    return AnalysisContext(http=rows, metadata=_segments_metadata())


def _fanout_context(AnalysisContext: type, count: int, span: float):
    if count <= 1:
        timestamps = [0.0]
    else:
        step = span / (count - 1)
        timestamps = [round(index * step, 9) for index in range(count)]
    rows = []
    for index, ts in enumerate(timestamps):
        rows.append({
            "uid": f"F{index}", "source_ip": "10.60.0.30", "destination_ip": f"10.70.0.{index + 1}",
            "destination_port": 5020, "protocol": "tcp", "service": "custom", "timestamp": ts,
        })
    return AnalysisContext(connections=rows, metadata=_segments_metadata())


def _check_medium(result: object) -> None:
    assert result.findings and result.findings[0].severity == "medium"


def _check_high(result: object) -> None:
    assert result.findings and result.findings[0].severity == "high"


def _check_outbound_threshold(result: object) -> None:
    assert result.findings
    assert result.findings[0].metadata["anomaly_threshold_bytes"] == 10 * MIB
    assert result.findings[0].metadata["absolute_threshold_only"] is True


def cases() -> list[BoundaryCase]:
    return [
        BoundaryCase("HTTP upload one byte below minimum", "large_outbound_http_uploads", 0,
                     lambda A: _http_upload_context(A, 10 * MIB - 1)),
        BoundaryCase("HTTP upload exactly at minimum", "large_outbound_http_uploads", 1,
                     lambda A: _http_upload_context(A, 10 * MIB), _check_high),
        BoundaryCase("HTTP upload exactly at high threshold", "large_outbound_http_uploads", 1,
                     lambda A: _http_upload_context(A, 100 * MIB), _check_high),
        BoundaryCase("Outbound volume zero bytes", "unusual_outbound_data_volume", 0,
                     lambda A: _outbound_volume_context(A, 0)),
        BoundaryCase("Outbound volume one byte below minimum", "unusual_outbound_data_volume", 0,
                     lambda A: _outbound_volume_context(A, 10 * MIB - 1)),
        BoundaryCase("Outbound volume exactly at minimum", "unusual_outbound_data_volume", 1,
                     lambda A: _outbound_volume_context(A, 10 * MIB), _check_outbound_threshold),
        BoundaryCase("Outbound volume unusually large integer", "unusual_outbound_data_volume", 1,
                     lambda A: _outbound_volume_context(A, 8 * 1024 * MIB), _check_high),
        BoundaryCase("ICMP one event below minimum", "icmp_data_channel", 0,
                     lambda A: _icmp_context(A, 11, 60.0)),
        BoundaryCase("ICMP exact event and span thresholds", "icmp_data_channel", 1,
                     lambda A: _icmp_context(A, 12, 60.0), _check_medium),
        BoundaryCase("ICMP exact event count just below span", "icmp_data_channel", 0,
                     lambda A: _icmp_context(A, 12, 59.999)),
        BoundaryCase("HTTP auth one failure below minimum", "brute_force_authentication", 0,
                     lambda A: _http_auth_context(A, [0.0, 15.0, 30.0, 45.0])),
        BoundaryCase("HTTP auth exact failures at 60 second window", "brute_force_authentication", 1,
                     lambda A: _http_auth_context(A, [0.0, 15.0, 30.0, 45.0, 60.0])),
        BoundaryCase("HTTP auth failures outside 60 second window", "brute_force_authentication", 0,
                     lambda A: _http_auth_context(A, [0.0, 15.1, 30.2, 45.3, 60.4])),
        BoundaryCase("Fan-out one destination below minimum", "high_fan_in_out", 0,
                     lambda A: _fanout_context(A, 19, 60.0)),
        BoundaryCase("Fan-out exact destination and window thresholds", "high_fan_in_out", 1,
                     lambda A: _fanout_context(A, 20, 60.0)),
        BoundaryCase("Fan-out exact count outside window", "high_fan_in_out", 0,
                     lambda A: _fanout_context(A, 20, 60.001)),
    ]


def run_cases(verbose: bool = True) -> list[str]:
    AnalysisContext, modules, _module_file = ensure_detector_package()
    failures: list[str] = []
    if verbose:
        print("\n=== 06_threshold_boundaries: Exact thresholds and edge-condition semantics ===")
    for case in cases():
        result = modules[case.module_id].analyze(case.build_context(AnalysisContext))
        actual = len(result.findings)
        ok = actual == case.expected_findings
        if ok and case.check is not None:
            try:
                case.check(result)
            except AssertionError as exc:
                ok = False
                failures.append(f"{case.name}: semantic check failed: {exc}")
        if actual != case.expected_findings:
            failures.append(f"{case.name}: expected {case.expected_findings}, got {actual}")
        if verbose:
            print(f"{'PASS' if ok else 'FAIL':4}  {case.module_id:34} {case.name}")
    return failures


def main() -> int:
    failures = run_cases(verbose=True)
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1
    print(f"PASS: Dataset 06 verified {len(cases())} threshold/boundary cases.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
