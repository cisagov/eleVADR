from __future__ import annotations

from copy import deepcopy
from typing import Any, Callable

from backend_bryan.integration.detector_runtime import ensure_detector_package


def _segments_metadata() -> dict[str, Any]:
    return {
        "segments": [
            {"name": "OT", "cidr": "10.80.0.0/24", "role": "OT", "trust_zone": "ot", "purdue_level": "Level 2"},
            {"name": "Enterprise", "cidr": "10.90.0.0/24", "role": "IT", "trust_zone": "enterprise", "purdue_level": "Level 4"},
        ],
        "asset_inventory": [
            {"ip": "10.80.0.10", "role": "PLC", "name": "PLC-A"},
            {"ip": "10.80.0.20", "role": "HMI", "name": "HMI-A"},
        ],
    }


def _conn(uid: str, ts: float, src: str = "10.80.0.10", dst: str = "203.0.113.10", port: int = 4444,
          service: str = "custom", protocol: str = "tcp", source_bytes: int = 1000) -> dict[str, Any]:
    return {
        "uid": uid,
        "timestamp": ts,
        "source_ip": src,
        "destination_ip": dst,
        "destination_port": port,
        "protocol": protocol,
        "service": service,
        "local_orig": True,
        "local_resp": False,
        "source_bytes": source_bytes,
        "orig_ip_bytes": source_bytes,
    }


def _serialized(result: Any) -> dict[str, Any]:
    return result.to_dict() if hasattr(result, "to_dict") else dict(result)


def _beacon_context(A: type, order: list[int] | None = None, duplicate_each: bool = False):
    timestamps = [0.0, 15.0, 30.0, 45.0, 60.0, 75.0]
    rows = [_conn(f"B{i}", ts) for i, ts in enumerate(timestamps)]
    if duplicate_each:
        rows = [row for item in rows for row in (item, {**item, "uid": item["uid"] + "D"})]
    if order is not None:
        rows = [rows[i] for i in order]
    return A(connections=rows, metadata=_segments_metadata())


def _bruteforce_context(A: type, reverse: bool = False):
    times = [0.0, 15.0, 30.0, 45.0, 60.0]
    rows = [
        {
            "uid": f"A{i}", "timestamp": ts, "source_ip": "10.90.0.10", "destination_ip": "10.80.0.20",
            "destination_port": 80, "status_code": 401, "method": "GET", "username": "operator",
        }
        for i, ts in enumerate(times)
    ]
    if reverse:
        rows.reverse()
    return A(http=rows, metadata=_segments_metadata())


def _new_service_context(A: type, reverse: bool = False, boundary_only: bool = False):
    rows = [
        _conn("S0", 0.0, "10.90.0.10", "10.80.0.10", 502, "modbus"),
        _conn("S1", 100.0, "10.90.0.10", "10.80.0.10", 502, "modbus"),
        _conn("S2", 200.0, "10.90.0.10", "10.80.0.10", 502, "modbus"),
        _conn("S3", 300.0, "10.90.0.10", "10.80.0.10", 44818 if boundary_only else 502,
              "ethernetip" if boundary_only else "modbus"),
        _conn("S4", 360.0, "10.90.0.10", "10.80.0.10", 44818, "ethernetip"),
    ]
    if reverse:
        rows.reverse()
    return A(connections=rows, metadata=_segments_metadata())


def _new_pair_context(A: type, reverse_order: bool = False):
    rows = [
        _conn("P0", 0.0, "10.80.0.10", "10.90.0.10", 502, "modbus"),
        _conn("P1", 100.0, "10.80.0.10", "10.90.0.10", 502, "modbus"),
        _conn("P2", 200.0, "10.80.0.10", "10.90.0.10", 502, "modbus"),
        _conn("P3", 360.0, "10.90.0.10", "10.80.0.10", 502, "modbus"),
    ]
    if reverse_order:
        rows.reverse()
    return A(connections=rows, metadata=_segments_metadata())


def _gone_silent_context(A: type, reverse: bool = False):
    # Four regular baseline observations at 60-second cadence, followed by an unrelated
    # event extending capture_end far enough for the learned conversation to be stale.
    rows = [
        _conn("G0", 0.0, "10.80.0.10", "10.90.0.10", 502, "modbus"),
        _conn("G1", 60.0, "10.80.0.10", "10.90.0.10", 502, "modbus"),
        _conn("G2", 120.0, "10.80.0.10", "10.90.0.10", 502, "modbus"),
        _conn("G3", 180.0, "10.80.0.10", "10.90.0.10", 502, "modbus"),
        _conn("GX", 600.0, "10.80.0.20", "10.90.0.20", 443, "ssl"),
    ]
    if reverse:
        rows.reverse()
    return A(connections=rows, metadata=_segments_metadata())


def _rich_context(A: type):
    # A compact context that exercises several temporal detectors. It is intentionally
    # self-contained so any module state retained after this run would be observable on
    # a subsequent empty-context pass.
    connections = [_conn(f"R{i}", float(i * 15)) for i in range(6)]
    connections.extend([
        _conn("RP0", 0.0, "10.80.0.10", "10.90.0.10", 502, "modbus"),
        _conn("RP1", 360.0, "10.90.0.10", "10.80.0.10", 502, "modbus"),
    ])
    http = [
        {"uid": f"RH{i}", "timestamp": float(i * 15), "source_ip": "10.90.0.10",
         "destination_ip": "10.80.0.20", "destination_port": 80, "status_code": 401,
         "method": "GET", "username": "operator"}
        for i in range(5)
    ]
    weird = [{"timestamp": 10.0, "source_ip": "10.80.0.10", "destination_ip": "10.90.0.10", "name": "bad_TCP_checksum"}]
    return A(connections=connections, http=http, weird=weird, metadata=_segments_metadata())


def _empty_context(A: type):
    return A(metadata=_segments_metadata())


def _compare(module: Any, left: Any, right: Any, label: str, failures: list[str]) -> None:
    a = _serialized(module.analyze(left))
    b = _serialized(module.analyze(right))
    if a != b:
        failures.append(f"{label}: result changed when logically equivalent input ordering/state was used")


def run_cases(verbose: bool = True) -> list[str]:
    AnalysisContext, modules, _module_file = ensure_detector_package()
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
        print("\n=== 07_stateful_temporal: Multi-window ordering and cross-run state isolation ===")

    def beacon_ordering() -> None:
        module = modules["beaconing_c2_communication"]
        ordered = _serialized(module.analyze(_beacon_context(AnalysisContext)))
        shuffled_rows = _beacon_context(AnalysisContext)
        shuffled_rows.connections = [shuffled_rows.connections[i] for i in [5, 1, 4, 0, 3, 2]]
        shuffled = _serialized(module.analyze(shuffled_rows))
        assert ordered == shuffled
        assert len(ordered["findings"]) == 1
    check("Beaconing is invariant to out-of-order conn timestamps", beacon_ordering)

    def beacon_duplicates() -> None:
        result = modules["beaconing_c2_communication"].analyze(_beacon_context(AnalysisContext, duplicate_each=True))
        assert len(result.findings) == 1
        assert result.findings[0].metadata["event_count"] == 6
    check("Beaconing duplicate rows do not inflate unique timestamp event count", beacon_duplicates)

    def brute_ordering() -> None:
        module = modules["brute_force_authentication"]
        a = _serialized(module.analyze(_bruteforce_context(AnalysisContext, False)))
        b = _serialized(module.analyze(_bruteforce_context(AnalysisContext, True)))
        assert a == b and len(a["findings"]) == 1
    check("Brute-force windowing is invariant to input ordering", brute_ordering)

    def service_ordering() -> None:
        module = modules["new_service_emergence_ot"]
        a = _serialized(module.analyze(_new_service_context(AnalysisContext, False)))
        b = _serialized(module.analyze(_new_service_context(AnalysisContext, True)))
        assert a == b and len(a["findings"]) == 1
    check("New-service baseline is invariant to input ordering", service_ordering)

    def service_boundary_tie() -> None:
        result = modules["new_service_emergence_ot"].analyze(_new_service_context(AnalysisContext, boundary_only=True))
        # EtherNet/IP first appears exactly at baseline_end, so it belongs to the baseline
        # and the later repetition must not be reported as a new service.
        assert len(result.findings) == 0
        assert result.evidence["baseline_end"] == 300.0
    check("Service first seen exactly at baseline_end is baseline, not post-baseline drift", service_boundary_tie)

    def pair_directionality() -> None:
        module = modules["new_ot_conversation_pair"]
        a = _serialized(module.analyze(_new_pair_context(AnalysisContext, False)))
        b = _serialized(module.analyze(_new_pair_context(AnalysisContext, True)))
        assert a == b and len(a["findings"]) == 1
        finding = a["findings"][0]
        assert finding["connection_pairs"][0] == {"source": "10.90.0.10", "destination": "10.80.0.10"}
    check("Communication-matrix baseline stays directional and order independent", pair_directionality)

    def gone_silent_ordering() -> None:
        module = modules["ot_asset_gone_silent"]
        a = _serialized(module.analyze(_gone_silent_context(AnalysisContext, False)))
        b = _serialized(module.analyze(_gone_silent_context(AnalysisContext, True)))
        assert a == b
        assert len(a["findings"]) >= 1
    check("Gone-silent cadence analysis is invariant to out-of-order rows", gone_silent_ordering)

    def same_instance_determinism() -> None:
        ids = [
            "beaconing_c2_communication", "brute_force_authentication", "new_service_emergence_ot",
            "new_ot_conversation_pair", "ot_asset_gone_silent", "high_fan_in_out",
            "unusual_outbound_data_volume", "icmp_data_channel",
        ]
        builders = {
            "beaconing_c2_communication": lambda: _beacon_context(AnalysisContext),
            "brute_force_authentication": lambda: _bruteforce_context(AnalysisContext),
            "new_service_emergence_ot": lambda: _new_service_context(AnalysisContext),
            "new_ot_conversation_pair": lambda: _new_pair_context(AnalysisContext),
            "ot_asset_gone_silent": lambda: _gone_silent_context(AnalysisContext),
            "high_fan_in_out": lambda: _rich_context(AnalysisContext),
            "unusual_outbound_data_volume": lambda: _rich_context(AnalysisContext),
            "icmp_data_channel": lambda: _rich_context(AnalysisContext),
        }
        for module_id in ids:
            module = modules[module_id]
            first = _serialized(module.analyze(builders[module_id]()))
            second = _serialized(module.analyze(builders[module_id]()))
            assert first == second, module_id
    check("Repeated analysis on singleton module instances is deterministic", same_instance_determinism)

    def all_modules_empty_state_reset() -> None:
        before = {mid: _serialized(module.analyze(_empty_context(AnalysisContext))) for mid, module in modules.items()}
        rich = _rich_context(AnalysisContext)
        for module in modules.values():
            # Each module receives its own copy so a detector cannot alter another detector's input.
            module.analyze(deepcopy(rich))
        after = {mid: _serialized(module.analyze(_empty_context(AnalysisContext))) for mid, module in modules.items()}
        assert set(before) == set(after) and len(before) == 75
        changed = [mid for mid in before if before[mid] != after[mid]]
        assert not changed, changed
    check("All 75 singleton detectors reset cleanly between independent analyses", all_modules_empty_state_reset)

    def trigger_clean_trigger() -> None:
        module = modules["beaconing_c2_communication"]
        first = _serialized(module.analyze(_beacon_context(AnalysisContext)))
        clean = _serialized(module.analyze(_empty_context(AnalysisContext)))
        third = _serialized(module.analyze(_beacon_context(AnalysisContext)))
        assert len(first["findings"]) == 1
        assert len(clean["findings"]) == 0
        assert first == third
    check("Finding-producing run does not contaminate a clean run or the next run", trigger_clean_trigger)

    def context_not_mutated() -> None:
        ctx = _rich_context(AnalysisContext)
        original = deepcopy(ctx)
        for module in modules.values():
            module.analyze(ctx)
        # The shared context is intended to be read-only from detector perspective.
        assert ctx == original
    check("Detector pass does not mutate shared AnalysisContext evidence or metadata", context_not_mutated)

    if verbose:
        print(f"PASS: Dataset 07 verified {passed} temporal/state-isolation cases." if not failures else f"FAIL: {len(failures)} Dataset 07 case(s) failed.")
    return failures


def main() -> int:
    failures = run_cases(verbose=True)
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
