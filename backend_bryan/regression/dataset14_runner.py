from __future__ import annotations

from typing import Any, Callable

from backend_bryan.integration.analysis_service import analyze_detection_request
from backend_bryan.integration.detector_runtime import ensure_detector_package


def _request() -> dict[str, Any]:
    _Context, modules, _path = ensure_detector_package()
    selected = sorted(modules)
    profile = {
        "schemaVersion": 3,
        "id": "regression-14",
        "name": "Regression 14 - Mixed OT Acceptance",
        "segments": [
            {"name": "Engineering", "cidr": "10.140.10.0/24", "role": "IT", "purdueLevel": "Level 4"},
            {"name": "Control", "cidr": "10.140.0.0/24", "role": "OT", "purdueLevel": "Level 1", "ipv6Allowed": False},
        ],
        "assets": [
            {"ip": "10.140.0.10", "role": "OT", "assetType": "PLC", "source": "user"},
            {"ip": "10.140.0.20", "role": "OT", "assetType": "PLC", "source": "user"},
            {"ip": "10.140.0.30", "role": "OT", "assetType": "PLC", "source": "user"},
            {"ip": "10.140.0.40", "role": "OT", "assetType": "Managed Switch", "source": "user"},
            {"ip": "10.140.0.99", "role": "OT", "assetType": "Unknown", "source": "zeek", "confidence": "high"},
        ],
        "infrastructure": [
            {"kind": "dns", "value": "10.140.10.53"},
            {"kind": "ntp", "value": "10.140.10.123"},
        ],
        "communicationPairs": [
            {"sourceIp": "10.140.10.99", "destinationIp": "10.140.0.10", "protocol": "modbus", "destinationPort": 502, "source": "zeek", "confidence": "high"}
        ],
        "allowedHosts": [],
        "allowedSegmentPairs": [],
        "approvedExternalDestinations": ["1.1.1.1"],
        "captureScope": {"internalIcsOnlyExpected": False, "dedicatedOtSensor": True, "ipv4OnlyExpected": True},
        "authorizedControlActions": [
            {"protocol": "modbus", "source": "10.140.10.50", "destination": "10.140.0.10", "allowedFunctionCodes": [6], "allowedOperations": ["write"]}
        ],
        "modulePolicies": {
            "snmp_write_ot_devices": {"target_hosts": ["10.140.0.40"], "allowed_managers": ["10.140.10.50"]},
            "bacnet_discovery_anomalies": {"window_seconds": 60, "who_is_threshold": 5, "i_am_threshold": 50, "allowed_discovery_sources": ["10.140.10.50"]},
        },
        "selectedModules": selected,
        "scan": {},
    }
    logs = {
        "connections": [
            {"uid": "A1", "timestamp": 1000.0, "source_ip": "10.140.0.10", "destination_ip": "10.140.10.53", "destination_port": 53, "protocol": "udp", "service": "dns", "conn_state": "SF", "orig_bytes": 50, "resp_bytes": 100},
            {"uid": "A2", "timestamp": 1001.0, "source_ip": "10.140.0.10", "destination_ip": "1.1.1.1", "destination_port": 443, "protocol": "tcp", "service": "ssl", "conn_state": "SF", "orig_bytes": 100, "resp_bytes": 100},
            {"uid": "A3", "timestamp": 1002.0, "source_ip": "10.140.0.10", "destination_ip": "8.8.8.8", "destination_port": 80, "protocol": "tcp", "service": "http", "conn_state": "SF", "orig_bytes": 200, "resp_bytes": 100},
        ],
        "modbus": [
            {"timestamp": 1003.0, "source_ip": "10.140.10.50", "source_port": 50000, "destination_ip": "10.140.0.10", "destination_port": 502, "function_code": 6},
            {"timestamp": 1004.0, "source_ip": "10.140.10.99", "source_port": 50001, "destination_ip": "10.140.0.10", "destination_port": 502, "function_code": 6},
        ],
        "s7comm": [{"timestamp": 1005.0, "source_ip": "10.140.10.99", "destination_ip": "10.140.0.20", "destination_port": 102, "function_code": 5}],
        "enip": [{"timestamp": 1006.0, "source_ip": "10.140.10.99", "destination_ip": "10.140.0.30", "destination_port": 44818, "cip_service": 77, "success": True}],
        "snmp": [{"timestamp": 1007.0, "source_ip": "10.140.10.99", "destination_ip": "10.140.0.40", "destination_port": 161, "version": 2, "community": "private", "set_requests": 1}],
        "bacnet": [
            {"timestamp": 1010.0 + i, "source_ip": "10.140.10.99", "destination_ip": "10.140.0.255", "destination_port": 47808, "function": "Who-Is"}
            for i in range(5)
        ],
        "weird": [{"timestamp": 1020.0, "source_ip": "10.140.0.10", "destination_ip": "10.140.10.5", "name": "bad_TCP_checksum", "addl": "synthetic acceptance anomaly"}],
    }
    return {"contractVersion": "elevadr.detection-context.analysis.v1", "profile": profile, "logs": logs}


def run_cases(verbose: bool = True) -> list[str]:
    failures: list[str] = []
    passed = 0
    response = analyze_detection_request(_request())
    results = {item.get("module_id"): item for item in response.get("moduleResults", [])}

    def check(label: str, fn: Callable[[], None]) -> None:
        nonlocal passed
        try: fn()
        except Exception as exc:
            failures.append(f"{label}: {type(exc).__name__}: {exc}")
            if verbose: print(f"FAIL  {label} ({type(exc).__name__}: {exc})")
        else:
            passed += 1
            if verbose: print(f"PASS  {label}")

    if verbose:
        print("\n=== 14_mixed_ot_acceptance: Full 75-module mixed-policy acceptance scenario ===")

    check("All 75 detector modules complete the mixed OT acceptance request", lambda: (
        (response["status"] == "completed" and response["summary"]["requestedModules"] == 75 and response["summary"]["completedModules"] == 75 and response["summary"]["failedModules"] == 0) or (_ for _ in ()).throw(AssertionError(response.get("errors")))
    ))
    check("Authorized Modbus path suppresses its matching write while observed unauthorized neighbor still finds", lambda: (
        (len(results["ics_write_operations"]["findings"]) == 1) or (_ for _ in ()).throw(AssertionError(results["ics_write_operations"]))
    ))
    check("Unauthorized S7 write is retained", lambda: (len(results["s7comm_unauthorized_write_stop"]["findings"]) >= 1) or (_ for _ in ()).throw(AssertionError()))
    check("Unauthorized EtherNet/IP CIP write is retained", lambda: (len(results["enip_cip_write_session_abuses"]["findings"]) >= 1) or (_ for _ in ()).throw(AssertionError()))
    check("Unauthorized SNMP SET is retained", lambda: (len(results["snmp_write_ot_devices"]["findings"]) >= 1) or (_ for _ in ()).throw(AssertionError()))
    check("BACnet discovery burst/non-BAS behavior is detected", lambda: (len(results["bacnet_discovery_anomalies"]["findings"]) >= 1) or (_ for _ in ()).throw(AssertionError()))
    check("Approved external destination does not suppress different unapproved OT egress", lambda: (len(results["ot_outbound_internet_any_protocol"]["findings"]) >= 1) or (_ for _ in ()).throw(AssertionError()))
    check("Observed Zeek communication does not broaden Modbus authorization", lambda: (
        any(f.get("metadata", {}).get("unauthorized_operation_confirmed") is True or f.get("metadata", {}).get("policy_status") in {"unprofiled_write", "outside_allowed_path"} for f in results["ics_write_operations"]["findings"]) or (_ for _ in ()).throw(AssertionError())
    ))
    check("SNMP credential material is redacted from returned finding flows", lambda: (
        all(row.get("community") in (None, "", "[REDACTED]") for f in results["snmp_write_ot_devices"]["findings"] for row in f.get("flows", [])) or (_ for _ in ()).throw(AssertionError())
    ))
    check("Mixed scenario produces findings without detector errors", lambda: (
        (response["summary"]["findingCount"] > 0 and response["errors"] == []) or (_ for _ in ()).throw(AssertionError())
    ))

    if verbose:
        print(f"{'FAIL' if failures else 'PASS'}: Dataset 14 verified {passed} mixed-OT acceptance cases with {response['summary']['findingCount']} total finding(s).")
    return failures


def main() -> int:
    return 1 if run_cases(True) else 0

if __name__ == "__main__":
    raise SystemExit(main())
