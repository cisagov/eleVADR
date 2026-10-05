from __future__ import annotations

from typing import Callable

from backend_bryan.adapters.detection_context_adapter import compile_detection_context_metadata
from backend_bryan.integration.detector_runtime import ensure_detector_package

EXPECTED_MODULE_COUNT = 75
NEW_MODULES = {
    "arp_ip_mac_identity_change",
    "unexpected_dhcp_server",
    "ot_protocol_role_reversal",
    "plc_rtu_peer_change",
    "engineering_workstation_control_burst",
}


def _profile() -> dict:
    return {
        "schemaVersion": 3,
        "id": "new-detector-acceptance",
        "name": "New Detector Acceptance",
        "captureScope": {}, "scan": {},
        "segments": [],
        "assets": [
            {"ip": "10.150.0.20", "hostname": "PLC-20", "macAddresses": ["00:11:22:33:44:55"], "assetType": "PLC", "role": "OT", "source": "user"},
            {"ip": "10.150.0.50", "hostname": "EWS-50", "macAddresses": [], "assetType": "Engineering Workstation", "role": "IT", "source": "user"},
        ],
        "infrastructure": [{"kind": "dhcp", "value": "10.150.0.2"}],
        "communicationPairs": [], "allowedHosts": [], "allowedSegmentPairs": [], "approvedExternalDestinations": [],
        "authorizedControlActions": [{"protocol": "modbus", "source": "10.150.0.50", "destination": "10.150.0.20", "allowedFunctionCodes": [6], "allowedOperations": ["write"]}],
        "modulePolicies": {
            "engineering_workstation_control_burst": {"minimum_operations": 5, "window_seconds": 60},
        },
        "selectedModules": sorted(NEW_MODULES),
    }


def run_cases(verbose: bool = True) -> list[str]:
    Context, modules, _ = ensure_detector_package()
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
        print("\n=== New detector acceptance: five additional OT/network modules ===")

    check("Registry contains 75 modules including all five Wave 1 additions", lambda: (
        (len(modules) == EXPECTED_MODULE_COUNT and NEW_MODULES.issubset(modules)) or (_ for _ in ()).throw(AssertionError(sorted(NEW_MODULES - set(modules))))
    ))

    metadata = compile_detection_context_metadata(_profile())

    arp = modules["arp_ip_mac_identity_change"].analyze(Context(
        arp=[
            {"ts": 1.0, "sender_ip": "10.150.0.20", "sender_mac": "00:11:22:33:44:55"},
            {"ts": 2.0, "sender_ip": "10.150.0.20", "sender_mac": "66:77:88:99:aa:bb"},
        ], metadata=metadata,
    ))
    check("ARP/IP-MAC identity detector catches authoritative mismatch", lambda: (
        len(arp.findings) >= 1 or (_ for _ in ()).throw(AssertionError(arp.metrics))
    ))

    dhcp = modules["unexpected_dhcp_server"].analyze(Context(
        dhcp=[{"ts": 1.0, "server_message": "DHCP OFFER", "server_ip": "10.150.0.99", "client_ip": "10.150.0.30"}],
        metadata=metadata,
    ))
    check("Unexpected DHCP server detector honors trusted infrastructure", lambda: (
        len(dhcp.findings) == 1 or (_ for _ in ()).throw(AssertionError(dhcp.metrics))
    ))

    role = modules["ot_protocol_role_reversal"].analyze(Context(connections=[
        {"timestamp": 0.0, "source_ip": "10.150.0.50", "destination_ip": "10.150.0.20", "destination_port": 502, "service": "modbus"},
        {"timestamp": 20.0, "source_ip": "10.150.0.51", "destination_ip": "10.150.0.20", "destination_port": 502, "service": "modbus"},
        {"timestamp": 400.0, "source_ip": "10.150.0.20", "destination_ip": "10.150.0.60", "destination_port": 502, "service": "modbus"},
    ], metadata=metadata))
    check("OT role-reversal detector catches responder becoming originator", lambda: (
        len(role.findings) == 1 or (_ for _ in ()).throw(AssertionError(role.metrics))
    ))

    peer = modules["plc_rtu_peer_change"].analyze(Context(connections=[
        {"timestamp": 0.0, "source_ip": "10.150.0.50", "destination_ip": "10.150.0.20", "destination_port": 502, "service": "modbus"},
        {"timestamp": 400.0, "source_ip": "10.150.0.99", "destination_ip": "10.150.0.20", "destination_port": 502, "service": "modbus"},
    ], metadata=metadata))
    check("PLC/RTU peer-change detector catches post-baseline peer", lambda: (
        len(peer.findings) == 1 or (_ for _ in ()).throw(AssertionError(peer.metrics))
    ))

    burst = modules["engineering_workstation_control_burst"].analyze(Context(
        modbus=[
            {"timestamp": float(i), "source_ip": "10.150.0.50", "destination_ip": "10.150.0.20", "destination_port": 502, "function_code": 6}
            for i in range(5)
        ], metadata=metadata,
    ))
    check("Engineering control-burst detector fires even on explicitly authorized path", lambda: (
        (len(burst.findings) == 1 and burst.findings[0].metadata.get("authorized_operation_count") == 5) or (_ for _ in ()).throw(AssertionError(burst.metrics))
    ))

    if verbose:
        print(f"{'FAIL' if failures else 'PASS'}: New detector acceptance verified {passed} cases.")
    return failures


def main() -> int:
    return 1 if run_cases(True) else 0


if __name__ == "__main__":
    raise SystemExit(main())
