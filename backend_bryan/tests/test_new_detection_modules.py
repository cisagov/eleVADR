from __future__ import annotations

from backend_bryan.adapters.detection_context_adapter import compile_detection_context_metadata
from backend_bryan.integration.detector_runtime import ensure_detector_package


Context, MODULES, _ = ensure_detector_package()


def test_arp_ip_mac_identity_change_uses_authoritative_inventory_only() -> None:
    ctx = Context(
        arp=[
            {"ts": 1.0, "sender_ip": "10.1.0.20", "sender_mac": "00:11:22:33:44:55"},
            {"ts": 2.0, "sender_ip": "10.1.0.20", "sender_mac": "66:77:88:99:aa:bb"},
        ],
        metadata={"asset_inventory": [{"ip": "10.1.0.20", "ips": ["10.1.0.20"], "macs": ["00:11:22:33:44:55"], "asset_type": "plc"}]},
    )
    result = MODULES["arp_ip_mac_identity_change"].analyze(ctx)
    assert len(result.findings) == 2
    assert any("unexpected MAC" in finding.title for finding in result.findings)
    assert any("multiple MAC" in finding.title for finding in result.findings)


def test_unexpected_dhcp_server_requires_explicit_trusted_infrastructure() -> None:
    profile = {
        "schemaVersion": 3,
        "id": "dhcp-test",
        "name": "DHCP Test",
        "segments": [], "assets": [], "communicationPairs": [], "allowedHosts": [],
        "allowedSegmentPairs": [], "approvedExternalDestinations": [], "authorizedControlActions": [],
        "captureScope": {}, "scan": {}, "modulePolicies": {},
        "infrastructure": [{"kind": "dhcp", "value": "10.2.0.2"}],
    }
    metadata = compile_detection_context_metadata(profile)
    ctx = Context(dhcp=[
        {"ts": 1.0, "server_message": "DHCP ACK", "server_ip": "10.2.0.2", "client_ip": "10.2.0.20"},
        {"ts": 2.0, "server_message": "DHCP OFFER", "server_ip": "10.2.0.99", "client_ip": "10.2.0.21"},
    ], metadata=metadata)
    result = MODULES["unexpected_dhcp_server"].analyze(ctx)
    assert len(result.findings) == 1
    assert result.findings[0].devices == ["10.2.0.99"]


def test_ot_protocol_role_reversal_detects_responder_becoming_originator() -> None:
    ctx = Context(connections=[
        {"timestamp": 0.0, "source_ip": "10.3.0.50", "destination_ip": "10.3.0.20", "destination_port": 502, "service": "modbus"},
        {"timestamp": 30.0, "source_ip": "10.3.0.51", "destination_ip": "10.3.0.20", "destination_port": 502, "service": "modbus"},
        {"timestamp": 400.0, "source_ip": "10.3.0.20", "destination_ip": "10.3.0.60", "destination_port": 502, "service": "modbus"},
    ], metadata={})
    result = MODULES["ot_protocol_role_reversal"].analyze(ctx)
    assert len(result.findings) == 1
    assert result.findings[0].devices[0] == "10.3.0.20"


def test_plc_rtu_peer_change_uses_authoritative_controller_identity() -> None:
    ctx = Context(connections=[
        {"timestamp": 0.0, "source_ip": "10.4.0.50", "destination_ip": "10.4.0.20", "destination_port": 502, "service": "modbus"},
        {"timestamp": 400.0, "source_ip": "10.4.0.99", "destination_ip": "10.4.0.20", "destination_port": 502, "service": "modbus"},
    ], metadata={"asset_inventory": [{"ip": "10.4.0.20", "ips": ["10.4.0.20"], "asset_type": "PLC", "role": "ot"}]})
    result = MODULES["plc_rtu_peer_change"].analyze(ctx)
    assert len(result.findings) == 1
    assert {"10.4.0.20", "10.4.0.99"}.issubset(set(result.findings[0].devices))


def test_engineering_workstation_control_burst_reports_even_authorized_burst() -> None:
    profile = {
        "schemaVersion": 3,
        "id": "eng-burst",
        "name": "Engineering burst",
        "segments": [],
        "assets": [
            {"ip": "10.5.0.50", "hostname": "EWS-01", "assetType": "Engineering Workstation", "role": "IT", "source": "user"},
            {"ip": "10.5.0.20", "assetType": "PLC", "role": "OT", "source": "user"},
        ],
        "infrastructure": [], "communicationPairs": [], "allowedHosts": [], "allowedSegmentPairs": [],
        "approvedExternalDestinations": [], "captureScope": {}, "scan": {},
        "authorizedControlActions": [{"protocol": "modbus", "source": "10.5.0.50", "destination": "10.5.0.20", "allowedFunctionCodes": [6], "allowedOperations": ["write"]}],
        "modulePolicies": {"engineering_workstation_control_burst": {"minimum_operations": 5, "window_seconds": 60}},
    }
    metadata = compile_detection_context_metadata(profile)
    ctx = Context(modbus=[
        {"timestamp": float(i), "source_ip": "10.5.0.50", "destination_ip": "10.5.0.20", "destination_port": 502, "function_code": 6}
        for i in range(5)
    ], metadata=metadata)
    result = MODULES["engineering_workstation_control_burst"].analyze(ctx)
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.metadata["authorized_operation_count"] == 5
    assert finding.metadata["unauthorized_operation_count"] == 0
    assert finding.metadata["authorized_paths_do_not_suppress_burst_behavior"] is True
