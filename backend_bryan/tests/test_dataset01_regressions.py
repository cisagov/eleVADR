from __future__ import annotations

from backend_bryan.adapters.detection_context_adapter import compile_detection_context_metadata
from backend_bryan.integration.report_builder import build_elevadr_report
from elevadr_modules.models import AnalysisContext
from elevadr_modules.modules.control_system_enterprise_non_dmz import ControlSystemEnterpriseNonDmzModule


def _profile() -> dict:
    return {
        "schemaVersion": 3,
        "id": "dataset-01-regression",
        "name": "Dataset 01 Regression",
        "selectedModules": ["control_system_enterprise_non_dmz"],
        "captureScope": {
            "internalIcsOnlyExpected": True,
            "dedicatedOtSensor": True,
            "ipv4OnlyExpected": True,
        },
        "segments": [
            {
                "id": "eng",
                "name": "Engineering & Services",
                "cidr": "10.10.0.0/24",
                "role": "it",
                "purdueLevel": "Level 3",
                "addressing": "static",
                "dhcpAllowed": False,
                "ipv6Allowed": False,
            },
            {
                "id": "ot",
                "name": "OT Control",
                "cidr": "10.20.0.0/24",
                "role": "ot",
                "purdueLevel": "Level 2",
                "addressing": "static",
                "dhcpAllowed": False,
                "ipv6Allowed": False,
            },
        ],
        "assets": [
            {"id": "eng-ws", "ip": "10.10.0.10", "hostname": "eng-ws-01", "assetType": "engineering workstation", "role": "engineering", "segment": "Engineering & Services", "purdueLevel": "Level 3", "macAddresses": []},
            {"id": "dns", "ip": "10.10.0.53", "hostname": "ot-dns-01", "assetType": "infrastructure server", "role": "dns", "segment": "Engineering & Services", "purdueLevel": "Level 3", "macAddresses": []},
            {"id": "ntp", "ip": "10.10.0.123", "hostname": "ot-ntp-01", "assetType": "infrastructure server", "role": "ntp", "segment": "Engineering & Services", "purdueLevel": "Level 3", "macAddresses": []},
            {"id": "plc", "ip": "10.20.0.20", "hostname": "plc-01", "assetType": "PLC", "role": "ot controller", "segment": "OT Control", "purdueLevel": "Level 1", "macAddresses": []},
            {"id": "hmi", "ip": "10.20.0.30", "hostname": "hmi-01", "assetType": "HMI", "role": "ot operator station", "segment": "OT Control", "purdueLevel": "Level 2", "macAddresses": []},
        ],
        "infrastructure": [
            {"id": "dns-i", "kind": "dns", "value": "10.10.0.53", "label": "Trusted DNS"},
            {"id": "ntp-i", "kind": "ntp", "value": "10.10.0.123", "label": "Trusted NTP"},
        ],
        "communicationPairs": [],
        "allowedHosts": [],
        "allowedSegmentPairs": [],
        "approvedExternalDestinations": [],
        "authorizedControlActions": [],
        "modulePolicies": {},
        "scan": {"filesScanned": 0, "recordsParsed": 0, "logTypes": {}, "warnings": []},
    }


def _connections() -> list[dict]:
    return [
        {"source_ip": "10.10.0.10", "destination_ip": "10.10.0.53", "source_port": 53000, "destination_port": 53, "protocol": "udp", "service": "dns", "zeek_state": "SF", "source_bytes": 31, "destination_bytes": 47},
        {"source_ip": "10.10.0.10", "destination_ip": "10.10.0.123", "source_port": 51000, "destination_port": 123, "protocol": "udp", "service": "ntp", "zeek_state": "SF", "source_bytes": 48, "destination_bytes": 48},
        {"source_ip": "10.10.0.10", "destination_ip": "10.20.0.20", "source_port": 40000, "destination_port": 502, "protocol": "tcp", "service": "modbus", "conn_state": "SF", "orig_bytes": 12, "resp_bytes": 13},
        {"source_ip": "10.10.0.10", "destination_ip": "10.20.0.30", "source_port": 40001, "destination_port": 80, "protocol": "tcp", "service": "http", "conn_state": "SF", "orig_bytes": 89, "resp_bytes": 66},
    ]


def test_report_respects_segment_role_over_descriptive_asset_role():
    profile = _profile()
    context = AnalysisContext(connections=_connections(), metadata=compile_detection_context_metadata(profile))
    report = build_elevadr_report(
        source_filename="01_mixed_ot_baseline.pcap",
        profile=profile,
        context=context,
        module_results=[],
        module_errors=[],
    )
    panel = report["modules"]["device_panel"]
    assert panel["hosts"] == 5
    assert panel["ot_hosts"] == 2
    assert panel["it_hosts"] == 3


def test_trusted_dns_ntp_do_not_become_direct_ot_enterprise_findings():
    profile = _profile()
    metadata = compile_detection_context_metadata(profile)
    trusted = metadata["control_system_enterprise_policy"]["trusted_service_hosts"]
    assert {item["host"] for item in trusted} == {"10.10.0.53", "10.10.0.123"}

    context = AnalysisContext(connections=_connections(), metadata=metadata)
    result = ControlSystemEnterpriseNonDmzModule().analyze(context)
    # Engineering & Services is explicitly IT, so DNS/NTP are same-zone and should
    # not be flagged.  The IT-to-OT Modbus/HTTP paths remain architecture findings.
    assert len(result.findings) == 2
    assert {tuple(f.devices) for f in result.findings} == {
        ("10.10.0.10", "10.20.0.20"),
        ("10.10.0.10", "10.20.0.30"),
    }


def test_trusted_service_host_suppression_is_service_scoped():
    profile = _profile()
    # Move the engineering workstation into OT so its DNS query really crosses OT->IT.
    profile["segments"][0]["role"] = "ot"
    profile["segments"][0]["name"] = "OT Engineering"
    for asset in profile["assets"][:3]:
        asset["segment"] = "OT Engineering"
    # Put trusted infrastructure into a separate IT segment.
    profile["segments"].append({
        "id": "infra", "name": "Enterprise Infrastructure", "cidr": "10.30.0.0/24", "role": "it",
        "purdueLevel": "Level 4", "addressing": "static", "dhcpAllowed": False, "ipv6Allowed": False,
    })
    profile["assets"][1]["ip"] = "10.30.0.53"
    profile["assets"][1]["segment"] = "Enterprise Infrastructure"
    profile["infrastructure"][0]["value"] = "10.30.0.53"
    metadata = compile_detection_context_metadata(profile)
    connections = [
        {"source_ip": "10.10.0.10", "destination_ip": "10.30.0.53", "destination_port": 53, "protocol": "udp", "service": "dns", "conn_state": "SF"},
        {"source_ip": "10.10.0.10", "destination_ip": "10.30.0.53", "destination_port": 3389, "protocol": "tcp", "service": "rdp", "conn_state": "SF"},
    ]
    result = ControlSystemEnterpriseNonDmzModule().analyze(AnalysisContext(connections=connections, metadata=metadata))
    assert len(result.findings) == 1
    assert result.findings[0].ports == [3389]


def _short_capture_connections() -> list[dict]:
    rows = _connections()
    for index, row in enumerate(rows):
        row["timestamp"] = 1760000000.0 + (index * 0.1)
    return rows


def test_short_capture_new_ot_pair_counts_responder_side_ot_observations():
    from elevadr_modules.modules.new_ot_conversation_pair import NewOtConversationPairModule

    profile = _profile()
    metadata = compile_detection_context_metadata(profile)
    result = NewOtConversationPairModule().analyze(
        AnalysisContext(connections=_short_capture_connections(), metadata=metadata)
    )

    # The capture is intentionally shorter than the 300-second learning window,
    # so drift cannot be evaluated yet.  It should still report the two flows
    # whose responder belongs to the configured OT segment.
    assert result.findings == []
    assert result.metrics["ot_involving_connections"] == 2
    assert result.metrics["baseline_directed_pairs"] == 2
    assert result.metrics["skipped_unclassified"] == 2
    assert any("does not extend beyond" in note for note in result.evidence["notes"])


def test_short_capture_gone_silent_counts_responder_side_ot_observations():
    from elevadr_modules.modules.ot_asset_gone_silent import OtAssetGoneSilentModule

    profile = _profile()
    metadata = compile_detection_context_metadata(profile)
    result = OtAssetGoneSilentModule().analyze(
        AnalysisContext(connections=_short_capture_connections(), metadata=metadata)
    )

    # Each IT->OT flow contributes one OT endpoint observation even though the
    # capture is too short to learn periodicity or assert a silence condition.
    assert result.findings == []
    assert result.metrics["ot_observations"] == 2
    assert result.metrics["ot_hosts_observed"] == 2
    assert result.metrics["baseline_conversations"] == 2
    assert result.metrics["periodic_conversations_learned"] == 0
    assert any("does not extend beyond" in note for note in result.evidence["notes"])


def test_broadcast_multicast_detector_remains_source_ot_scoped():
    from elevadr_modules.modules.excessive_broadcast_multicast_ot import ExcessiveBroadcastMulticastOtModule

    profile = _profile()
    metadata = compile_detection_context_metadata(profile)
    result = ExcessiveBroadcastMulticastOtModule().analyze(
        AnalysisContext(connections=_short_capture_connections(), metadata=metadata)
    )

    # This detector measures traffic *originating from* OT segments; inbound
    # IT->OT flows are intentionally not part of its broadcast/multicast rate
    # denominator.  A zero here is correct and is distinct from endpoint
    # classification in the two baseline-oriented detectors above.
    assert result.metrics["ot_connections_evaluated"] == 0


def test_ot_outbound_detector_respects_explicit_it_segment_over_engineering_asset_label():
    from elevadr_modules.modules.ot_outbound_internet_any_protocol import OtOutboundInternetAnyProtocolModule

    profile = _profile()
    metadata = compile_detection_context_metadata(profile)
    connections = [{
        "timestamp": 1760000000.0,
        "source_ip": "10.10.0.10",
        "destination_ip": "8.8.8.8",
        "destination_port": 443,
        "protocol": "tcp",
        "service": "https",
        "conn_state": "SF",
        "orig_bytes": 100,
        "resp_bytes": 100,
    }]
    result = OtOutboundInternetAnyProtocolModule().analyze(
        AnalysisContext(connections=connections, metadata=metadata)
    )
    assert result.findings == []
    assert result.metrics["ot_outbound_public_flows"] == 0
