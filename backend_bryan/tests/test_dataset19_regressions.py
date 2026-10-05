from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

from backend_bryan.adapters.detection_context_adapter import compile_detection_context_metadata
from backend_bryan.regression.dataset19_fixture_builder import CONTEXT, FIXTURE, MANIFEST, build_fixture
from backend_bryan.integration.detector_runtime import ensure_detector_package

Context, MODULES, _ = ensure_detector_package()


def _pcap_stats(path: Path) -> tuple[int, float, float]:
    data = path.read_bytes()
    assert len(data) > 24
    magic, major, minor, _zone, _sigfigs, snaplen, network = struct.unpack_from("<IHHIIII", data, 0)
    assert magic == 0xA1B2C3D4
    assert (major, minor, snaplen, network) == (2, 4, 65535, 1)
    offset = 24
    count = 0
    first = None
    last = None
    while offset < len(data):
        sec, usec, included, original = struct.unpack_from("<IIII", data, offset)
        offset += 16
        assert included == original
        timestamp = sec + usec / 1_000_000
        first = timestamp if first is None else first
        last = timestamp
        offset += included
        count += 1
    assert offset == len(data)
    assert first is not None and last is not None
    return count, first, last


def test_dataset19_is_a_multi_hour_frozen_raw_pcap_with_full_registry_context() -> None:
    count, first, last = _pcap_stats(FIXTURE)
    assert count == 2253
    assert first == 0.0
    assert last >= 4 * 60 * 60
    assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == "764009dffce55e8ef0ff1ad3ffdc00a1c75e870453e0a80d31a2d974e9473858"

    profile = json.loads(CONTEXT.read_text(encoding="utf-8"))
    assert len(profile["selectedModules"]) == 75
    metadata = compile_detection_context_metadata(profile)
    assert metadata["unexpected_dhcp_server_policy"]["expected_servers"] == ["10.190.10.2"]
    assert metadata["unexpected_multicast_policy"]["allowed_groups"] == ["239.1.1.1"]
    assert metadata["remote_access_tool_policy"]["allowed_hosts"] == ["10.190.10.50"]
    assert metadata["ics_write_policy"]["allowed_paths"]
    assert metadata["asset_inventory"][0]["macs"] == ["00:19:00:00:20:20"]
    assert metadata["plc_rtu_peer_change_policy"]["allowed_pairs"] == [{"source": "10.190.10.50", "destination": "10.190.20.20"}]

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert manifest["duration_seconds"] == 14400
    assert set(manifest["required_finding_modules"]) == {
        "ics_write_operations", "unexpected_dhcp_server", "rogue_dhcp_static_ot"
    }


def test_dataset19_fixture_rebuild_is_byte_deterministic(tmp_path: Path) -> None:
    rebuilt = build_fixture(tmp_path / "rebuilt.pcap")
    assert rebuilt.read_bytes() == FIXTURE.read_bytes()


def test_dataset19_live_zeek_semantic_edge_cases_are_suppressed() -> None:
    metadata = compile_detection_context_metadata(json.loads(CONTEXT.read_text(encoding="utf-8")))

    write = MODULES["ics_write_operations"].analyze(Context(
        modbus=[{
            "timestamp": 7250.03, "source_ip": "10.190.10.50", "destination_ip": "10.190.20.20",
            "destination_port": 502, "func": "WRITE_SINGLE_REGISTER",
        }],
        metadata=metadata,
    ))
    assert write.findings == []

    outbound = MODULES["ot_outbound_internet_any_protocol"].analyze(Context(
        connections=[{
            "timestamp": 15.0, "source_ip": "10.190.20.20", "destination_ip": "239.1.1.1",
            "destination_port": 31000, "protocol": "udp", "service": "",
        }],
        metadata=metadata,
    ))
    assert outbound.findings == []

    rogue = MODULES["unknown_rogue_devices"].analyze(Context(
        connections=[
            {"timestamp": 20.0, "source_ip": "0.0.0.0", "destination_ip": "255.255.255.255", "protocol": "udp", "local_orig": True, "local_resp": True},
            {"timestamp": 21.0, "source_ip": "10.190.20.20", "destination_ip": "239.1.1.1", "protocol": "udp", "local_orig": True, "local_resp": True},
        ],
        metadata=metadata,
    ))
    assert rogue.findings == []

    peer = MODULES["plc_rtu_peer_change"].analyze(Context(
        connections=[
            {"timestamp": 0.0, "source_ip": "10.190.20.30", "destination_ip": "10.190.20.20", "destination_port": 502, "service": "modbus"},
            {"timestamp": 7250.0, "source_ip": "10.190.10.50", "destination_ip": "10.190.20.20", "destination_port": 502, "service": "modbus"},
        ],
        metadata=metadata,
    ))
    assert peer.findings == []
