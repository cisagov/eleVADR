from __future__ import annotations

import json
import struct
from pathlib import Path

from backend_bryan.adapters.detection_context_adapter import compile_detection_context_metadata
from backend_bryan.integration.detector_runtime import ensure_detector_package
from backend_bryan.regression.dataset16_fixture_builder import FIXTURE


Context, MODULES, _ = ensure_detector_package()


def test_dataset16_fixture_and_context_are_frozen_raw_inputs() -> None:
    data = FIXTURE.read_bytes()
    assert len(data) > 24
    magic, major, minor, _zone, _sigfigs, snaplen, network = struct.unpack_from("<IHHIIII", data, 0)
    assert magic == 0xA1B2C3D4
    assert (major, minor, snaplen, network) == (2, 4, 65535, 1)

    offset = 24
    count = 0
    while offset < len(data):
        _sec, _usec, included, original = struct.unpack_from("<IIII", data, offset)
        offset += 16
        assert included == original
        offset += included
        count += 1
    assert offset == len(data)
    assert count == 51

    context_path = FIXTURE.with_name("16_wave2_raw_pcap_context.json")
    profile = json.loads(context_path.read_text(encoding="utf-8"))
    metadata = compile_detection_context_metadata(profile)
    assert metadata["dns_source_drift_policy"]["trusted_resolvers"] == ["10.160.0.2"]
    assert metadata["ntp_source_drift_policy"]["trusted_servers"] == ["10.160.0.3"]
    assert metadata["unexpected_multicast_policy"]["allowed_groups"] == ["239.1.1.1"]
    assert profile["selectedModules"] == [
        "dns_source_drift",
        "ntp_source_drift",
        "arp_l2_reconnaissance",
        "unexpected_multicast_behavior",
        "tcp_reset_abort_surge",
    ]


def test_tcp_reset_detector_understands_native_zeek_state_key() -> None:
    rows = [
        {
            "timestamp": float(i),
            "source_ip": f"10.160.0.{100 + i}",
            "destination_ip": "10.160.0.20",
            "protocol": "tcp",
            "zeek_state": "REJ",
        }
        for i in range(10)
    ]
    metadata = {
        "tcp_reset_abort_policy": {
            "minimum_events": 10,
            "window_seconds": 60,
            "minimum_failure_ratio": 0.6,
        }
    }
    result = MODULES["tcp_reset_abort_surge"].analyze(Context(connections=rows, metadata=metadata))
    assert len(result.findings) == 1
    assert result.findings[0].metadata["failure_events"] == 10
