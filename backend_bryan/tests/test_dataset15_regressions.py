from __future__ import annotations

import json
import struct
from pathlib import Path

from backend_bryan.adapters.detection_context_adapter import compile_detection_context_metadata
from backend_bryan.integration.detector_runtime import ensure_detector_package
from backend_bryan.regression.dataset15_fixture_builder import FIXTURE


Context, MODULES, _ = ensure_detector_package()


def test_dataset15_fixture_and_context_are_frozen_raw_inputs() -> None:
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
    assert count == 62

    context_path = FIXTURE.with_name("15_new_detector_raw_pcap_context.json")
    profile = json.loads(context_path.read_text(encoding="utf-8"))
    metadata = compile_detection_context_metadata(profile)
    assert metadata["unexpected_dhcp_server_policy"]["expected_servers"] == ["10.150.0.2"]
    assert metadata["engineering_control_burst_policy"]["authorized_paths"][0]["allowed_function_codes"] == [6]


def test_engineering_burst_understands_native_zeek_modbus_function_names() -> None:
    profile = json.loads(FIXTURE.with_name("15_new_detector_raw_pcap_context.json").read_text(encoding="utf-8"))
    metadata = compile_detection_context_metadata(profile)
    # Native Zeek Modbus::Info.func is a function-name string rather than the
    # numeric function code used by several normalized fixtures.
    rows = [
        {
            "timestamp": float(i),
            "source_ip": "10.150.0.50",
            "destination_ip": "10.150.0.20",
            "destination_port": 502,
            "func": "WRITE_SINGLE_REGISTER",
            "pdu_type": "REQ",
        }
        for i in range(5)
    ]
    result = MODULES["engineering_workstation_control_burst"].analyze(Context(modbus=rows, metadata=metadata))
    assert len(result.findings) == 1
    assert result.findings[0].metadata["authorized_operation_count"] == 5
    assert result.findings[0].metadata["unauthorized_operation_count"] == 0
