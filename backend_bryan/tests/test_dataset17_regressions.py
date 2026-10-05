from __future__ import annotations

import json
import struct

from backend_bryan.adapters.detection_context_adapter import compile_detection_context_metadata
from backend_bryan.regression.dataset17_fixture_builder import FIXTURE


def test_dataset17_fixture_and_context_are_frozen_raw_inputs() -> None:
    data = FIXTURE.read_bytes()
    assert len(data) > 24
    magic, major, minor, _zone, _sigfigs, snaplen, network = struct.unpack_from("<IHHIIII", data, 0)
    assert magic == 0xA1B2C3D4
    assert (major, minor, snaplen, network) == (2, 4, 65535, 1)
    assert b"secure-plc.local" in data
    assert b"secure-plc-new.local" in data

    offset = 24
    count = 0
    while offset < len(data):
        _sec, _usec, included, original = struct.unpack_from("<IIII", data, offset)
        offset += 16
        assert included == original
        offset += included
        count += 1
    assert offset == len(data)
    assert count == 224

    context_path = FIXTURE.with_name("17_wave3_raw_pcap_context.json")
    profile = json.loads(context_path.read_text(encoding="utf-8"))
    metadata = compile_detection_context_metadata(profile)
    assert metadata["encrypted_session_fingerprint_policy"]["baseline_seconds"] == 120
    assert metadata["remote_access_session_anomaly_policy"]["authorized_sources"] == ["10.170.0.5"]
    assert metadata["service_disappearance_replacement_policy"]["ot_hosts"] == ["10.170.0.30"]
    assert metadata["polling_cadence_disruption_policy"]["interval_change_ratio"] == 0.5
    assert metadata["controller_communication_jitter_policy"]["controller_hosts"] == ["10.170.0.50"]
    assert profile["selectedModules"] == [
        "encrypted_session_fingerprint_change",
        "remote_access_session_anomaly",
        "service_disappearance_replacement",
        "polling_cadence_disruption",
        "controller_communication_jitter",
    ]


def test_dataset17_policy_keeps_observation_separate_from_authorization() -> None:
    context_path = FIXTURE.with_name("17_wave3_raw_pcap_context.json")
    profile = json.loads(context_path.read_text(encoding="utf-8"))
    metadata = compile_detection_context_metadata(profile)

    # The management host is explicit policy.  New RDP targets, TLS fingerprints,
    # services, polling intervals, and jitter values come only from packet evidence
    # and must not be promoted into authorization/allowlist fields by compilation.
    assert metadata["remote_access_session_anomaly_policy"]["authorized_sources"] == ["10.170.0.5"]
    assert profile["communicationPairs"] == []
    assert profile["allowedHosts"] == []
    assert profile["allowedSegmentPairs"] == []
    assert profile["authorizedControlActions"] == []
