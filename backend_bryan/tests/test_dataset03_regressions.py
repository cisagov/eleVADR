from __future__ import annotations

from backend_bryan.vendor.elevadr_modules.models import AnalysisContext
from backend_bryan.vendor.elevadr_modules.modules.unusual_outbound_data_volume import (
    UnusualOutboundDataVolumeModule,
)


MIB = 1024 * 1024


def _external_connection(byte_count: int) -> dict:
    return {
        "timestamp": 1760002000.0,
        "source_ip": "10.50.0.25",
        "source_port": 45000,
        "destination_ip": "1.1.1.1",
        "destination_port": 80,
        "protocol": "tcp",
        "service": "http",
        "source_bytes": byte_count,
        "destination_bytes": 43,
        "local_orig": "T",
        "local_resp": "F",
        "conn_state": "S2",
    }


def test_sparse_baseline_uses_external_absolute_floor_not_always_report_ceiling() -> None:
    result = UnusualOutboundDataVolumeModule().analyze(
        AnalysisContext(connections=[_external_connection(12 * MIB)], metadata={})
    )

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.metadata["orig_bytes"] == 12 * MIB
    assert finding.metadata["anomaly_threshold_bytes"] == 10 * MIB
    assert finding.metadata["absolute_threshold_only"] is True
    assert result.metrics["external_destination_findings"] == 1


def test_sparse_baseline_still_ignores_external_transfer_below_absolute_floor() -> None:
    result = UnusualOutboundDataVolumeModule().analyze(
        AnalysisContext(connections=[_external_connection(9 * MIB)], metadata={})
    )

    assert result.findings == []
    assert result.metrics["candidate_outbound_connections_evaluated"] == 1


def test_learned_threshold_is_capped_by_always_report_bytes() -> None:
    # Ten very large historical flows would otherwise drive the learned
    # threshold above the module's 100 MiB always-report ceiling.
    rows = [_external_connection(200 * MIB) for _ in range(10)]
    result = UnusualOutboundDataVolumeModule().analyze(
        AnalysisContext(connections=rows, metadata={})
    )

    assert len(result.findings) == 10
    assert all(f.metadata["anomaly_threshold_bytes"] == 100 * MIB for f in result.findings)

from backend_bryan.vendor.elevadr_modules.modules.new_service_emergence_ot import (
    NewServiceEmergenceOtModule,
)


def _service_drift_metadata() -> dict:
    return {
        "segments": [
            {
                "name": "OT PLC",
                "cidr": "10.60.0.0/24",
                "role": "ot",
            }
        ],
        "service_baseline_policy": {
            "baseline_seconds": 300,
            "min_post_baseline_occurrences": 1,
        },
    }


def test_new_service_baseline_is_anchored_to_capture_start_not_first_ot_observation() -> None:
    rows = [
        {
            "timestamp": 1000.0,
            "source_ip": "10.50.0.25",
            "destination_ip": "1.1.1.1",
            "destination_port": 80,
            "protocol": "tcp",
            "service": "http",
        },
        {
            "timestamp": 1700.0,
            "source_ip": "10.50.0.25",
            "destination_ip": "10.60.0.20",
            "destination_port": 502,
            "protocol": "tcp",
            "service": "modbus",
        },
    ]

    result = NewServiceEmergenceOtModule().analyze(
        AnalysisContext(connections=rows, metadata=_service_drift_metadata())
    )

    assert len(result.findings) == 1
    assert result.findings[0].metadata["first_seen_timestamp"] == 1700.0
    assert result.findings[0].metadata["baseline_end_timestamp"] == 1300.0
    assert result.evidence["capture_start"] == 1000.0
    assert result.evidence["capture_end"] == 1700.0
    assert result.evidence["baseline_start"] == 1000.0
    assert result.evidence["baseline_end"] == 1300.0


def test_new_service_seen_during_capture_baseline_does_not_alert() -> None:
    rows = [
        {
            "timestamp": 1000.0,
            "source_ip": "10.50.0.25",
            "destination_ip": "1.1.1.1",
            "destination_port": 80,
            "protocol": "tcp",
            "service": "http",
        },
        {
            "timestamp": 1200.0,
            "source_ip": "10.50.0.25",
            "destination_ip": "10.60.0.20",
            "destination_port": 502,
            "protocol": "tcp",
            "service": "modbus",
        },
        {
            "timestamp": 1700.0,
            "source_ip": "10.50.0.25",
            "destination_ip": "10.60.0.20",
            "destination_port": 502,
            "protocol": "tcp",
            "service": "modbus",
        },
    ]

    result = NewServiceEmergenceOtModule().analyze(
        AnalysisContext(connections=rows, metadata=_service_drift_metadata())
    )

    assert result.findings == []
    assert result.metrics["baseline_services"] == 1
    assert result.evidence["baseline_start"] == 1000.0
    assert result.evidence["baseline_end"] == 1300.0
