from elevadr_modules.models import AnalysisContext
from elevadr_modules.modules.controller_communication_jitter import (
    ControllerCommunicationJitterModule,
)
from elevadr_modules.modules.ot_asset_gone_silent import OtAssetGoneSilentModule
from elevadr_modules.modules.polling_cadence_disruption import (
    PollingCadenceDisruptionModule,
)


def _single_persistent_session(source: str, destination: str, port: int, start: float, end: float) -> dict:
    # One conn.log row representing a single long-lived TCP session spanning the
    # whole capture; no per-poll timing is visible from conn.log alone here.
    return {
        "uid": "persistent-1",
        "timestamp": start,
        "source_ip": source,
        "destination_ip": destination,
        "destination_port": port,
        "protocol": "tcp",
        "duration": end - start,
    }


def _modbus_polls(source: str, destination: str, timestamps: list[float]) -> list[dict]:
    return [
        {"timestamp": t, "source_ip": source, "destination_ip": destination, "uid": "persistent-1"}
        for t in timestamps
    ]


def test_polling_cadence_disruption_uses_modbus_timing_inside_persistent_session():
    source, destination = "10.0.1.5", "10.0.0.10"
    # Baseline: steady 10s cadence for 60s, then post-baseline: steady 40s cadence -
    # a clear cadence shift that conn.log's single session row cannot reveal.
    baseline_times = [0, 10, 20, 30, 40, 50]
    post_times = [400, 440, 480, 520]
    polls = _modbus_polls(source, destination, baseline_times + post_times)
    context = AnalysisContext(
        connections=[_single_persistent_session(source, destination, 502, 0, 520)],
        modbus=polls,
    )
    context.metadata["polling_cadence_disruption_policy"] = {
        "baseline_seconds": 300,
        "minimum_baseline_observations": 5,
        "interval_change_ratio": 0.5,
    }
    result = PollingCadenceDisruptionModule().analyze(context)
    assert len(result.findings) == 1
    assert result.findings[0].metadata["timing_basis"] == "protocol_log"
    assert "protocol-log-timing" in result.findings[0].tags
    assert result.metrics["series_using_protocol_log_timing"] == 1
    assert "modbus" in result.evidence["inspected_logs"]


def test_polling_cadence_disruption_falls_back_to_conn_log_without_protocol_log():
    source, destination = "10.0.1.5", "10.0.0.10"
    times = [0, 10, 20, 30, 40, 50, 400, 430, 460, 490]
    rows = [
        {
            "timestamp": t,
            "source_ip": source,
            "destination_ip": destination,
            "destination_port": 502,
            "protocol": "tcp",
            "service": "modbus",
        }
        for t in times
    ]
    context = AnalysisContext(connections=rows)
    context.metadata["polling_cadence_disruption_policy"] = {
        "baseline_seconds": 300,
        "minimum_baseline_observations": 5,
        "interval_change_ratio": 0.5,
    }
    result = PollingCadenceDisruptionModule().analyze(context)
    assert len(result.findings) == 1
    assert result.findings[0].metadata["timing_basis"] == "connection"
    assert result.metrics["series_using_protocol_log_timing"] == 0
    assert result.evidence["inspected_logs"] == ["conn"]


def test_controller_jitter_uses_s7comm_timing_inside_persistent_session():
    source, destination = "10.0.0.10", "10.0.1.5"
    baseline_times = [0, 10, 20, 30, 40, 50, 60]
    # Highly irregular post-baseline cadence that should register as jitter.
    post_times = [400, 405, 425, 433, 470]
    polls = [
        {"timestamp": t, "source_ip": source, "destination_ip": destination, "uid": "persistent-2"}
        for t in baseline_times + post_times
    ]
    context = AnalysisContext(
        connections=[_single_persistent_session(source, destination, 102, 0, 470)],
        s7comm=polls,
    )
    context.metadata["controller_communication_jitter_policy"] = {
        "baseline_seconds": 300,
        "minimum_baseline_observations": 6,
        "jitter_multiplier": 3,
        "minimum_post_jitter_ratio": 0.2,
        "controller_hosts": [source],
    }
    result = ControllerCommunicationJitterModule().analyze(context)
    assert len(result.findings) == 1
    assert result.findings[0].metadata["timing_basis"] == "protocol_log"
    assert result.metrics["series_using_protocol_log_timing"] == 1


def test_controller_jitter_uses_cip_timing_inside_persistent_session():
    # ICSNPP-ENIP can split EtherNet/IP into enip.log (session/registration) and
    # cip.log (per-poll CIP service-code records); the timing fallback must also
    # check cip.log, not just enip.log, for per-poll granularity.
    source, destination = "10.0.0.10", "10.0.1.5"
    baseline_times = [0, 10, 20, 30, 40, 50, 60]
    post_times = [400, 405, 425, 433, 470]
    polls = [
        {"timestamp": t, "source_ip": source, "destination_ip": destination, "uid": "persistent-4"}
        for t in baseline_times + post_times
    ]
    context = AnalysisContext(
        connections=[_single_persistent_session(source, destination, 44818, 0, 470)],
        cip=polls,
    )
    context.metadata["controller_communication_jitter_policy"] = {
        "baseline_seconds": 300,
        "minimum_baseline_observations": 6,
        "jitter_multiplier": 3,
        "minimum_post_jitter_ratio": 0.2,
        "controller_hosts": [source],
    }
    result = ControllerCommunicationJitterModule().analyze(context)
    assert len(result.findings) == 1
    assert result.findings[0].metadata["timing_basis"] == "protocol_log"
    assert result.metrics["series_using_protocol_log_timing"] == 1
    assert "cip" in result.evidence["inspected_logs"]


def test_ot_asset_gone_silent_uses_enip_timing_inside_persistent_session():
    ot_host, peer = "10.0.0.10", "10.0.1.5"
    baseline_times = [0.0, 30.0, 60.0, 90.0, 120.0, 150.0]
    polls = [
        {"timestamp": t, "source_ip": ot_host, "destination_ip": peer, "uid": "persistent-3"}
        for t in baseline_times
    ]
    # Zeek periodically rotates very long-lived connections into additional
    # conn.log rows; the second row here extends capture_end past the baseline
    # window while keeping both rows describing the same single session/pair.
    context = AnalysisContext(
        connections=[
            _single_persistent_session(ot_host, peer, 44818, 0.0, 1200.0),
            _single_persistent_session(ot_host, peer, 44818, 1200.0, 1200.0),
        ],
        enip=polls,
    )
    context.metadata["segments"] = [
        {"name": "ot", "cidr": "10.0.0.0/24", "role": "ot"},
        {"name": "it", "cidr": "10.0.1.0/24", "role": "it"},
    ]
    context.metadata["ot_asset_silence_policy"] = {
        "baseline_seconds": 180,
        "min_baseline_observations": 4,
        "min_silence_seconds": 60,
        "silence_multiplier": 3,
    }
    result = OtAssetGoneSilentModule().analyze(context)
    assert result.metrics["conversations_using_protocol_log_timing"] == 1
    assert len(result.findings) >= 1
    assert "enip" in result.evidence["inspected_logs"]
