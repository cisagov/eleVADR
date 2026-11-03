from elevadr_modules.models import AnalysisContext
from elevadr_modules.modules.enip_cip_write_session_abuses import EnipCipWriteSessionAbusesModule
from elevadr_modules.modules.ics_protocol_error_spike import IcsProtocolErrorSpikeModule


def _cip_write_row(timestamp: float, source: str = "10.0.0.5", destination: str = "10.0.0.6") -> dict:
    return {
        "timestamp": timestamp,
        "source_ip": source,
        "destination_ip": destination,
        "destination_port": 44818,
        "cip_service": "write_tag",
    }


def test_enip_cip_write_detects_from_cip_log_alone():
    context = AnalysisContext(cip=[_cip_write_row(1000.0)])
    result = EnipCipWriteSessionAbusesModule().analyze(context)
    assert result.metrics["cip_events_evaluated"] == 1
    assert result.metrics["cip_write_events"] == 1
    assert len(result.findings) == 1
    assert "cip" in result.evidence["inspected_logs"]


def test_enip_cip_write_still_detects_from_enip_log_alone():
    context = AnalysisContext(enip=[_cip_write_row(1000.0)])
    result = EnipCipWriteSessionAbusesModule().analyze(context)
    assert result.metrics["enip_events_evaluated"] == 1
    assert result.metrics["cip_write_events"] == 1
    assert len(result.findings) == 1
    assert "enip" in result.evidence["inspected_logs"]


def test_enip_cip_write_combines_both_logs():
    context = AnalysisContext(
        enip=[_cip_write_row(1000.0, "10.0.0.5", "10.0.0.6")],
        cip=[_cip_write_row(1001.0, "10.0.0.7", "10.0.0.8")],
    )
    result = EnipCipWriteSessionAbusesModule().analyze(context)
    assert result.metrics["cip_events_evaluated"] == 1
    assert result.metrics["enip_events_evaluated"] == 1
    assert len(result.findings) == 2


def test_enip_cip_write_empty_without_either_log():
    result = EnipCipWriteSessionAbusesModule().analyze(AnalysisContext())
    assert result.findings == []
    assert result.evidence["inspected_logs"] == []


def test_ics_protocol_error_spike_reads_general_status_from_cip_log():
    rows = [
        {
            "timestamp": 1000.0 + i,
            "source_ip": "10.0.0.5",
            "destination_ip": "10.0.0.6",
            "general_status": 1 if i % 2 == 0 else 0,
        }
        for i in range(20)
    ]
    context = AnalysisContext(cip=rows)
    result = IcsProtocolErrorSpikeModule().analyze(context)
    assert result.metrics["enip_cip_error_events"] == 10
    assert "cip" in result.evidence["inspected_logs"]
