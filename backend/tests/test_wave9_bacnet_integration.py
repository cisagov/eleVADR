from pathlib import Path
from elevadr_modules.models import AnalysisContext
from elevadr_modules.zeek.parser import load_zeek_directory
from elevadr_modules.modules.bacnet_discovery_anomalies import BacnetDiscoveryAnomaliesModule


def test_dedicated_discovery_preferred_and_direction_preserved(tmp_path: Path):
    fields = ["ts", "uid", "id.orig_h", "id.resp_h", "source_h", "destination_h", "pdu_service"]
    records = ["\t".join([str(1000+i), "same-uid", "10.0.0.1", "10.0.0.2", "10.0.0.2", "10.0.0.1", "who-is"]) for i in range(3)]
    (tmp_path / "bacnet_discovery.log").write_text("#fields\t" + "\t".join(fields) + "\n" + "\n".join(records) + "\n")
    (tmp_path / "bacnet.log").write_text("#fields\t" + "\t".join(fields) + "\n" + "\n".join(records) + "\n")
    context = load_zeek_directory(tmp_path)
    assert len(context.bacnet_discovery) == 3
    assert context.log("bacnet_discovery")[0]["source_ip"] == "10.0.0.2"
    context.metadata["bacnet_discovery_policy"] = {"who_is_threshold": 3}
    result = BacnetDiscoveryAnomaliesModule().analyze(context)
    assert result.metrics["who_is_events"] == 3
    assert result.evidence["inspected_logs"] == ["bacnet_discovery"]
    assert result.findings
    assert result.findings[0].provenance["zeek_logs"] == ["bacnet_discovery.log"]
    assert "10.0.0.2" in result.findings[0].devices


def test_legacy_bacnet_still_works():
    context = AnalysisContext(bacnet=[{"service": "who-is", "source_ip": "10.0.0.3", "destination_ip": "10.0.0.4", "timestamp": i} for i in range(3)])
    context.metadata["bacnet_discovery_policy"] = {"who_is_threshold": 3}
    result = BacnetDiscoveryAnomaliesModule().analyze(context)
    assert result.metrics["who_is_events"] == 3
    assert result.evidence["inspected_logs"] == ["bacnet"]
