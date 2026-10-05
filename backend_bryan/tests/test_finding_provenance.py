from __future__ import annotations

import json
from pathlib import Path

from backend_bryan.integration.analysis_service import analyze_detection_request
from backend_bryan.integration.detector_runtime import ensure_detector_package
from backend_bryan.integration.finding_provenance import attach_finding_provenance

ROOT = Path(__file__).resolve().parents[1]
Context, MODULES, _ = ensure_detector_package()


def _request() -> dict:
    return json.loads((ROOT / "examples" / "analysis_request.json").read_text(encoding="utf-8"))


def test_protocol_finding_records_exact_zeek_log_and_fields() -> None:
    request = _request()
    request["profile"]["selectedModules"] = ["s7comm_unauthorized_write_stop"]
    request["profile"]["authorizedControlActions"] = []
    row = {
        "ts": 1710000000.25,
        "id.orig_h": "10.10.1.50",
        "id.orig_p": 41000,
        "id.resp_h": "10.10.2.20",
        "id.resp_p": 102,
        "function": "write",
    }
    request["logs"] = {"s7comm": [row]}

    response = analyze_detection_request(request)
    finding = response["moduleResults"][0]["findings"][0]
    provenance = finding["provenance"]

    assert provenance["schema_version"] == 1
    assert provenance["resolution"] == "representative_flow"
    assert provenance["sources"]
    source = provenance["sources"][0]
    assert source["log_type"] == "s7comm.log"
    assert source["record_index"] == 0
    assert source["fields"]["function"] == "write"
    assert source["fields"]["id.orig_h"] == "10.10.1.50"
    assert source["fields"]["id.resp_h"] == "10.10.2.20"
    assert finding["metadata"]["zeek_provenance"] == provenance


def test_derived_finding_correlates_back_to_conn_log() -> None:
    context = Context(
        connections=[
            {"timestamp": 0.0, "source_ip": "10.3.0.50", "destination_ip": "10.3.0.20", "destination_port": 502, "service": "modbus"},
            {"timestamp": 30.0, "source_ip": "10.3.0.51", "destination_ip": "10.3.0.20", "destination_port": 502, "service": "modbus"},
            {"timestamp": 400.0, "source_ip": "10.3.0.20", "destination_ip": "10.3.0.60", "destination_port": 502, "service": "modbus"},
        ],
        metadata={},
    )
    module = MODULES["ot_protocol_role_reversal"]
    result = module.analyze(context)
    attach_finding_provenance(module, result, context)

    finding = result.findings[0]
    assert finding.provenance["sources"]
    assert all(source["log_type"] == "conn.log" for source in finding.provenance["sources"])
    assert any(source["fields"].get("source_ip") == "10.3.0.20" for source in finding.provenance["sources"])


def test_provenance_redacts_credential_like_values() -> None:
    context = Context(
        snmp=[
            {
                "ts": 1.0,
                "id.orig_h": "10.1.1.10",
                "id.resp_h": "10.1.1.20",
                "version": "2c",
                "community": "private-secret",
                "get_bulk_request": False,
                "set_request": True,
            }
        ],
        metadata={},
    )
    module = MODULES["snmp_write_ot_devices"]
    result = module.analyze(context)
    attach_finding_provenance(module, result, context)

    if result.findings:
        sources = result.findings[0].provenance["sources"]
        assert sources
        for source in sources:
            if "community" in source["fields"]:
                assert source["fields"]["community"] == "<redacted>"
