from elevadr_modules.models import AnalysisContext
from elevadr_modules.modules.smb_admin_share_access import SmbAdminShareAccessModule


def _admin_share_row(uid: str, source: str, destination: str) -> dict:
    return {
        "uid": uid,
        "source_ip": source,
        "destination_ip": destination,
        "destination_port": 445,
        "share": "ADMIN$",
        "timestamp": 1000,
    }


def test_admin_share_access_without_dce_rpc_is_medium_severity():
    context = AnalysisContext(smb_mapping=[_admin_share_row("u1", "10.0.0.5", "10.0.0.6")])
    result = SmbAdminShareAccessModule().analyze(context)
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.severity == "medium"
    assert "dce-rpc-corroborated" not in finding.tags
    assert finding.metadata["service_control_rpc_operations"] == []
    assert result.metrics["service_control_rpc_corroborated_events"] == 0


def test_admin_share_access_with_svcctl_dce_rpc_is_corroborated_and_escalated():
    context = AnalysisContext(
        smb_mapping=[_admin_share_row("u1", "10.0.0.5", "10.0.0.6")],
        dce_rpc=[
            {
                "uid": "u1",
                "source_ip": "10.0.0.5",
                "destination_ip": "10.0.0.6",
                "endpoint": "svcctl",
                "operation": "OpenSCManagerW",
                "timestamp": 1001,
            }
        ],
    )
    result = SmbAdminShareAccessModule().analyze(context)
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.severity == "high"
    assert "dce-rpc-corroborated" in finding.tags
    assert finding.metadata["service_control_rpc_operations"] == ["OpenSCManagerW"]
    assert "dce_rpc.log" in finding.summary
    assert result.metrics["service_control_rpc_corroborated_events"] == 1
    assert "dce_rpc" in result.evidence["inspected_logs"]


def test_unrelated_dce_rpc_endpoint_does_not_corroborate():
    context = AnalysisContext(
        smb_mapping=[_admin_share_row("u1", "10.0.0.5", "10.0.0.6")],
        dce_rpc=[
            {
                "uid": "u1",
                "source_ip": "10.0.0.5",
                "destination_ip": "10.0.0.6",
                "endpoint": "epmapper",
                "operation": "Lookup",
                "timestamp": 1001,
            }
        ],
    )
    result = SmbAdminShareAccessModule().analyze(context)
    finding = result.findings[0]
    assert finding.severity == "medium"
    assert "dce-rpc-corroborated" not in finding.tags
