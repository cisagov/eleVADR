from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

from backend_bryan.integration.pcap_analysis import analyze_pcap_to_report


def _fake_zeek(path: Path) -> Path:
    script = path / "fake_zeek"
    script.write_text(
        "#!/usr/bin/env python3\n"
        "from pathlib import Path\n"
        "Path('conn.log').write_text("
        "'#separator \\x09\\n#unset_field -\\n#empty_field (empty)\\n'"
        "+ '#fields\\tts\\tuid\\tid.orig_h\\tid.orig_p\\tid.resp_h\\tid.resp_p\\tproto\\tservice\\tduration\\torig_bytes\\tresp_bytes\\tconn_state\\thistory\\torig_pkts\\tresp_pkts\\n'"
        "+ '1.0\\tC1\\t10.0.0.10\\t12345\\t10.0.0.20\\t502\\ttcp\\tmodbus\\t1.2\\t100\\t50\\tSF\\tShADadFf\\t3\\t2\\n', encoding='utf-8')\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return script


def test_pcap_pipeline_returns_canonical_report(tmp_path, monkeypatch):
    fake = _fake_zeek(tmp_path)
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(b"not-a-real-pcap; fake zeek ignores input")
    monkeypatch.setenv("ELEVADR_ZEEK_COMMAND", f'"{sys.executable}" "{fake}"')

    from backend_bryan.reference_fixture import representative_profile
    profile = representative_profile()

    report = analyze_pcap_to_report(pcap, profile, source_filename="capture.pcap")
    assert report["report_version"].startswith("2.")
    assert report["report_id"].startswith("elevadr-")
    assert report["modules"]["device_panel"]["hosts"] >= 2
    assert report["modules"]["service_count_panel"]["service_count"] == 1
    assert report["arch_insights"]["analysis_provenance"]["source_type"] == "pcap"
    assert report["arch_insights"]["analysis_provenance"]["source_filename"] == "capture.pcap"
    assert report["arch_insights"]["detection_context_snapshot"]["schemaVersion"] == 3
