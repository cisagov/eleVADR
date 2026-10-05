from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import patch

from backend_bryan.integration import http_reference_server as server


def test_analysis_job_preserves_backend_progress() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        pcap = Path(tmp) / "capture.pcap"
        pcap.write_bytes(b"pcap")
        job_id = "analysis-progress-test"
        with server._ANALYSIS_LOCK:
            server._ANALYSIS_JOBS[job_id] = {
                "jobId": job_id,
                "status": "queued",
                "stage": "queued",
                "progress": 0,
                "message": "queued",
                "detail": None,
            }

        fake_report = {
            "report_version": "2.0.0",
            "report_id": "elevadr-test",
            "executive_summary": {},
            "modules": {},
            "arch_insights": {},
        }

        def fake_analyze(_path: Path, _profile: dict, *, source_filename: str | None = None, progress=None):
            assert progress is not None
            progress("zeek-running", None, "Analyzing PCAP with Zeek…", source_filename)
            progress("detectors", 90, "Running detector modules 30/60…", "example")
            progress("building-report", 98, "Building eleVADR JSON report…", None)
            return fake_report

        with patch.object(server, "analyze_pcap_to_report", side_effect=fake_analyze):
            server._run_analysis_job(job_id, pcap, "capture.pcap", {"schemaVersion": 3})

        job = server._analysis_job_snapshot(job_id)
        assert job is not None
        assert job["status"] == "completed"
        assert job["progress"] == 100
        assert job["result"]["report_id"] == "elevadr-test"
