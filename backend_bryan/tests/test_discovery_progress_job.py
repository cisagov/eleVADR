from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import patch

from backend_bryan.integration import http_reference_server as server


def test_discovery_job_preserves_backend_progress() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        pcap = Path(tmp) / "capture.pcap"
        pcap.write_bytes(b"pcap")
        job_id = "progress-test"
        with server._DISCOVERY_LOCK:
            server._DISCOVERY_JOBS[job_id] = {
                "jobId": job_id,
                "status": "queued",
                "stage": "queued",
                "progress": 0,
                "message": "queued",
                "detail": None,
            }

        def fake_discover(_path: Path, _evidence_dir: Path, *, source_filename: str | None = None, progress=None):
            assert progress is not None
            progress("docker-pull", 17, "Downloading Zeek Docker image zeek/zeek:9.0.0…", "2/8 layers complete")
            progress("zeek-running", None, "Analyzing PCAP with Zeek…", source_filename)
            return {"assets": [], "segments": [], "pairs": [], "infrastructure": []}

        with patch.object(server, "discover_context_with_retained_evidence", side_effect=fake_discover), patch.object(server, "_register_evidence", return_value=("evidence-test", {"pcap_sha256": "abc", "zeek_policy_sha256": "def"})):

            server._run_discovery_job(job_id, pcap, "capture.pcap")

        job = server._job_snapshot(job_id)
        assert job is not None
        assert job["status"] == "completed"
        assert job["progress"] == 100
        assert job["result"]["assets"] == []
