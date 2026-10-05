from __future__ import annotations

import copy
import hashlib
import stat
import sys
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from backend_bryan.integration.context_discovery import discover_context_with_retained_evidence
from backend_bryan.integration.pcap_analysis import analyze_zeek_evidence_to_report
from backend_bryan.reference_fixture import representative_profile


def _counting_fake_zeek(path: Path, counter: Path) -> Path:
    script = path / "fake_zeek_once"
    script.write_text(
        "#!/usr/bin/env python3\n"
        "from pathlib import Path\n"
        f"counter = Path({str(counter)!r})\n"
        "count = int(counter.read_text() or '0') if counter.exists() else 0\n"
        "counter.write_text(str(count + 1), encoding='utf-8')\n"
        "Path('conn.log').write_text("
        "'#separator \\x09\\n#unset_field -\\n#empty_field (empty)\\n'"
        "+ '#fields\\tts\\tuid\\tid.orig_h\\tid.orig_p\\tid.resp_h\\tid.resp_p\\tproto\\tservice\\tduration\\torig_bytes\\tresp_bytes\\tconn_state\\thistory\\torig_pkts\\tresp_pkts\\n'"
        "+ '1.0\\tC1\\t10.0.0.10\\t12345\\t10.0.0.20\\t502\\ttcp\\tmodbus\\t1.2\\t100\\t50\\tSF\\tShADadFf\\t3\\t2\\n', encoding='utf-8')\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return script


def _install_record(server, tmp_path: Path, *, token: str = "a" * 32, filename: str = "capture.pcap", sha: str = "b" * 64):
    evidence_dir = tmp_path / f"evidence-{token[:4]}"
    evidence_dir.mkdir(exist_ok=True)
    record = {
        "evidenceToken": token,
        "path": str(evidence_dir),
        "filename": filename,
        "pcap_sha256": sha,
        "zeek_policy_sha256": "policy-a",
        "zeek_runtime": "runtime-a",
        "createdAt": time.time(),
        "leases": 0,
    }
    with server._EVIDENCE_LOCK:
        server._EVIDENCE_CACHE[token] = record
    return token, evidence_dir, record


def _install_job(server, job_id: str) -> None:
    with server._ANALYSIS_LOCK:
        server._ANALYSIS_JOBS[job_id] = {
            "jobId": job_id,
            "status": "queued",
            "stage": "queued",
            "progress": 0,
            "message": "queued",
            "detail": None,
        }


def _clear_server_state(server) -> None:
    with server._EVIDENCE_LOCK:
        records = list(server._EVIDENCE_CACHE.values())
        server._EVIDENCE_CACHE.clear()
    for record in records:
        path = Path(str(record.get("path", "")))
        if path.is_dir():
            import shutil
            shutil.rmtree(path, ignore_errors=True)
    with server._ANALYSIS_LOCK:
        server._ANALYSIS_JOBS.clear()


def test_context_discovery_and_detector_analysis_reuse_one_zeek_extraction(tmp_path, monkeypatch):
    counter = tmp_path / "zeek-count.txt"
    fake = _counting_fake_zeek(tmp_path, counter)
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(b"fake pcap")
    evidence_dir = tmp_path / "evidence"
    monkeypatch.setenv("ELEVADR_ZEEK_COMMAND", f'"{sys.executable}" "{fake}"')

    discovery = discover_context_with_retained_evidence(
        pcap,
        evidence_dir,
        source_filename="capture.pcap",
    )
    report = analyze_zeek_evidence_to_report(
        evidence_dir,
        representative_profile(),
        source_filename="capture.pcap",
        evidence_metadata={"zeek_evidence_id": "test-evidence"},
    )

    assert int(counter.read_text()) == 1
    assert discovery["recordsParsed"] > 0
    provenance = report["arch_insights"]["analysis_provenance"]
    assert provenance["zeek_evidence_reused"] is True
    assert provenance["zeek_evidence_id"] == "test-evidence"


def test_analysis_job_prefers_retained_evidence_over_fresh_pcap(tmp_path):
    from backend_bryan.integration import http_reference_server as server

    _clear_server_state(server)
    token, _evidence_dir, record = _install_record(server, tmp_path)
    job_id = "one-pass-analysis-job"
    _install_job(server, job_id)

    fake_report = {"report_version": "2.0.0", "report_id": "elevadr-reused", "executive_summary": {}, "modules": {}, "arch_insights": {}}
    with patch.object(server, "_runtime_signature_matches", return_value=True), patch.object(
        server, "analyze_zeek_evidence_to_report", return_value=fake_report
    ) as reused, patch.object(server, "analyze_pcap_to_report", side_effect=AssertionError("fresh Zeek path must not run")):
        server._run_analysis_job(job_id, None, "capture.pcap", {"schemaVersion": 3}, token, record["pcap_sha256"])

    reused.assert_called_once()
    job = server._analysis_job_snapshot(job_id)
    assert job is not None
    assert job["status"] == "completed"
    assert job["result"]["report_id"] == "elevadr-reused"
    assert server._evidence_snapshot(token)["leases"] == 0
    _clear_server_state(server)


def test_expired_token_is_rejected_and_evidence_removed(tmp_path, monkeypatch):
    from backend_bryan.integration import http_reference_server as server

    _clear_server_state(server)
    token, evidence_dir, record = _install_record(server, tmp_path)
    record["createdAt"] = time.time() - 100
    with server._EVIDENCE_LOCK:
        server._EVIDENCE_CACHE[token]["createdAt"] = record["createdAt"]
    monkeypatch.setattr(server, "EVIDENCE_TTL_SECONDS", 1)

    with pytest.raises(server.EvidenceExpired):
        server._acquire_evidence(token, expected_filename="capture.pcap", expected_pcap_sha256=record["pcap_sha256"])
    assert server._evidence_snapshot(token) is None
    assert not evidence_dir.exists()


def test_tampered_token_never_resolves_to_cached_evidence(tmp_path):
    from backend_bryan.integration import http_reference_server as server

    _clear_server_state(server)
    token, _evidence_dir, _record = _install_record(server, tmp_path)
    tampered = token[:-1] + ("c" if token[-1] != "c" else "d")
    assert server._evidence_snapshot(tampered) is None
    with pytest.raises(server.EvidenceExpired):
        server._acquire_evidence(tampered)
    assert server._evidence_snapshot(token) is not None
    _clear_server_state(server)


def test_wrong_pcap_filename_or_hash_cannot_reuse_token(tmp_path):
    from backend_bryan.integration import http_reference_server as server

    _clear_server_state(server)
    token, _evidence_dir, record = _install_record(server, tmp_path)
    with patch.object(server, "_runtime_signature_matches", return_value=True):
        with pytest.raises(server.EvidenceBindingMismatch, match="different PCAP filename"):
            server._acquire_evidence(token, expected_filename="other.pcap", expected_pcap_sha256=record["pcap_sha256"])
        with pytest.raises(server.EvidenceBindingMismatch, match="does not match"):
            server._acquire_evidence(token, expected_filename="capture.pcap", expected_pcap_sha256="c" * 64)
    assert server._evidence_snapshot(token)["leases"] == 0
    _clear_server_state(server)


def test_runtime_or_policy_change_invalidates_new_reuse(tmp_path):
    from backend_bryan.integration import http_reference_server as server

    _clear_server_state(server)
    token, _evidence_dir, record = _install_record(server, tmp_path)
    with patch.object(server, "_runtime_signature_matches", return_value=False):
        with pytest.raises(server.EvidenceRuntimeMismatch):
            server._acquire_evidence(token, expected_filename="capture.pcap", expected_pcap_sha256=record["pcap_sha256"])
    assert server._evidence_snapshot(token)["leases"] == 0
    _clear_server_state(server)


def test_concurrent_leases_prevent_cleanup_until_last_analysis_releases(tmp_path, monkeypatch):
    from backend_bryan.integration import http_reference_server as server

    _clear_server_state(server)
    token, evidence_dir, record = _install_record(server, tmp_path)
    monkeypatch.setattr(server, "EVIDENCE_TTL_SECONDS", 1)
    with patch.object(server, "_runtime_signature_matches", return_value=True):
        first = server._acquire_evidence(token, expected_filename="capture.pcap", expected_pcap_sha256=record["pcap_sha256"])
        second = server._acquire_evidence(token, expected_filename="capture.pcap", expected_pcap_sha256=record["pcap_sha256"])
    assert first["path"] == second["path"]
    with server._EVIDENCE_LOCK:
        server._EVIDENCE_CACHE[token]["createdAt"] = time.time() - 100
    server._cleanup_expired_evidence()
    assert evidence_dir.exists()
    assert server._evidence_snapshot(token) is not None
    server._release_evidence(token)
    assert evidence_dir.exists()
    server._release_evidence(token)
    assert not evidence_dir.exists()
    assert server._evidence_snapshot(token) is None


def test_restart_cleanup_removes_orphaned_managed_evidence(tmp_path, monkeypatch):
    from backend_bryan.integration import http_reference_server as server

    root = tmp_path / "managed-cache"
    orphan = root / "evidence-old"
    orphan.mkdir(parents=True)
    (orphan / "conn.log").write_text("old")
    stray = root / "stale.tmp"
    stray.write_text("old")
    monkeypatch.setattr(server, "EVIDENCE_CACHE_ROOT", root)

    server._cleanup_restart_orphans()
    assert root.is_dir()
    assert list(root.iterdir()) == []



def test_missing_evidence_directory_invalidates_token(tmp_path):
    from backend_bryan.integration import http_reference_server as server

    _clear_server_state(server)
    token, evidence_dir, record = _install_record(server, tmp_path)
    evidence_dir.rmdir()
    with patch.object(server, "_runtime_signature_matches", return_value=True):
        with pytest.raises(server.EvidenceExpired, match="files are unavailable"):
            server._acquire_evidence(token, expected_filename="capture.pcap", expected_pcap_sha256=record["pcap_sha256"])
    _clear_server_state(server)

def test_same_evidence_can_be_reanalyzed_with_different_detection_contexts(tmp_path):
    from backend_bryan.integration import http_reference_server as server

    _clear_server_state(server)
    token, _evidence_dir, record = _install_record(server, tmp_path)
    reports = [
        {"report_version": "2.0.0", "report_id": "profile-a", "executive_summary": {}, "modules": {}, "arch_insights": {}},
        {"report_version": "2.0.0", "report_id": "profile-b", "executive_summary": {}, "modules": {}, "arch_insights": {}},
    ]
    profiles = [
        {"schemaVersion": 3, "id": "profile-a", "name": "Context A"},
        {"schemaVersion": 3, "id": "profile-b", "name": "Context B"},
    ]
    for index, profile in enumerate(profiles):
        job_id = f"reanalyze-{index}"
        _install_job(server, job_id)
        with patch.object(server, "_runtime_signature_matches", return_value=True), patch.object(
            server, "analyze_zeek_evidence_to_report", return_value=reports[index]
        ) as reused:
            server._run_analysis_job(job_id, None, "capture.pcap", profile, token, record["pcap_sha256"])
        args = reused.call_args.args
        assert args[1] == profile
        assert server._analysis_job_snapshot(job_id)["status"] == "completed"
    assert server._evidence_snapshot(token)["leases"] == 0
    assert server._evidence_snapshot(token)["pcap_sha256"] == record["pcap_sha256"]
    _clear_server_state(server)


def test_two_analysis_jobs_can_read_same_evidence_concurrently(tmp_path):
    from backend_bryan.integration import http_reference_server as server

    _clear_server_state(server)
    token, _evidence_dir, record = _install_record(server, tmp_path)
    for job_id in ("concurrent-a", "concurrent-b"):
        _install_job(server, job_id)

    entered = threading.Barrier(3)
    release = threading.Event()

    def fake_analyze(*args, **kwargs):
        entered.wait(timeout=5)
        release.wait(timeout=5)
        return {"report_version": "2.0.0", "report_id": threading.current_thread().name, "executive_summary": {}, "modules": {}, "arch_insights": {}}

    with patch.object(server, "_runtime_signature_matches", return_value=True), patch.object(
        server, "analyze_zeek_evidence_to_report", side_effect=fake_analyze
    ):
        threads = [
            threading.Thread(target=server._run_analysis_job, name="job-a", args=("concurrent-a", None, "capture.pcap", {"schemaVersion": 3}, token, record["pcap_sha256"])),
            threading.Thread(target=server._run_analysis_job, name="job-b", args=("concurrent-b", None, "capture.pcap", {"schemaVersion": 3}, token, record["pcap_sha256"])),
        ]
        for thread in threads:
            thread.start()
        entered.wait(timeout=5)
        snapshot = server._evidence_snapshot(token)
        assert snapshot is not None and snapshot["leases"] == 2
        release.set()
        for thread in threads:
            thread.join(timeout=5)
            assert not thread.is_alive()

    assert server._analysis_job_snapshot("concurrent-a")["status"] == "completed"
    assert server._analysis_job_snapshot("concurrent-b")["status"] == "completed"
    assert server._evidence_snapshot(token)["leases"] == 0
    _clear_server_state(server)


def _evidence_fingerprint(evidence_dir: Path) -> dict[str, str]:
    return {
        str(path.relative_to(evidence_dir)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(evidence_dir.rglob("*"))
        if path.is_file()
    }


def _reanalysis_profile(name: str, *, source_role: str = "it", allow_segment_pair: bool = False) -> dict:
    profile = copy.deepcopy(representative_profile())
    profile["id"] = name.lower().replace(" ", "-")
    profile["name"] = name
    profile["selectedModules"] = ["control_system_enterprise_non_dmz"]
    profile["segments"] = [
        {
            "id": "source-zone",
            "name": "Source Zone",
            "cidr": "10.0.0.10/32",
            "role": source_role,
            "purdueLevel": "Level 4" if source_role == "it" else "Level 3",
            "addressing": "static",
            "dhcpAllowed": False,
            "ipv6Allowed": False,
        },
        {
            "id": "control-zone",
            "name": "Control Zone",
            "cidr": "10.0.0.20/32",
            "role": "ot",
            "purdueLevel": "Level 2",
            "addressing": "static",
            "dhcpAllowed": False,
            "ipv6Allowed": False,
        },
    ]
    profile["assets"][0].update({"segment": "Source Zone", "role": source_role})
    profile["assets"][1].update({"segment": "Control Zone", "role": "ot"})
    profile["allowedSegmentPairs"] = (
        [{"sourceSegment": "Source Zone", "destinationSegment": "Control Zone"}]
        if allow_segment_pair
        else []
    )
    return profile


def test_one_extraction_supports_multiple_real_context_analyses_without_mutating_evidence(tmp_path, monkeypatch):
    counter = tmp_path / "zeek-count.txt"
    fake = _counting_fake_zeek(tmp_path, counter)
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(b"fake pcap")
    evidence_dir = tmp_path / "retained-evidence"
    monkeypatch.setenv("ELEVADR_ZEEK_COMMAND", f'"{sys.executable}" "{fake}"')

    discovery = discover_context_with_retained_evidence(
        pcap,
        evidence_dir,
        source_filename="capture.pcap",
    )
    assert discovery["recordsParsed"] > 0
    assert int(counter.read_text()) == 1

    original_fingerprint = _evidence_fingerprint(evidence_dir)
    assert original_fingerprint

    contexts = [
        (
            _reanalysis_profile("Direct IT to OT"),
            1,
        ),
        (
            _reanalysis_profile("Same-zone OT", source_role="ot"),
            0,
        ),
        (
            _reanalysis_profile("Approved IT to OT", allow_segment_pair=True),
            0,
        ),
    ]

    reports = []
    for index, (profile, expected_findings) in enumerate(contexts, start=1):
        report = analyze_zeek_evidence_to_report(
            evidence_dir,
            profile,
            source_filename="capture.pcap",
            evidence_metadata={
                "zeek_evidence_id": "shared-evidence",
                "pcap_sha256": "1" * 64,
            },
        )
        reports.append(report)

        detector_results = report["arch_insights"]["detector_results"]
        assert len(detector_results) == 1
        assert detector_results[0]["module_id"] == "control_system_enterprise_non_dmz"
        assert len(detector_results[0]["findings"]) == expected_findings

        provenance = report["arch_insights"]["analysis_provenance"]
        assert provenance["zeek_evidence_reused"] is True
        assert provenance["zeek_evidence_id"] == "shared-evidence"
        assert provenance["pcap_sha256"] == "1" * 64

        assert _evidence_fingerprint(evidence_dir) == original_fingerprint, (
            f"retained Zeek evidence changed after analysis {index}: {profile['name']}"
        )
        assert int(counter.read_text()) == 1

    assert [len(r["arch_insights"]["detector_findings"]) for r in reports] == [1, 0, 0]
    assert _evidence_fingerprint(evidence_dir) == original_fingerprint
    assert int(counter.read_text()) == 1
