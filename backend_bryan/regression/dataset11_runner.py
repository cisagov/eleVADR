from __future__ import annotations

import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable

import backend_bryan.integration.analysis_service as analysis_service
import backend_bryan.integration.http_reference_server as server


def run_cases(verbose: bool = True) -> list[str]:
    failures: list[str] = []
    passed = 0

    def check(label: str, fn: Callable[[], None]) -> None:
        nonlocal passed
        try:
            fn()
        except Exception as exc:
            failures.append(f"{label}: {type(exc).__name__}: {exc}")
            if verbose:
                print(f"FAIL  {label} ({type(exc).__name__}: {exc})")
        else:
            passed += 1
            if verbose:
                print(f"PASS  {label}")

    if verbose:
        print("\n=== 11_failure_recovery: Cancellation, partial results, retry, and job isolation ===")

    def partial_detector_failure_isolated() -> None:
        class Context:
            def __init__(self, metadata: dict[str, Any], **logs: Any):
                self.metadata = metadata
                self.__dict__.update(logs)

        class Good:
            def analyze(self, _context: Any) -> Any:
                return SimpleNamespace(to_dict=lambda: {"module_id": "good", "findings": [{"title": "kept"}]})

        class Bad:
            def analyze(self, _context: Any) -> Any:
                raise RuntimeError("synthetic detector failure")

        old = analysis_service.ensure_detector_package
        analysis_service.ensure_detector_package = lambda: (Context, {"good": Good(), "bad": Bad()}, "fake")
        try:
            req = {
                "contractVersion": "elevadr.detection-context.analysis.v1",
                "profile": {
                    "schemaVersion": 3, "id": "d11", "name": "Failure recovery", "segments": [], "assets": [],
                    "infrastructure": [], "communicationPairs": [], "allowedHosts": [], "allowedSegmentPairs": [],
                    "approvedExternalDestinations": [], "authorizedControlActions": [], "modulePolicies": {},
                    "selectedModules": ["good", "bad"], "captureScope": {}, "scan": {},
                },
                "logs": {},
            }
            result = analysis_service.analyze_detection_request(req)
            assert result["status"] == "partial"
            assert result["summary"] == {"requestedModules": 2, "completedModules": 1, "failedModules": 1, "findingCount": 1}
            assert result["moduleResults"][0]["module_id"] == "good"
            assert result["errors"][0]["code"] == "module_execution_failed"
        finally:
            analysis_service.ensure_detector_package = old
    check("Detector exception is isolated and successful findings survive as a partial response", partial_detector_failure_isolated)

    def stale_job_ids_are_isolated() -> None:
        assert server._analysis_job_snapshot("missing") is None
        assert server._job_snapshot("missing") is None
        assert server._cancel_analysis_job("missing") is False
        assert server._cancel_discovery_job("missing") is False
    check("Stale or unknown job IDs cannot affect active job state", stale_job_ids_are_isolated)

    def analysis_cancel_is_cooperative() -> None:
        job = "cancel-analysis"
        with server._ANALYSIS_LOCK:
            server._ANALYSIS_JOBS[job] = {"jobId": job, "status": "running", "createdAt": 0.0, "updatedAt": 0.0}
        try:
            assert server._cancel_analysis_job(job) is True
            snap = server._analysis_job_snapshot(job)
            assert snap and snap["status"] == "canceling" and snap["cancelRequested"] is True
            try:
                server._raise_if_analysis_canceled(job)
            except server.JobCancelled:
                pass
            else:
                raise AssertionError("canceled analysis did not raise cooperative cancellation")
        finally:
            with server._ANALYSIS_LOCK:
                server._ANALYSIS_JOBS.pop(job, None)
    check("PCAP-analysis cancellation becomes a cooperative cancel signal", analysis_cancel_is_cooperative)

    def discovery_cancel_is_cooperative() -> None:
        job = "cancel-discovery"
        with server._DISCOVERY_LOCK:
            server._DISCOVERY_JOBS[job] = {"jobId": job, "status": "running", "createdAt": 0.0, "updatedAt": 0.0}
        try:
            assert server._cancel_discovery_job(job) is True
            snap = server._job_snapshot(job)
            assert snap and snap["status"] == "canceling" and snap["cancelRequested"] is True
            try:
                server._raise_if_discovery_canceled(job)
            except server.JobCancelled:
                pass
            else:
                raise AssertionError("canceled discovery did not raise cooperative cancellation")
        finally:
            with server._DISCOVERY_LOCK:
                server._DISCOVERY_JOBS.pop(job, None)
    check("Context-discovery cancellation becomes a cooperative cancel signal", discovery_cancel_is_cooperative)

    def failed_job_cleans_temp_and_has_no_result() -> None:
        job = "failed-job"
        with tempfile.NamedTemporaryFile(delete=False) as handle:
            temp = Path(handle.name)
            handle.write(b"pcap")
        with server._ANALYSIS_LOCK:
            server._ANALYSIS_JOBS[job] = {"jobId": job, "status": "queued", "createdAt": 0.0, "updatedAt": 0.0}
        old = server.analyze_pcap_to_report
        server.analyze_pcap_to_report = lambda *a, **k: (_ for _ in ()).throw(ValueError("synthetic pipeline failure"))
        try:
            server._run_analysis_job(job, temp, "capture.pcap", {})
            snap = server._analysis_job_snapshot(job)
            assert snap and snap["status"] == "failed" and snap["error"] == "pcap_analysis_failed"
            assert "result" not in snap
            assert not temp.exists()
        finally:
            server.analyze_pcap_to_report = old
            with server._ANALYSIS_LOCK:
                server._ANALYSIS_JOBS.pop(job, None)
            temp.unlink(missing_ok=True)
    check("Failed PCAP jobs clean temporary files and never publish a partial report result", failed_job_cleans_temp_and_has_no_result)

    def canceled_job_cleans_temp_and_has_no_result() -> None:
        job = "canceled-job"
        with tempfile.NamedTemporaryFile(delete=False) as handle:
            temp = Path(handle.name)
            handle.write(b"pcap")
        with server._ANALYSIS_LOCK:
            server._ANALYSIS_JOBS[job] = {"jobId": job, "status": "canceling", "cancelRequested": True, "createdAt": 0.0, "updatedAt": 0.0}
        try:
            server._run_analysis_job(job, temp, "capture.pcap", {})
            snap = server._analysis_job_snapshot(job)
            assert snap and snap["status"] == "canceled" and snap["error"] == "canceled"
            assert "result" not in snap
            assert not temp.exists()
        finally:
            with server._ANALYSIS_LOCK:
                server._ANALYSIS_JOBS.pop(job, None)
            temp.unlink(missing_ok=True)
    check("Canceled jobs terminate without publishing a report and clean temporary files", canceled_job_cleans_temp_and_has_no_result)

    def zeek_runtime_failure_is_structured() -> None:
        job = "zeek-failure"
        with tempfile.NamedTemporaryFile(delete=False) as handle:
            temp = Path(handle.name); handle.write(b"pcap")
        with server._ANALYSIS_LOCK:
            server._ANALYSIS_JOBS[job] = {"jobId": job, "status": "queued", "createdAt": 0.0, "updatedAt": 0.0}
        old = server.analyze_pcap_to_report
        server.analyze_pcap_to_report = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("Zeek unavailable"))
        try:
            server._run_analysis_job(job, temp, "capture.pcap", {})
            snap = server._analysis_job_snapshot(job)
            assert snap and snap["status"] == "failed" and snap["error"] == "zeek_unavailable"
            assert "result" not in snap and not temp.exists()
        finally:
            server.analyze_pcap_to_report = old
            with server._ANALYSIS_LOCK: server._ANALYSIS_JOBS.pop(job, None)
            temp.unlink(missing_ok=True)
    check("Zeek runtime failure is reported as a structured failed job without a report result", zeek_runtime_failure_is_structured)

    def retry_uses_fresh_job_state() -> None:
        with server._ANALYSIS_LOCK:
            server._ANALYSIS_JOBS["old"] = {"jobId": "old", "status": "failed", "error": "x", "createdAt": 0.0, "updatedAt": 0.0}
            server._ANALYSIS_JOBS["retry"] = {"jobId": "retry", "status": "queued", "createdAt": 0.0, "updatedAt": 0.0}
        try:
            server._analysis_job_update("retry", status="completed", result={"report_id": "fresh"})
            old = server._analysis_job_snapshot("old")
            retry = server._analysis_job_snapshot("retry")
            assert old and old["status"] == "failed" and "result" not in old
            assert retry and retry["status"] == "completed" and retry["result"]["report_id"] == "fresh"
        finally:
            with server._ANALYSIS_LOCK:
                server._ANALYSIS_JOBS.pop("old", None); server._ANALYSIS_JOBS.pop("retry", None)
    check("A retry uses a new job record and cannot inherit failure/result state from the previous attempt", retry_uses_fresh_job_state)

    if verbose:
        print(f"{'FAIL' if failures else 'PASS'}: Dataset 11 verified {passed} failure-recovery/cancellation cases.")
    return failures


def main() -> int:
    failures = run_cases(True)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
