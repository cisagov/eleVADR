"""Local stdlib reference server for eleVADR contract and PCAP analysis.

This is intentionally isolated under backend_bryan. It is not production server
code. The PCAP endpoint reads multipart requests into memory for developer use;
a production backend should stream uploads and use its normal job framework.

PCAP context discovery is job-based so the browser can poll real Zeek/Docker
progress while the capture is being processed.
"""
from __future__ import annotations

import argparse
import atexit
import hashlib
import json
import os
import shutil
import tempfile
import threading
import time
import uuid
from email.parser import BytesParser
from email.policy import default
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from backend_bryan.integration.analysis_service import analyze_detection_request
from backend_bryan.integration.detector_runtime import ensure_detector_package
from backend_bryan.integration.pcap_analysis import analyze_pcap_to_report, analyze_zeek_evidence_to_report
from backend_bryan.integration.context_discovery import discover_context_with_retained_evidence

ANALYSIS_PATH = "/api/v1/detection-analysis"
PCAP_PATH = "/api/v1/pcap-analysis"
DISCOVERY_PATH = "/api/v1/pcap-context-discovery"
HEALTH_PATH = "/health"

MAX_JSON_REQUEST_BYTES = 16 * 1024 * 1024
MAX_PCAP_UPLOAD_BYTES = 1024 * 1024 * 1024
MAX_UPLOAD_FILENAME_CHARS = 255


class JobCancelled(RuntimeError):
    """Cooperative cancellation signal for reference analysis jobs."""


def _sanitize_upload_filename(value: str | None, default_name: str = "capture.pcap") -> str:
    raw = str(value or "").replace("\\", "/")
    name = raw.rsplit("/", 1)[-1]
    name = "".join(ch for ch in name if ch >= " " and ch != "\x7f").strip().strip(".")
    if not name:
        name = default_name
    return name[:MAX_UPLOAD_FILENAME_CHARS]


def _validated_content_length(headers: Any, maximum: int, label: str) -> int:
    raw = headers.get("Content-Length", "0")
    try:
        length = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid Content-Length for {label}") from exc
    if length < 0:
        raise ValueError(f"Invalid Content-Length for {label}")
    if length > maximum:
        raise ValueError(f"{label} exceeds the {maximum}-byte developer-server limit")
    return length


def _strict_json_loads(raw: bytes) -> Any:
    text = raw.decode("utf-8")
    def reject_constant(value: str) -> None:
        raise ValueError(f"Non-finite JSON number is not allowed: {value}")
    return json.loads(text, parse_constant=reject_constant)

_DISCOVERY_JOBS: dict[str, dict[str, Any]] = {}
_DISCOVERY_LOCK = threading.Lock()
_ANALYSIS_JOBS: dict[str, dict[str, Any]] = {}
_ANALYSIS_LOCK = threading.Lock()
_EVIDENCE_CACHE: dict[str, dict[str, Any]] = {}
_EVIDENCE_LOCK = threading.Lock()
EVIDENCE_TTL_SECONDS = int(os.environ.get("ELEVADR_EVIDENCE_TTL_SECONDS", "7200"))
EVIDENCE_CACHE_ROOT = Path(os.environ.get("ELEVADR_EVIDENCE_CACHE_ROOT", str(Path(tempfile.gettempdir()) / "elevadr-zeek-evidence-cache")))


class EvidenceError(RuntimeError):
    """Base class for retained Zeek evidence lifecycle errors."""


class EvidenceExpired(EvidenceError):
    """The requested evidence token no longer refers to reusable evidence."""


class EvidenceBindingMismatch(EvidenceError):
    """The token was presented for a different PCAP identity."""


class EvidenceRuntimeMismatch(EvidenceError):
    """The extraction runtime/policy differs from the current runtime/policy."""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _ensure_evidence_cache_root() -> Path:
    EVIDENCE_CACHE_ROOT.mkdir(parents=True, exist_ok=True)
    return EVIDENCE_CACHE_ROOT


def _cleanup_restart_orphans() -> None:
    """Remove retained evidence from a previous server process.

    Tokens are intentionally process-local. After a restart there is no in-memory
    mapping that can safely authenticate an old token, so old managed directories
    are deleted before accepting work.
    """
    root = _ensure_evidence_cache_root()
    for child in root.iterdir():
        if child.is_dir():
            shutil.rmtree(child, ignore_errors=True)
        else:
            try:
                child.unlink()
            except OSError:
                pass


def _record_is_expired(record: dict[str, Any], now: float | None = None) -> bool:
    current = time.time() if now is None else now
    return current - float(record.get("createdAt", current)) > EVIDENCE_TTL_SECONDS


def _cleanup_expired_evidence(*, force: bool = False) -> None:
    now = time.time()
    doomed: list[dict[str, Any]] = []
    with _EVIDENCE_LOCK:
        for token, record in list(_EVIDENCE_CACHE.items()):
            expired = force or _record_is_expired(record, now)
            if not expired:
                continue
            if not force and int(record.get("leases", 0)) > 0:
                record["expiredPendingRelease"] = True
                continue
            doomed.append(record)
            _EVIDENCE_CACHE.pop(token, None)
    for record in doomed:
        path = Path(str(record.get("path", "")))
        if str(path):
            shutil.rmtree(path, ignore_errors=True)


def _runtime_signature_matches(record: dict[str, Any]) -> bool:
    from backend_bryan.runtime.zeek_runtime import zeek_evidence_signature

    current = zeek_evidence_signature()
    return (
        str(record.get("zeek_policy_sha256", "")) == str(current.get("zeek_policy_sha256", ""))
        and str(record.get("zeek_runtime", "")) == str(current.get("zeek_runtime", ""))
    )


def _register_evidence(path: Path, filename: str, pcap_sha256: str) -> tuple[str, dict[str, Any]]:
    from backend_bryan.runtime.zeek_runtime import zeek_evidence_signature

    _cleanup_expired_evidence()
    token = uuid.uuid4().hex
    signature = zeek_evidence_signature()
    record = {
        "evidenceToken": token,
        "path": str(path.resolve()),
        "filename": _sanitize_upload_filename(filename),
        "pcap_sha256": pcap_sha256,
        "zeek_policy_sha256": signature.get("zeek_policy_sha256", ""),
        "zeek_runtime": signature.get("zeek_runtime", ""),
        "createdAt": time.time(),
        "leases": 0,
    }
    with _EVIDENCE_LOCK:
        _EVIDENCE_CACHE[token] = record
    return token, dict(record)


def _evidence_snapshot(token: str) -> dict[str, Any] | None:
    if len(token) != 32 or any(ch not in "0123456789abcdef" for ch in token.lower()):
        return None
    _cleanup_expired_evidence()
    with _EVIDENCE_LOCK:
        record = _EVIDENCE_CACHE.get(token)
        return dict(record) if record is not None else None


def _acquire_evidence(
    token: str,
    *,
    expected_filename: str | None = None,
    expected_pcap_sha256: str | None = None,
) -> dict[str, Any]:
    """Validate and lease retained evidence for one analysis job."""
    if len(token) != 32 or any(ch not in "0123456789abcdef" for ch in token.lower()):
        raise EvidenceExpired("Retained Zeek evidence token is invalid or unavailable.")
    _cleanup_expired_evidence()
    with _EVIDENCE_LOCK:
        record = _EVIDENCE_CACHE.get(token)
        if record is None or _record_is_expired(record):
            raise EvidenceExpired("Retained Zeek evidence has expired or is unavailable. Re-open the PCAP to extract evidence again.")
        if expected_filename is not None:
            expected = _sanitize_upload_filename(expected_filename)
            if expected != str(record.get("filename", "")):
                raise EvidenceBindingMismatch("Retained Zeek evidence belongs to a different PCAP filename. Re-open the selected PCAP.")
        if expected_pcap_sha256:
            if expected_pcap_sha256.lower() != str(record.get("pcap_sha256", "")).lower():
                raise EvidenceBindingMismatch("Retained Zeek evidence does not match the selected PCAP identity. Re-open the selected PCAP.")
        if not _runtime_signature_matches(record):
            raise EvidenceRuntimeMismatch("The Zeek runtime or extraction policy changed after evidence extraction. Re-open the PCAP to regenerate compatible evidence.")
        path = Path(str(record.get("path", "")))
        if not path.is_dir():
            raise EvidenceExpired("Retained Zeek evidence files are unavailable. Re-open the PCAP to extract evidence again.")
        record["leases"] = int(record.get("leases", 0)) + 1
        return dict(record)


def _release_evidence(token: str) -> None:
    doomed: dict[str, Any] | None = None
    with _EVIDENCE_LOCK:
        record = _EVIDENCE_CACHE.get(token)
        if record is None:
            return
        record["leases"] = max(0, int(record.get("leases", 0)) - 1)
        if record["leases"] == 0 and (record.get("expiredPendingRelease") or _record_is_expired(record)):
            doomed = record
            _EVIDENCE_CACHE.pop(token, None)
    if doomed is not None:
        shutil.rmtree(Path(str(doomed.get("path", ""))), ignore_errors=True)


atexit.register(lambda: _cleanup_expired_evidence(force=True))


def _job_update(job_id: str, **updates: Any) -> None:
    with _DISCOVERY_LOCK:
        job = _DISCOVERY_JOBS.get(job_id)
        if job is not None:
            job.update(updates)
            job["updatedAt"] = time.time()


def _job_snapshot(job_id: str) -> dict[str, Any] | None:
    with _DISCOVERY_LOCK:
        job = _DISCOVERY_JOBS.get(job_id)
        return dict(job) if job is not None else None




def _analysis_job_update(job_id: str, **updates: Any) -> None:
    with _ANALYSIS_LOCK:
        job = _ANALYSIS_JOBS.get(job_id)
        if job is not None:
            job.update(updates)
            job["updatedAt"] = time.time()


def _analysis_job_snapshot(job_id: str) -> dict[str, Any] | None:
    with _ANALYSIS_LOCK:
        job = _ANALYSIS_JOBS.get(job_id)
        return dict(job) if job is not None else None


def _cancel_analysis_job(job_id: str) -> bool:
    with _ANALYSIS_LOCK:
        job = _ANALYSIS_JOBS.get(job_id)
        if job is None:
            return False
        if job.get("status") in {"completed", "failed", "canceled"}:
            return True
        job["cancelRequested"] = True
        job["status"] = "canceling"
        job["stage"] = "canceling"
        job["message"] = "Canceling PCAP analysis…"
        job["updatedAt"] = time.time()
        return True


def _cancel_discovery_job(job_id: str) -> bool:
    with _DISCOVERY_LOCK:
        job = _DISCOVERY_JOBS.get(job_id)
        if job is None:
            return False
        if job.get("status") in {"completed", "failed", "canceled"}:
            return True
        job["cancelRequested"] = True
        job["status"] = "canceling"
        job["stage"] = "canceling"
        job["message"] = "Canceling context discovery…"
        job["updatedAt"] = time.time()
        return True


def _raise_if_analysis_canceled(job_id: str) -> None:
    snapshot = _analysis_job_snapshot(job_id)
    if snapshot and snapshot.get("cancelRequested"):
        raise JobCancelled("PCAP analysis canceled by client")


def _raise_if_discovery_canceled(job_id: str) -> None:
    snapshot = _job_snapshot(job_id)
    if snapshot and snapshot.get("cancelRequested"):
        raise JobCancelled("Context discovery canceled by client")


def _run_analysis_job(
    job_id: str,
    temp_path: Path | None,
    filename: str,
    profile: dict[str, Any],
    evidence_token: str | None = None,
    evidence_pcap_sha256: str | None = None,
) -> None:
    started = time.time()
    evidence_leased = False

    def progress(stage: str, value: int | None, message: str, detail: str | None = None) -> None:
        _raise_if_analysis_canceled(job_id)
        _analysis_job_update(
            job_id,
            status="running",
            stage=stage,
            progress=value,
            message=message,
            detail=detail,
            elapsedSeconds=round(time.time() - started, 1),
        )

    try:
        if evidence_token:
            evidence = _acquire_evidence(
                evidence_token,
                expected_filename=filename,
                expected_pcap_sha256=evidence_pcap_sha256,
            )
            evidence_leased = True
            progress("preparing-analysis", 1, "Preparing analysis from retained Zeek evidence…", filename)
            report = analyze_zeek_evidence_to_report(
                Path(str(evidence["path"])),
                profile,
                source_filename=filename,
                progress=progress,
                evidence_metadata={
                    "zeek_evidence_id": evidence_token,
                    "pcap_sha256": evidence.get("pcap_sha256"),
                    "zeek_policy_sha256": evidence.get("zeek_policy_sha256"),
                    "zeek_evidence_created_at": evidence.get("createdAt"),
                },
            )
        else:
            if temp_path is None:
                raise ValueError("PCAP analysis requires either retained Zeek evidence or a PCAP upload")
            progress("preparing-analysis", 1, "Preparing PCAP analysis…", filename)
            report = analyze_pcap_to_report(temp_path, profile, source_filename=filename, progress=progress)
        _analysis_job_update(
            job_id,
            status="completed",
            stage="completed",
            progress=100,
            message="Analysis complete. Loading eleVADR report…",
            detail=report.get("report_id"),
            elapsedSeconds=round(time.time() - started, 1),
            result=report,
        )
    except JobCancelled as exc:
        _analysis_job_update(job_id, status="canceled", stage="canceled", progress=None, message=str(exc), detail=None, error="canceled")
    except EvidenceExpired as exc:
        _analysis_job_update(job_id, status="failed", stage="failed", progress=None, message=str(exc), detail=None, error="evidence_expired")
    except EvidenceBindingMismatch as exc:
        _analysis_job_update(job_id, status="failed", stage="failed", progress=None, message=str(exc), detail=None, error="evidence_mismatch")
    except EvidenceRuntimeMismatch as exc:
        _analysis_job_update(job_id, status="failed", stage="failed", progress=None, message=str(exc), detail=None, error="evidence_runtime_mismatch")
    except RuntimeError as exc:
        _analysis_job_update(job_id, status="failed", stage="failed", progress=None, message=str(exc), detail=None, error="zeek_unavailable")
    except Exception as exc:
        _analysis_job_update(
            job_id,
            status="failed",
            stage="failed",
            progress=None,
            message=f"{type(exc).__name__}: {exc}",
            detail=None,
            error="pcap_analysis_failed",
        )
    finally:
        if evidence_token and evidence_leased:
            _release_evidence(evidence_token)
        if temp_path is not None:
            try:
                os.unlink(temp_path)
            except OSError:
                pass

def _run_discovery_job(job_id: str, temp_path: Path, filename: str) -> None:
    started = time.time()
    evidence_dir = Path(tempfile.mkdtemp(prefix="evidence-", dir=_ensure_evidence_cache_root()))
    evidence_registered = False

    def progress(stage: str, value: int | None, message: str, detail: str | None = None) -> None:
        _raise_if_discovery_canceled(job_id)
        _job_update(
            job_id,
            status="running",
            stage=stage,
            progress=value,
            message=message,
            detail=detail,
            elapsedSeconds=round(time.time() - started, 1),
        )

    try:
        progress("preparing", 1, "Preparing packet capture…", filename)
        pcap_sha256 = _sha256_file(temp_path)
        result = discover_context_with_retained_evidence(
            temp_path,
            evidence_dir,
            source_filename=filename,
            progress=progress,
        )
        token, evidence = _register_evidence(evidence_dir, filename, pcap_sha256)
        evidence_registered = True
        result["evidenceToken"] = token
        result["evidence"] = {
            "reusable": True,
            "pcapSha256": evidence.get("pcap_sha256"),
            "zeekPolicySha256": evidence.get("zeek_policy_sha256"),
            "ttlSeconds": EVIDENCE_TTL_SECONDS,
        }
        _job_update(
            job_id,
            status="completed",
            stage="completed",
            progress=100,
            message="Zeek evidence extraction and Detection Context discovery complete.",
            detail=f"{len(result.get('assets', []))} assets · {len(result.get('segments', []))} segments · {len(result.get('pairs', []))} communication pairs · evidence retained for analysis",
            elapsedSeconds=round(time.time() - started, 1),
            result=result,
        )
    except JobCancelled as exc:
        _job_update(job_id, status="canceled", stage="canceled", progress=None, message=str(exc), detail=None, error="canceled")
    except RuntimeError as exc:
        _job_update(job_id, status="failed", stage="failed", progress=None, message=str(exc), detail=None, error="zeek_unavailable")
    except Exception as exc:
        _job_update(
            job_id,
            status="failed",
            stage="failed",
            progress=None,
            message=f"{type(exc).__name__}: {exc}",
            detail=None,
            error="context_discovery_failed",
        )
    finally:
        if not evidence_registered:
            shutil.rmtree(evidence_dir, ignore_errors=True)
        try:
            os.unlink(temp_path)
        except OSError:
            pass


def health_payload() -> dict[str, Any]:
    """Return operator-visible runtime/contract diagnostics without mutating state."""
    from backend_bryan.integration.api_contract import REQUEST_CONTRACT_VERSION, RESPONSE_CONTRACT_VERSION
    from backend_bryan.runtime.zeek_runtime import describe_zeek_runtime

    _context_type, modules, _module_file = ensure_detector_package()
    return {
        "status": "ok",
        "detectorModules": len(modules),
        "requestContractVersion": REQUEST_CONTRACT_VERSION,
        "responseContractVersion": RESPONSE_CONTRACT_VERSION,
        "zeekRuntime": describe_zeek_runtime(),
        "evidenceTtlSeconds": EVIDENCE_TTL_SECONDS,
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "eleVADR-backend-bryan/3"

    def _cors_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _json(self, status: int, payload: Any) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:  # noqa: N802
        if self.path not in {ANALYSIS_PATH, PCAP_PATH, DISCOVERY_PATH, HEALTH_PATH} and not self.path.startswith(f"{DISCOVERY_PATH}/") and not self.path.startswith(f"{PCAP_PATH}/"):
            self._json(404, {"error": "not_found"})
            return
        self.send_response(204)
        self._cors_headers()
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        if self.path == HEALTH_PATH:
            self._json(200, health_payload())
            return

        discovery_prefix = f"{DISCOVERY_PATH}/"
        if self.path.startswith(discovery_prefix):
            job_id = self.path[len(discovery_prefix):].strip("/")
            job = _job_snapshot(job_id)
            if job is None:
                self._json(404, {"error": "job_not_found", "message": "Unknown context-discovery job."})
                return
            payload = {key: value for key, value in job.items() if key not in {"createdAt", "updatedAt"}}
            self._json(200, payload)
            return

        analysis_prefix = f"{PCAP_PATH}/"
        if self.path.startswith(analysis_prefix):
            job_id = self.path[len(analysis_prefix):].strip("/")
            job = _analysis_job_snapshot(job_id)
            if job is None:
                self._json(404, {"error": "job_not_found", "message": "Unknown PCAP-analysis job."})
                return
            payload = {key: value for key, value in job.items() if key not in {"createdAt", "updatedAt"}}
            self._json(200, payload)
            return
        self._json(404, {"error": "not_found"})

    def _read_json(self) -> Any:
        length = _validated_content_length(self.headers, MAX_JSON_REQUEST_BYTES, "JSON request")
        return _strict_json_loads(self.rfile.read(length))

    def _multipart(self) -> tuple[bytes | None, str, dict[str, Any], str | None, str | None]:
        content_type = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in content_type:
            raise ValueError("PCAP analysis requires multipart/form-data")
        length = _validated_content_length(self.headers, MAX_PCAP_UPLOAD_BYTES, "PCAP upload")
        raw = self.rfile.read(length)
        message = BytesParser(policy=default).parsebytes(
            f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("utf-8") + raw
        )
        pcap_bytes: bytes | None = None
        filename = "capture.pcap"
        profile: dict[str, Any] | None = None
        evidence_token: str | None = None
        evidence_pcap_sha256: str | None = None
        for part in message.iter_parts():
            name = part.get_param("name", header="content-disposition")
            if name == "file":
                pcap_bytes = part.get_payload(decode=True)
                filename = _sanitize_upload_filename(part.get_filename(), filename)
            elif name == "profile":
                payload = part.get_payload(decode=True) or b"{}"
                profile = _strict_json_loads(payload)
            elif name == "evidenceToken":
                evidence_token = (part.get_payload(decode=True) or b"").decode("utf-8", errors="strict").strip() or None
            elif name == "evidencePcapSha256":
                evidence_pcap_sha256 = (part.get_payload(decode=True) or b"").decode("utf-8", errors="strict").strip().lower() or None
            elif name == "sourceFilename":
                value = (part.get_payload(decode=True) or b"").decode("utf-8", errors="strict")
                filename = _sanitize_upload_filename(value, filename)
        if pcap_bytes is None and not evidence_token:
            raise ValueError("Missing PCAP upload or retained Zeek evidence token")
        if not isinstance(profile, dict):
            raise ValueError("Missing or invalid multipart field 'profile'")
        if evidence_pcap_sha256 and (len(evidence_pcap_sha256) != 64 or any(ch not in "0123456789abcdef" for ch in evidence_pcap_sha256)):
            raise ValueError("Invalid retained-evidence PCAP SHA-256")
        return pcap_bytes, filename, profile, evidence_token, evidence_pcap_sha256

    def _multipart_file(self) -> tuple[bytes, str]:
        content_type = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in content_type:
            raise ValueError("PCAP context discovery requires multipart/form-data")
        length = _validated_content_length(self.headers, MAX_PCAP_UPLOAD_BYTES, "PCAP upload")
        raw = self.rfile.read(length)
        message = BytesParser(policy=default).parsebytes(
            f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("utf-8") + raw
        )
        for part in message.iter_parts():
            if part.get_param("name", header="content-disposition") == "file":
                return part.get_payload(decode=True) or b"", _sanitize_upload_filename(part.get_filename(), "capture.pcap")
        raise ValueError("Missing multipart field 'file'")

    def do_DELETE(self) -> None:  # noqa: N802
        discovery_prefix = f"{DISCOVERY_PATH}/"
        if self.path.startswith(discovery_prefix):
            job_id = self.path[len(discovery_prefix):].strip("/")
            if not _cancel_discovery_job(job_id):
                self._json(404, {"error": "job_not_found", "message": "Unknown context-discovery job."})
                return
            self._json(202, {"jobId": job_id, "status": "canceling"})
            return
        analysis_prefix = f"{PCAP_PATH}/"
        if self.path.startswith(analysis_prefix):
            job_id = self.path[len(analysis_prefix):].strip("/")
            if not _cancel_analysis_job(job_id):
                self._json(404, {"error": "job_not_found", "message": "Unknown PCAP-analysis job."})
                return
            self._json(202, {"jobId": job_id, "status": "canceling"})
            return
        self._json(404, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path == ANALYSIS_PATH:
            try:
                request = self._read_json()
            except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                self._json(400, {"error": "invalid_json", "message": str(exc)})
                return
            response = analyze_detection_request(request)
            status = 200 if response.get("status") in {"completed", "partial"} else 400
            self._json(status, response)
            return

        if self.path == DISCOVERY_PATH:
            try:
                pcap_bytes, filename = self._multipart_file()
                suffix = ".pcapng" if filename.lower().endswith(".pcapng") else ".pcap"
                with tempfile.NamedTemporaryFile(prefix="elevadr-discovery-", suffix=suffix, delete=False) as handle:
                    handle.write(pcap_bytes)
                    temp_path = Path(handle.name)
                job_id = uuid.uuid4().hex
                with _DISCOVERY_LOCK:
                    _DISCOVERY_JOBS[job_id] = {
                        "jobId": job_id,
                        "status": "queued",
                        "stage": "queued",
                        "progress": 0,
                        "message": "Context discovery queued.",
                        "detail": filename,
                        "elapsedSeconds": 0,
                        "createdAt": time.time(),
                        "updatedAt": time.time(),
                    }
                threading.Thread(target=_run_discovery_job, args=(job_id, temp_path, filename), daemon=True).start()
                self._json(202, {"jobId": job_id, "status": "queued", "statusUrl": f"{DISCOVERY_PATH}/{job_id}"})
            except (ValueError, json.JSONDecodeError) as exc:
                self._json(400, {"error": "invalid_request", "message": str(exc)})
            except Exception as exc:
                self._json(500, {"error": "context_discovery_failed", "message": f"{type(exc).__name__}: {exc}"})
            return

        if self.path == PCAP_PATH:
            try:
                pcap_bytes, filename, profile, evidence_token, evidence_pcap_sha256 = self._multipart()
                temp_path: Path | None = None
                if evidence_token:
                    snapshot = _evidence_snapshot(evidence_token)
                    if snapshot is None:
                        self._json(410, {"error": "evidence_expired", "message": "Retained Zeek evidence is unavailable. Re-open the PCAP to extract evidence again."})
                        return
                    filename = _sanitize_upload_filename(filename if filename != "capture.pcap" else str(snapshot.get("filename", filename)), filename)
                    try:
                        _acquire_evidence(
                            evidence_token,
                            expected_filename=filename,
                            expected_pcap_sha256=evidence_pcap_sha256,
                        )
                    except EvidenceExpired as exc:
                        self._json(410, {"error": "evidence_expired", "message": str(exc)})
                        return
                    except EvidenceBindingMismatch as exc:
                        self._json(409, {"error": "evidence_mismatch", "message": str(exc)})
                        return
                    except EvidenceRuntimeMismatch as exc:
                        self._json(409, {"error": "evidence_runtime_mismatch", "message": str(exc)})
                        return
                    else:
                        _release_evidence(evidence_token)
                else:
                    assert pcap_bytes is not None
                    suffix = ".pcapng" if filename.lower().endswith(".pcapng") else ".pcap"
                    with tempfile.NamedTemporaryFile(prefix="elevadr-upload-", suffix=suffix, delete=False) as handle:
                        handle.write(pcap_bytes)
                        temp_path = Path(handle.name)
                job_id = uuid.uuid4().hex
                with _ANALYSIS_LOCK:
                    _ANALYSIS_JOBS[job_id] = {
                        "jobId": job_id,
                        "status": "queued",
                        "stage": "queued",
                        "progress": 0,
                        "message": "Analysis queued using retained Zeek evidence." if evidence_token else "PCAP analysis queued.",
                        "detail": filename,
                        "elapsedSeconds": 0,
                        "createdAt": time.time(),
                        "updatedAt": time.time(),
                    }
                threading.Thread(
                    target=_run_analysis_job,
                    args=(job_id, temp_path, filename, profile, evidence_token, evidence_pcap_sha256),
                    daemon=True,
                ).start()
                self._json(202, {"jobId": job_id, "status": "queued", "statusUrl": f"{PCAP_PATH}/{job_id}", "zeekEvidenceReused": bool(evidence_token)})
            except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                self._json(400, {"error": "invalid_request", "message": str(exc)})
            except Exception as exc:
                self._json(500, {"error": "pcap_analysis_failed", "message": f"{type(exc).__name__}: {exc}"})
            return

        self._json(404, {"error": "not_found"})

    def log_message(self, format: str, *args: object) -> None:
        return


def main() -> int:
    parser = argparse.ArgumentParser(description="Run isolated eleVADR analysis reference server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    try:
        _context_type, modules, module_file = ensure_detector_package()
    except ImportError as exc:
        print(f"ERROR: detector package startup check failed: {exc}")
        return 2
    print(f"Detector package: {module_file}")
    print(f"Detector modules: {len(modules)}")
    from backend_bryan.runtime.zeek_runtime import describe_zeek_runtime
    print(f"Zeek runtime: {describe_zeek_runtime()}")
    _cleanup_restart_orphans()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"Analysis API: http://{args.host}:{args.port}{ANALYSIS_PATH}")
    print(f"PCAP API:     http://{args.host}:{args.port}{PCAP_PATH}")
    print(f"Context API:  http://{args.host}:{args.port}{DISCOVERY_PATH}")
    print("Context discovery progress: job polling enabled")
    print("PCAP analysis progress:     job polling enabled")
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
