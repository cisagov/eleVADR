"""Reference PCAP -> Zeek evidence -> detectors -> canonical eleVADR JSON pipeline.

The preferred interactive workflow extracts Zeek evidence once during Detection
Context discovery, retains that evidence, and later reuses it for detector
analysis after the user reviews/edits policy. ``analyze_pcap_to_report`` remains
as a compatibility/direct-analysis path for regression runners and callers that
do not have retained Zeek evidence.
"""
from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import Any, Callable, Mapping

from backend_bryan.adapters.detection_context_adapter import compile_detection_context_metadata, validate_profile_v3
from backend_bryan.integration.detector_runtime import ensure_detector_package
from backend_bryan.integration.finding_provenance import attach_finding_provenance
from backend_bryan.integration.finding_calibration import calibrate_module_result
from backend_bryan.integration.report_builder import build_elevadr_report

ProgressCallback = Callable[[str, int | None, str, str | None], None]


def _emit(progress: ProgressCallback | None, stage: str, value: int | None, message: str, detail: str | None = None) -> None:
    if progress is not None:
        progress(stage, value, message, detail)


def _zeek_log_types(zeek_path: Path) -> dict[str, int]:
    log_types: dict[str, int] = {}
    for child in zeek_path.iterdir():
        if child.is_file() and (child.name.endswith(".log") or child.name.endswith(".json")):
            name = child.name.split(".", 1)[0]
            log_types[name] = log_types.get(name, 0) + 1
    return log_types


def _analyze_loaded_zeek_context(
    context: Any,
    zeek_path: Path,
    profile: Mapping[str, Any],
    *,
    source_filename: str,
    progress: ProgressCallback | None,
    evidence_reused: bool,
    evidence_metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    _emit(progress, "compiling-context", 85, "Applying Detection Context policy…", str(profile.get("name", "")) or None)
    context.metadata = compile_detection_context_metadata(profile)

    _context_type, MODULES, _module_file = ensure_detector_package()
    requested = profile.get("selectedModules", [])
    requested_ids = [str(value) for value in requested] if isinstance(requested, list) else []
    module_results: list[dict[str, Any]] = []
    module_errors: list[dict[str, Any]] = []
    total = len(requested_ids)
    if total == 0:
        _emit(progress, "detectors", 96, "No detector modules were selected.", None)
    for index, module_id in enumerate(requested_ids, start=1):
        detector_progress = 86 + int((10 * (index - 1)) / max(total, 1))
        _emit(progress, "detectors", detector_progress, f"Running detector modules {index}/{total}…", module_id)
        module = MODULES.get(module_id)
        if module is None:
            module_errors.append({"code": "unknown_module", "moduleId": module_id, "message": f"Unknown detector module: {module_id}"})
            continue
        try:
            result = module.analyze(context)
            calibrate_module_result(module, result)
            attach_finding_provenance(module, result, context)
            serialized = result.to_dict() if hasattr(result, "to_dict") else dict(result)
            module_results.append(serialized)
        except Exception as exc:
            module_errors.append({"code": "module_execution_failed", "moduleId": module_id, "message": f"{type(exc).__name__}: {exc}"})
    if total:
        _emit(progress, "detectors", 96, f"Detector analysis complete: {len(module_results)}/{total} modules completed.", f"{len(module_errors)} module error(s)")

    _emit(progress, "building-report", 98, "Building eleVADR JSON report…", None)
    from backend_bryan.runtime.zeek_runtime import describe_zeek_runtime

    report = build_elevadr_report(
        source_filename=source_filename,
        profile=profile,
        context=context,
        module_results=module_results,
        module_errors=module_errors,
        zeek_log_types=_zeek_log_types(zeek_path),
        zeek_runtime=describe_zeek_runtime(),
        detector_modules_requested=total,
    )
    provenance = report.setdefault("arch_insights", {}).setdefault("analysis_provenance", {})
    provenance["zeek_evidence_reused"] = evidence_reused
    if evidence_metadata:
        for key in ("pcap_sha256", "zeek_policy_sha256", "zeek_evidence_created_at", "zeek_evidence_id"):
            value = evidence_metadata.get(key)
            if value not in (None, ""):
                provenance[key] = value
    _emit(progress, "report-ready", 99, "eleVADR JSON report is ready.", report.get("report_id"))
    return report


def analyze_zeek_evidence_to_report(
    evidence_dir: str | Path,
    profile: Mapping[str, Any],
    *,
    source_filename: str,
    progress: ProgressCallback | None = None,
    evidence_metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Analyze previously extracted Zeek logs without running Zeek again."""
    _emit(progress, "validating-context", 1, "Validating Detection Context…", str(profile.get("name", "")) or None)
    validate_profile_v3(profile)
    ensure_detector_package()
    from elevadr_modules.zeek.parser import load_zeek_directory

    zeek_path = Path(evidence_dir).resolve()
    if not zeek_path.exists() or not zeek_path.is_dir():
        raise FileNotFoundError(f"Retained Zeek evidence is unavailable: {zeek_path}")
    _emit(progress, "reusing-zeek-evidence", 82, "Reusing previously extracted Zeek evidence…", source_filename)
    context = load_zeek_directory(zeek_path)
    return _analyze_loaded_zeek_context(
        context,
        zeek_path,
        profile,
        source_filename=source_filename,
        progress=progress,
        evidence_reused=True,
        evidence_metadata=evidence_metadata,
    )


def analyze_pcap_to_report(
    pcap_path: str | Path,
    profile: Mapping[str, Any],
    *,
    source_filename: str | None = None,
    progress: ProgressCallback | None = None,
) -> dict[str, Any]:
    """Direct/compatibility path that performs a fresh Zeek extraction."""
    _emit(progress, "validating-context", 1, "Validating Detection Context…", str(profile.get("name", "")) or None)
    validate_profile_v3(profile)
    ensure_detector_package()
    from backend_bryan.runtime.zeek_runtime import run_zeek_on_pcap

    output_dir = Path(tempfile.mkdtemp(prefix="elevadr-zeek-analysis-"))
    try:
        context, zeek_path = run_zeek_on_pcap(pcap_path, output_dir=output_dir, progress=progress)
        return _analyze_loaded_zeek_context(
            context,
            zeek_path,
            profile,
            source_filename=source_filename or Path(pcap_path).name,
            progress=progress,
            evidence_reused=False,
        )
    finally:
        shutil.rmtree(output_dir, ignore_errors=True)
