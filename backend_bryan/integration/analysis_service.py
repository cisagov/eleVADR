"""Transport-neutral reference analysis service for backend handoff."""
from __future__ import annotations

from typing import Any, Mapping

from backend_bryan.adapters.detection_context_adapter import compile_detection_context_metadata
from backend_bryan.integration.detector_runtime import ensure_detector_package
from backend_bryan.integration.finding_provenance import attach_finding_provenance
from backend_bryan.integration.finding_calibration import calibrate_module_result
from backend_bryan.integration.api_contract import (
    ContractError,
    RESPONSE_CONTRACT_VERSION,
    RequestValidationError,
    error_response,
    validate_api_request,
)


def _serialize_module_result(result: Any) -> dict[str, Any]:
    if hasattr(result, "to_dict"):
        value = result.to_dict()
        if isinstance(value, dict):
            return value
    if isinstance(result, Mapping):
        return dict(result)
    raise TypeError(f"Unsupported module result type: {type(result).__name__}")


def analyze_detection_request(request: Any) -> dict[str, Any]:
    """Validate, compile, execute selected modules, and return contract JSON.

    Per-module exceptions are isolated and returned as structured errors so one
    detector failure does not erase successful findings from other detectors.
    """
    try:
        profile, logs = validate_api_request(request)
    except RequestValidationError as exc:
        return error_response(exc.errors)

    try:
        AnalysisContext, MODULES, _module_file = ensure_detector_package()
    except ImportError as exc:
        return error_response(
            [ContractError("detector_package_unavailable", str(exc))]
        )

    metadata = compile_detection_context_metadata(profile)
    context = AnalysisContext(metadata=metadata, **logs)

    requested = profile.get("selectedModules", [])
    if not isinstance(requested, list):
        return error_response(
            [ContractError("invalid_profile", "selectedModules must be an array", "profile.selectedModules")]
        )

    results: list[dict[str, Any]] = []
    errors: list[ContractError] = []
    finding_count = 0

    for raw_module_id in requested:
        module_id = str(raw_module_id)
        module = MODULES.get(module_id)
        if module is None:
            errors.append(
                ContractError(
                    "unknown_module",
                    f"Unknown detector module: {module_id}",
                    "profile.selectedModules",
                    module_id,
                )
            )
            continue
        try:
            result = module.analyze(context)
            calibrate_module_result(module, result)
            attach_finding_provenance(module, result, context)
            serialized = _serialize_module_result(result)
            results.append(serialized)
            findings = serialized.get("findings", [])
            if isinstance(findings, list):
                finding_count += len(findings)
        except Exception as exc:  # reference boundary intentionally isolates detector failures
            errors.append(
                ContractError(
                    "module_execution_failed",
                    f"{type(exc).__name__}: {exc}",
                    module_id=module_id,
                )
            )

    completed = len(results)
    failed = len(errors)
    if failed == 0:
        status = "completed"
    elif completed > 0:
        status = "partial"
    else:
        status = "failed"

    return {
        "contractVersion": RESPONSE_CONTRACT_VERSION,
        "status": status,
        "summary": {
            "requestedModules": len(requested),
            "completedModules": completed,
            "failedModules": failed,
            "findingCount": finding_count,
        },
        "moduleResults": results,
        "errors": [error.to_dict() for error in errors],
    }
