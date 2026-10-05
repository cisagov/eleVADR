"""Compatibility helpers around the authoritative analysis API contract.

New integrations should call ``analysis_service.analyze_detection_request``.
These helpers remain useful for backend unit tests and direct AnalysisContext
construction without an HTTP transport.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from backend_bryan.adapters.detection_context_adapter import compile_detection_context_metadata
from backend_bryan.integration.api_contract import (
    REQUEST_CONTRACT_VERSION as CONTRACT_VERSION,
    validate_api_request,
)


def validate_analysis_request(request: Mapping[str, Any]) -> Mapping[str, Any]:
    profile, _logs = validate_api_request(request)
    return profile


def compile_analysis_request(request: Mapping[str, Any]) -> dict[str, Any]:
    profile, _logs = validate_api_request(request)
    return compile_detection_context_metadata(profile)


def build_analysis_context(request: Mapping[str, Any], **logs: list[dict[str, Any]]):
    """Construct AnalysisContext using request logs plus explicit test overrides."""
    from elevadr_modules.models import AnalysisContext

    profile, request_logs = validate_api_request(request)
    merged_logs = {**request_logs, **logs}
    return AnalysisContext(
        metadata=compile_detection_context_metadata(profile),
        **merged_logs,
    )


def run_selected_modules(request: Mapping[str, Any], **logs: list[dict[str, Any]]):
    from elevadr_modules.registry import MODULES

    profile = validate_analysis_request(request)
    context = build_analysis_context(request, **logs)
    module_ids = profile.get("selectedModules", [])
    if not isinstance(module_ids, list):
        raise TypeError("profile.selectedModules must be an array")
    return {module_id: MODULES[module_id].analyze(context) for module_id in module_ids}
