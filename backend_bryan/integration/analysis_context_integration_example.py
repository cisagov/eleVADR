"""Example only: simplified future backend integration.

Nothing in production imports this file. The intended runtime boundary is now:
frontend Detection Context request -> backend authoritative compiler -> AnalysisContext.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from backend_bryan.integration.analysis_request import (
    build_analysis_context,
    run_selected_modules,
)


def load_analysis_request(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def build_context_from_request_file(path: str | Path, **logs: list[dict[str, Any]]):
    return build_analysis_context(load_analysis_request(path), **logs)


def run_request_file(path: str | Path, **logs: list[dict[str, Any]]):
    return run_selected_modules(load_analysis_request(path), **logs)
