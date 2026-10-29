"""Descriptive evidence prerequisites, separate from detector execution readiness."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

METADATA_PATH = Path(__file__).resolve().parents[1] / "reference" / "module_evidence_metadata.json"


def load_module_evidence_metadata() -> dict[str, dict[str, Any]]:
    """Return a fresh read-only-by-convention metadata mapping."""
    result = json.loads(METADATA_PATH.read_text(encoding="utf-8"))
    if len(result) != 75:
        raise ValueError("Expected evidence metadata for exactly 75 modules")
    return result
