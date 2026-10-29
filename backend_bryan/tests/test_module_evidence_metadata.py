"""Wave 9 Step 2: evidence metadata must match the detector registry."""
from __future__ import annotations

import json
from pathlib import Path

from backend_bryan.integration.module_evidence_metadata import load_module_evidence_metadata

ROOT = Path(__file__).resolve().parents[2]


def test_module_evidence_metadata_complete_and_in_sync():
    from elevadr_modules.registry import MODULES
    data = load_module_evidence_metadata()
    assert set(data) == set(MODULES)
    frontend = json.loads((ROOT / "frontend/src/app/components/DetectionConfiguration/moduleEvidenceMetadata.json").read_text(encoding="utf-8"))
    assert data == frontend
    for module_id, item in data.items():
        assert item["implementationId"] == module_id
        assert item["logSourceTier"].strip()
        assert isinstance(item["declaredLogs"], list)
        assert item["capturePrerequisites"].strip()
        assert item["evidenceLimitations"].strip()
        assert item["verificationNote"].strip()
        assert "runtimeEvidenceStatus" not in item
