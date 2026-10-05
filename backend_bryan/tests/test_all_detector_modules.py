"""Optional contract test against the standalone detector package.

Run with the detector package installed or available on PYTHONPATH.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
import unittest

from backend_bryan.integration.analysis_request import build_analysis_context, validate_analysis_request

ROOT = Path(__file__).resolve().parents[1]

try:
    from elevadr_modules.registry import MODULES
except ImportError:  # pragma: no cover - expected when detector package is not present
    MODULES = None  # type: ignore[assignment]


@unittest.skipIf(MODULES is None, "standalone elevadr_modules package is not on PYTHONPATH")
class AllDetectorContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.request = json.loads((ROOT / "examples" / "analysis_request.json").read_text(encoding="utf-8"))
        self.profile = validate_analysis_request(self.request)

    def test_registry_contains_exactly_75_modules(self) -> None:
        self.assertEqual(len(MODULES), 75)
        self.assertEqual(len(set(MODULES)), 75)
        self.assertEqual(len(self.profile["selectedModules"]), 75)

    def test_frontend_catalog_matches_backend_registry(self) -> None:
        catalog = ROOT.parent / "frontend" / "src" / "app" / "components" / "DetectionConfiguration" / "moduleCatalog.ts"
        module_ids = set(re.findall(r'^\s*"([a-z0-9_]+)",?$', catalog.read_text(encoding="utf-8"), re.MULTILINE))
        self.assertEqual(module_ids, set(MODULES))

    def test_all_75_modules_accept_simplified_request_path(self) -> None:
        failures: list[str] = []
        context = build_analysis_context(self.request)
        for module_id in self.profile["selectedModules"]:
            module = MODULES[module_id]
            try:
                result = module.analyze(context)
                self.assertEqual(result.module_id, module_id)
            except Exception as exc:  # collect all contract failures in one run
                failures.append(f"{module_id}: {type(exc).__name__}: {exc}")
        self.assertFalse(failures, "Detector contract failures:\n" + "\n".join(failures))


if __name__ == "__main__":
    unittest.main()
