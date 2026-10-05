from __future__ import annotations

import json
from pathlib import Path
import unittest

from backend_bryan.integration.analysis_service import analyze_detection_request

ROOT = Path(__file__).resolve().parents[1] / "reference" / "e2e"


def load(name: str) -> dict:
    return json.loads((ROOT / name).read_text(encoding="utf-8"))


class RealDataEndToEndTests(unittest.TestCase):
    def test_known_zeek_connection_produces_expected_rogue_device_finding(self) -> None:
        response = analyze_detection_request(load("rogue_finding_request.json"))
        self.assertEqual(response["status"], "completed")
        self.assertEqual(response["summary"]["completedModules"], 1)
        self.assertEqual(response["summary"]["findingCount"], 1)
        result = response["moduleResults"][0]
        self.assertEqual(result["module_id"], "unknown_rogue_devices")
        self.assertEqual(len(result["findings"]), 1)
        finding = result["findings"][0]
        self.assertEqual(finding["metadata"]["identifier"], "10.0.0.99")
        self.assertIn("10.0.0.99", finding["devices"])

    def test_detection_context_inventory_suppresses_expected_rogue_finding(self) -> None:
        response = analyze_detection_request(load("rogue_suppressed_request.json"))
        self.assertEqual(response["status"], "completed")
        self.assertEqual(response["summary"]["findingCount"], 0)
        self.assertEqual(response["moduleResults"][0]["findings"], [])


if __name__ == "__main__":
    unittest.main()
