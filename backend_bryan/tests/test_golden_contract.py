from __future__ import annotations

import json
from pathlib import Path
import unittest

from backend_bryan.integration.analysis_service import analyze_detection_request

ROOT = Path(__file__).resolve().parents[1] / "reference" / "golden"


def load(name: str) -> dict:
    return json.loads((ROOT / name).read_text(encoding="utf-8"))


class GoldenContractTests(unittest.TestCase):
    def test_completed_golden_contract(self) -> None:
        self.assertEqual(
            analyze_detection_request(load("completed_request.json")),
            load("completed_response.json"),
        )

    def test_partial_golden_contract(self) -> None:
        self.assertEqual(
            analyze_detection_request(load("partial_request.json")),
            load("partial_response.json"),
        )

    def test_invalid_golden_contract(self) -> None:
        self.assertEqual(
            analyze_detection_request(load("invalid_request.json")),
            load("invalid_response.json"),
        )


if __name__ == "__main__":
    unittest.main()
