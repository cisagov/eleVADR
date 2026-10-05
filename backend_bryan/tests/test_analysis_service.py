from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from backend_bryan.integration.analysis_service import analyze_detection_request
from backend_bryan.integration.api_contract import RESPONSE_CONTRACT_VERSION

ROOT = Path(__file__).resolve().parents[1]


def request_fixture() -> dict:
    return json.loads((ROOT / "examples" / "analysis_request.json").read_text(encoding="utf-8"))


class AnalysisServiceTests(unittest.TestCase):
    def test_invalid_request_returns_structured_failed_response(self) -> None:
        response = analyze_detection_request({"contractVersion": "wrong", "profile": {}})
        self.assertEqual(response["contractVersion"], RESPONSE_CONTRACT_VERSION)
        self.assertEqual(response["status"], "failed")
        self.assertTrue(response["errors"])

    def test_known_modules_return_completed_contract(self) -> None:
        request = request_fixture()
        request["profile"]["selectedModules"] = [
            "public_to_public_traffic",
            "unknown_rogue_devices",
        ]
        response = analyze_detection_request(request)
        self.assertEqual(response["status"], "completed")
        self.assertEqual(response["summary"]["requestedModules"], 2)
        self.assertEqual(response["summary"]["completedModules"], 2)
        self.assertEqual(response["summary"]["failedModules"], 0)
        self.assertEqual(len(response["moduleResults"]), 2)

    def test_unknown_module_produces_partial_response(self) -> None:
        request = request_fixture()
        request["profile"]["selectedModules"] = [
            "public_to_public_traffic",
            "not_a_real_module",
        ]
        response = analyze_detection_request(request)
        self.assertEqual(response["status"], "partial")
        self.assertEqual(response["summary"]["completedModules"], 1)
        self.assertEqual(response["summary"]["failedModules"], 1)
        self.assertEqual(response["errors"][0]["code"], "unknown_module")
        self.assertEqual(response["errors"][0]["moduleId"], "not_a_real_module")

    def test_logs_are_analysis_data_not_authorization(self) -> None:
        request = request_fixture()
        request["profile"]["selectedModules"] = ["s7comm_unauthorized_write_stop"]
        request["profile"]["authorizedControlActions"] = []
        request["logs"] = {
            "s7comm": [{"id.orig_h": "10.0.0.10", "id.resp_h": "10.0.0.20", "function": "write"}]
        }
        response = analyze_detection_request(request)
        self.assertEqual(response["status"], "completed")
        # The service may detect the activity, but the request logs cannot create an
        # authorization policy. That invariant is tested at the compiler boundary too.
        self.assertEqual(response["summary"]["completedModules"], 1)


if __name__ == "__main__":
    unittest.main()
