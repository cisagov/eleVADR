from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest

from backend_bryan.integration.api_contract import (
    REQUEST_CONTRACT_VERSION,
    RESPONSE_CONTRACT_VERSION,
    RequestValidationError,
    error_response,
    validate_api_request,
)

ROOT = Path(__file__).resolve().parents[1]


def request_fixture() -> dict:
    return json.loads((ROOT / "examples" / "analysis_request.json").read_text(encoding="utf-8"))


class ApiContractTests(unittest.TestCase):
    def test_profile_and_logs_are_separate(self) -> None:
        request = request_fixture()
        request["logs"] = {
            "conn": [{"id.orig_h": "10.0.0.10", "id.resp_h": "10.0.0.20"}],
            "s7comm": [{"uid": "abc"}],
        }
        profile, logs = validate_api_request(request)
        self.assertEqual(profile["schemaVersion"], 3)
        self.assertIn("connections", logs)
        self.assertIn("s7comm", logs)
        self.assertNotIn("logs", profile)

    def test_rejects_unsupported_log_name(self) -> None:
        request = request_fixture()
        request["logs"] = {"made_up_log": []}
        with self.assertRaises(RequestValidationError) as raised:
            validate_api_request(request)
        self.assertEqual(raised.exception.errors[0].code, "unsupported_log")

    def test_rejects_non_object_log_rows(self) -> None:
        request = request_fixture()
        request["logs"] = {"dns": ["not-an-object"]}
        with self.assertRaises(RequestValidationError):
            validate_api_request(request)

    def test_rejects_unknown_request_contract(self) -> None:
        request = request_fixture()
        request["contractVersion"] = "future-version"
        with self.assertRaises(RequestValidationError) as raised:
            validate_api_request(request)
        self.assertEqual(raised.exception.errors[0].code, "unsupported_contract_version")

    def test_failed_response_contract_is_stable(self) -> None:
        response = error_response([])
        self.assertEqual(response["contractVersion"], RESPONSE_CONTRACT_VERSION)
        self.assertEqual(response["status"], "failed")
        self.assertEqual(response["moduleResults"], [])

    def test_request_constant_matches_fixture(self) -> None:
        self.assertEqual(request_fixture()["contractVersion"], REQUEST_CONTRACT_VERSION)


if __name__ == "__main__":
    unittest.main()
