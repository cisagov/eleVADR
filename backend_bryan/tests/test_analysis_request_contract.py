from __future__ import annotations

import json
from pathlib import Path
import unittest

from backend_bryan.adapters.detection_context_adapter import compile_detection_context_metadata
from backend_bryan.integration.analysis_request import (
    CONTRACT_VERSION,
    compile_analysis_request,
    validate_analysis_request,
)

ROOT = Path(__file__).resolve().parents[1]


def example_request() -> dict:
    return json.loads((ROOT / "examples" / "analysis_request.json").read_text(encoding="utf-8"))


class AnalysisRequestContractTests(unittest.TestCase):
    def test_accepts_one_versioned_v3_profile_request(self) -> None:
        request = example_request()
        profile = validate_analysis_request(request)
        self.assertEqual(request["contractVersion"], CONTRACT_VERSION)
        self.assertEqual(profile["schemaVersion"], 3)
        self.assertEqual(len(profile["selectedModules"]), 75)

    def test_rejects_unknown_contract_version(self) -> None:
        request = example_request()
        request["contractVersion"] = "elevadr.detection-context.analysis.v999"
        with self.assertRaises(ValueError):
            validate_analysis_request(request)

    def test_backend_compiler_is_authoritative_for_request(self) -> None:
        request = example_request()
        self.assertEqual(
            compile_analysis_request(request),
            compile_detection_context_metadata(request["profile"]),
        )

    def test_observed_communications_do_not_become_authorization(self) -> None:
        request = example_request()
        request["profile"]["authorizedControlActions"] = []
        metadata = compile_analysis_request(request)
        self.assertNotIn("ics_write_policy", metadata)
        self.assertNotIn("s7comm_control_policy", metadata)
        self.assertNotIn("enip_cip_policy", metadata)
        self.assertGreater(len(metadata["detection_context_observations"]["communications"]), 0)

    def test_request_envelope_rejects_backend_policy_at_request_root(self) -> None:
        request = {"contractVersion": CONTRACT_VERSION, "profile": {"schemaVersion": 3}}
        request["ics_write_policy"] = {"allowed_paths": []}
        with self.assertRaises(ValueError):
            validate_analysis_request(request)


if __name__ == "__main__":
    unittest.main()
