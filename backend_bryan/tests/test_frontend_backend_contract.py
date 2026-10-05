from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import unittest

from backend_bryan.integration.analysis_request import (
    CONTRACT_VERSION,
    compile_analysis_request,
    validate_analysis_request,
)

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "backend_bryan" / "reference" / "contract_profiles"
FRONTEND_RUNNER = ROOT / "backend_bryan" / "integration" / "build_frontend_analysis_request.cjs"


def build_frontend_request(profile_path: Path) -> dict:
    env = dict(os.environ)
    # The validation environment has TypeScript installed globally. Normal frontend
    # checkouts resolve it locally and do not need this fallback.
    env.setdefault("NODE_PATH", "/opt/nvm/versions/node/v22.16.0/lib/node_modules")
    completed = subprocess.run(
        ["node", str(FRONTEND_RUNNER), str(profile_path)],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )
    return json.loads(completed.stdout)


class FrontendBackendContractTests(unittest.TestCase):
    def test_all_reference_profiles_cross_one_raw_profile_boundary(self) -> None:
        fixtures = sorted(FIXTURES.glob("*.json"))
        self.assertGreaterEqual(len(fixtures), 9)
        for fixture in fixtures:
            with self.subTest(profile=fixture.name):
                request = build_frontend_request(fixture)
                profile = validate_analysis_request(request)
                self.assertEqual(request["contractVersion"], CONTRACT_VERSION)
                self.assertEqual(profile["schemaVersion"], 3)
                # Detector metadata belongs to backend output, not the frontend envelope.
                for backend_key in (
                    "asset_inventory",
                    "ics_write_policy",
                    "s7comm_control_policy",
                    "enip_cip_policy",
                    "ot_dns_policy",
                    "ipv6_ot_policy",
                ):
                    self.assertNotIn(backend_key, request)
                # Every valid request must remain compilable by the single backend adapter.
                metadata = compile_analysis_request(request)
                self.assertIsInstance(metadata.get("segments"), list)
                self.assertIsInstance(metadata.get("asset_inventory"), list)

    def test_observed_only_fixture_remains_non_authorizing_end_to_end(self) -> None:
        request = build_frontend_request(FIXTURES / "observed_only_no_authorization.json")
        metadata = compile_analysis_request(request)
        self.assertNotIn("ics_write_policy", metadata)
        self.assertNotIn("s7comm_control_policy", metadata)
        self.assertNotIn("enip_cip_policy", metadata)
        self.assertNotIn("control_system_enterprise_policy", metadata)
        self.assertTrue(metadata["detection_context_observations"]["communications"])


if __name__ == "__main__":
    unittest.main()
