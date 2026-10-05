from __future__ import annotations

"""Regression guard for the single authoritative Detection Context compiler.

Older prototypes duplicated detector-metadata compilation in TypeScript and then
compared that output byte-for-byte with the Python adapter.  That architecture
was intentionally removed: the frontend now sends one normalized raw v3 profile
and ``backend_bryan.adapters.detection_context_adapter`` is the sole owner of
profile -> AnalysisContext.metadata compilation.

These tests keep the useful parity guarantee without reintroducing a second
policy compiler into the frontend.
"""

import json
import os
from pathlib import Path
import subprocess
import unittest

from backend_bryan.adapters.detection_context_adapter import compile_detection_context_metadata
from backend_bryan.integration.analysis_request import compile_analysis_request

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "backend_bryan" / "reference" / "contract_profiles"
FRONTEND_RUNNER = ROOT / "backend_bryan" / "integration" / "build_frontend_analysis_request.cjs"


def _frontend_node_env() -> dict[str, str]:
    env = dict(os.environ)
    frontend_modules = ROOT / "frontend" / "node_modules"
    existing = env.get("NODE_PATH", "")
    if frontend_modules.exists():
        env["NODE_PATH"] = str(frontend_modules) + (os.pathsep + existing if existing else "")
    else:
        # CI/container fallback used by the project validation environment.
        env.setdefault("NODE_PATH", "/opt/nvm/versions/node/v22.16.0/lib/node_modules")
    return env


def build_frontend_request(profile_path: Path) -> dict:
    completed = subprocess.run(
        ["node", str(FRONTEND_RUNNER), str(profile_path)],
        check=True,
        capture_output=True,
        text=True,
        env=_frontend_node_env(),
    )
    return json.loads(completed.stdout)


class AdapterParityTests(unittest.TestCase):
    def test_all_reference_profiles_use_one_authoritative_backend_compiler(self) -> None:
        fixtures = sorted(FIXTURES.glob("*.json"))
        self.assertGreaterEqual(len(fixtures), 9)
        for fixture in fixtures:
            with self.subTest(profile=fixture.name):
                raw_profile = json.loads(fixture.read_text(encoding="utf-8"))
                request = build_frontend_request(fixture)

                # The frontend boundary is the raw normalized profile, not a
                # detector-policy metadata object.
                self.assertEqual(request["contractVersion"], "elevadr.detection-context.analysis.v1")
                self.assertEqual(request["profile"]["schemaVersion"], 3)
                self.assertNotIn("asset_inventory", request)
                self.assertNotIn("ics_write_policy", request)
                self.assertNotIn("public_to_public_policy", request)

                # Once the frontend request crosses the boundary, metadata must
                # be exactly what the authoritative Python adapter produces from
                # that same normalized profile.
                from_request = compile_analysis_request(request)
                from_profile = compile_detection_context_metadata(request["profile"])
                self.assertEqual(from_request, from_profile)

                # Sanity check that normalization did not change the profile ID.
                self.assertEqual(request["profile"].get("id"), raw_profile.get("id"))


if __name__ == "__main__":
    unittest.main()
