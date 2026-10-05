from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend_bryan.integration.context_discovery import discover_context_from_pcap
from backend_bryan.integration.detector_runtime import ensure_detector_package


class ContextDiscoveryTests(unittest.TestCase):
    def test_observed_facts_are_discovered_without_policy_authorization(self) -> None:
        AnalysisContext, _modules, _module_file = ensure_detector_package()
        context = AnalysisContext(
            connections=[{"source_ip": "10.1.1.10", "destination_ip": "10.1.1.20", "destination_port": 502, "protocol": "tcp", "service": "modbus"}],
            modbus=[{"source_ip": "10.1.1.10", "destination_ip": "10.1.1.20", "destination_port": 502}],
            dns=[{"source_ip": "10.1.1.10", "destination_ip": "10.1.1.53"}],
        )
        with tempfile.TemporaryDirectory() as tmp:
            pcap = Path(tmp) / "sample.pcap"
            pcap.write_bytes(b"pcap")
            zeek_dir = Path(tmp) / "zeek"
            zeek_dir.mkdir()
            (zeek_dir / "conn.log").write_text("# fake")
            with patch("backend_bryan.runtime.zeek_runtime.run_zeek_on_pcap", return_value=(context, zeek_dir)):
                result = discover_context_from_pcap(pcap, source_filename="sample.pcap")

        self.assertGreaterEqual(len(result["assets"]), 3)
        self.assertTrue(any(asset["ip"] == "10.1.1.20" and asset["role"] == "OT" for asset in result["assets"]))
        self.assertTrue(any(segment["role"] == "ot" for segment in result["segments"]))
        self.assertTrue(any(item["kind"] == "dns" and item["value"] == "10.1.1.53" for item in result["infrastructure"]))
        self.assertTrue(result["pairs"])
        # Discovery is observations only. No policy/authorization fields are returned.
        for forbidden in ("allowedHosts", "allowedSegmentPairs", "approvedExternalDestinations", "authorizedControlActions", "modulePolicies"):
            self.assertNotIn(forbidden, result)


if __name__ == "__main__":
    unittest.main()
