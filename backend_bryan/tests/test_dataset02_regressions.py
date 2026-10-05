from __future__ import annotations

import unittest

from backend_bryan.adapters.detection_context_adapter import compile_detection_context_metadata
from backend_bryan.vendor.elevadr_modules.models import AnalysisContext
from backend_bryan.vendor.elevadr_modules.modules.unknown_rogue_devices import UnknownRogueDevicesModule


class Dataset02RegressionTests(unittest.TestCase):
    def test_zeek_only_host_remains_unknown_to_inventory_detector(self) -> None:
        profile = {
            "schemaVersion": 3,
            "id": "dataset02-regression",
            "name": "Dataset 02 regression",
            "segments": [
                {"id": "it", "name": "Engineering Network", "cidr": "10.30.0.0/24", "role": "it"},
                {"id": "ot", "name": "Legacy OT Services", "cidr": "10.40.0.0/24", "role": "ot"},
            ],
            "assets": [
                {
                    "id": "known-eng", "ip": "10.30.0.50", "hostname": "legacy-eng-ws",
                    "assetType": "engineering workstation", "role": "engineering",
                    "macAddresses": [], "services": [], "ports": [], "source": "imported",
                },
                {
                    "id": "observed-rogue", "ip": "10.30.0.99", "hostname": "",
                    "assetType": "Observed host", "role": "Unknown",
                    "macAddresses": [], "services": [], "ports": [], "source": "zeek",
                    "confidence": "low", "observedCount": 8,
                },
                {
                    "id": "known-rdp", "ip": "10.40.0.15", "hostname": "legacy-rdp",
                    "assetType": "remote access server", "role": "ot support",
                    "macAddresses": [], "services": ["rdp"], "ports": [3389], "source": "imported",
                },
            ],
            "infrastructure": [], "communicationPairs": [], "allowedHosts": [],
            "allowedSegmentPairs": [], "approvedExternalDestinations": [],
            "authorizedControlActions": [], "modulePolicies": {},
        }
        metadata = compile_detection_context_metadata(profile)
        context = AnalysisContext(
            connections=[
                {
                    "id.orig_h": "10.30.0.99", "id.orig_p": 43000,
                    "id.resp_h": "10.40.0.15", "id.resp_p": 3389,
                    "proto": "tcp", "conn_state": "REJ", "local_orig": "T", "local_resp": "T",
                }
            ],
            metadata=metadata,
        )
        result = UnknownRogueDevicesModule().analyze(context)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].metadata["identifier"], "10.30.0.99")
        self.assertEqual(result.metrics["inventory_ip_addresses"], 2)


if __name__ == "__main__":
    unittest.main()
