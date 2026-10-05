from __future__ import annotations

import json
from pathlib import Path
import unittest

from backend_bryan.adapters.detection_context_adapter import (
    compile_detection_context_metadata,
    validate_profile_v3,
)

ROOT = Path(__file__).resolve().parents[1]


def example_profile() -> dict:
    return json.loads((ROOT / "examples" / "input_profile.json").read_text(encoding="utf-8"))


class DetectionContextAdapterTests(unittest.TestCase):
    def test_requires_schema_v3(self) -> None:
        profile = example_profile()
        profile["schemaVersion"] = 2
        with self.assertRaises(ValueError):
            validate_profile_v3(profile)

    def test_shared_aliases_compile_to_detector_shape(self) -> None:
        metadata = compile_detection_context_metadata(example_profile())
        segment = metadata["segments"][0]
        self.assertEqual(segment["purdue_level"], "Level 2")
        self.assertEqual(segment["vlan_id"], 120)
        self.assertFalse(segment["dhcp_allowed"])
        self.assertTrue(segment["ipv4_only"])

        asset = metadata["asset_inventory"][0]
        self.assertEqual(asset["asset_type"], "PLC")
        self.assertIn("00:11:22:33:44:55", asset["macs"])

    def test_observed_facts_are_not_policy(self) -> None:
        profile = example_profile()
        profile["authorizedControlActions"] = []
        metadata = compile_detection_context_metadata(profile)
        self.assertNotIn("s7comm_control_policy", metadata)
        self.assertNotIn("ics_write_policy", metadata)
        self.assertNotIn("enip_cip_policy", metadata)
        observed = metadata["detection_context_observations"]["communications"][0]
        self.assertEqual(observed["source"], "10.10.2.10")
        self.assertEqual(observed["destination"], "10.10.1.20")


    def test_zeek_observed_assets_are_not_authoritative_inventory(self) -> None:
        profile = example_profile()
        profile["assets"].append({
            "id": "observed-only",
            "ip": "10.10.99.99",
            "hostname": "",
            "assetType": "Observed host",
            "role": "Unknown",
            "macAddresses": [],
            "services": [],
            "ports": [],
            "source": "zeek",
            "confidence": "low",
            "observedCount": 8,
        })
        metadata = compile_detection_context_metadata(profile)

        inventory_ips = {item["ip"] for item in metadata["asset_inventory"]}
        self.assertNotIn("10.10.99.99", inventory_ips)

        observed = metadata["detection_context_observations"]["assets"]
        observed_row = next(item for item in observed if item["ip"] == "10.10.99.99")
        self.assertEqual(observed_row["source_kind"], "zeek")
        self.assertEqual(observed_row["observed_count"], 8)

    def test_capture_scope_and_trusted_infrastructure_are_deliberate(self) -> None:
        metadata = compile_detection_context_metadata(example_profile())
        self.assertTrue(metadata["public_to_public_policy"]["internal_ics_only_expected"])
        self.assertTrue(metadata["ipv6_ot_policy"]["ipv4_only_expected"])
        self.assertEqual(metadata["ot_dns_policy"]["trusted_resolvers"], ["10.10.0.53"])
        self.assertEqual(metadata["ntp_ot_policy"]["trusted_servers"], ["10.10.0.123"])
        self.assertEqual(metadata["dhcp_ot_policy"]["expected_servers"], ["10.10.0.5"])
        self.assertEqual(metadata["ot_certificate_policy"]["management_hosts"], ["10.10.0.20"])

    def test_segment_exceptions_go_only_to_known_consumers(self) -> None:
        metadata = compile_detection_context_metadata(example_profile())
        expected = [{"source": "Enterprise", "destination": "Control"}]
        self.assertEqual(metadata["control_system_enterprise_policy"]["allowed_segment_pairs"], expected)
        self.assertEqual(metadata["database_exposure_policy"]["allowed_segment_pairs"], expected)
        self.assertEqual(metadata["netbios_smbv1_policy"]["allowed_segment_pairs"], expected)

    def test_explicit_control_authorization_maps_by_protocol(self) -> None:
        metadata = compile_detection_context_metadata(example_profile())
        modbus = metadata["ics_write_policy"]["allowed_paths"][0]
        self.assertEqual(modbus["protocol"], "modbus")
        self.assertEqual(modbus["allowed_function_codes"], [5, 6, 16])

        s7 = metadata["s7comm_control_policy"]["allowed_paths"][0]
        self.assertEqual(s7["source"], "10.10.2.11")
        self.assertEqual(s7["allowed_operations"], ["write"])

        cip = metadata["enip_cip_policy"]["allowed_write_paths"][0]
        self.assertEqual(cip["allowed_service_codes"], [16])
        self.assertEqual(len(metadata["plc_program_firmware_policy"]["allowed_pairs"]), 3)

    def test_advanced_override_overlays_first_class_policy(self) -> None:
        profile = example_profile()
        profile["modulePolicies"]["public_to_public_traffic"]["internal_ics_only_expected"] = False
        metadata = compile_detection_context_metadata(profile)
        self.assertFalse(metadata["public_to_public_policy"]["internal_ics_only_expected"])
        self.assertEqual(metadata["public_to_public_policy"]["min_flows"], 3)


if __name__ == "__main__":
    unittest.main()
