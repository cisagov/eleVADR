"""Compatibility shim for checkouts upgraded from the original 60-detector baseline.

This filename is intentionally retained so extracting the 75-detector checkpoint over
an older eleVADR tree overwrites the obsolete test that asserted exactly 60 modules.
The authoritative registry contract lives in test_all_detector_modules.py.
"""
from __future__ import annotations

import unittest

from elevadr_modules.registry import MODULES


class LegacyDetectorCountCompatibilityTests(unittest.TestCase):
    def test_registry_has_current_75_module_count(self) -> None:
        self.assertEqual(len(MODULES), 75)


if __name__ == "__main__":
    unittest.main()
