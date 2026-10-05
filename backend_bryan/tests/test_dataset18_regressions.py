from __future__ import annotations

import csv
import tempfile
import unittest
from pathlib import Path

from backend_bryan.regression.dataset18_real_site_runner import (
    _coverage,
    _read_review,
    _review_rows,
    _review_summary,
    _write_csv,
)


class Dataset18RegressionTests(unittest.TestCase):
    def _report(self) -> dict:
        return {
            "connections": [
                {"service.name": "modbus", "state": "SF"},
                {"service.name": "modbus", "state": "RSTO"},
            ],
            "arch_insights": {
                "analysis_provenance": {
                    "source_filename": "site.pcap",
                    "detection_context_name": "Site A",
                    "zeek_runtime": "Docker",
                    "zeek_log_types": {"conn": 2, "modbus": 1},
                    "detector_modules_requested": 75,
                    "detector_modules_completed": 75,
                    "detector_modules_failed": 0,
                },
                "detector_results": [
                    {
                        "module_id": "example_detector",
                        "findings": [
                            {
                                "title": "Example finding",
                                "severity": "medium",
                                "summary": "Observed evidence requires analyst review.",
                                "confidence": "high",
                                "detection_basis": "protocol_log",
                                "devices": ["10.0.0.10"],
                                "services": ["modbus"],
                                "ports": [502],
                                "connection_pairs": [{"source": "10.0.0.5", "destination": "10.0.0.10"}],
                                "timestamps": [1.0],
                                "metadata": {"observed": True},
                            }
                        ],
                        "warnings": [],
                    },
                    {"module_id": "clean_detector", "findings": [], "warnings": []},
                ],
                "detector_errors": [],
            },
        }

    def test_review_rows_are_stable_and_leave_policy_decision_blank(self) -> None:
        first = _review_rows(self._report())
        second = _review_rows(self._report())
        self.assertEqual(first, second)
        self.assertEqual(len(first), 1)
        self.assertEqual(first[0]["module_id"], "example_detector")
        self.assertEqual(first[0]["analyst_disposition"], "")
        self.assertEqual(first[0]["suggested_tuning_action"], "")
        self.assertTrue(first[0]["review_id"])

    def test_coverage_reports_zero_finding_modules_without_inventing_policy(self) -> None:
        coverage = _coverage(self._report())
        self.assertEqual(coverage["detector_modules_completed"], 75)
        self.assertEqual(coverage["findings_total"], 1)
        self.assertEqual(coverage["modules_with_findings"], ["example_detector"])
        self.assertEqual(coverage["modules_without_findings"], ["clean_detector"])
        self.assertEqual(coverage["service_counts"]["modbus"], 2)

    def test_review_round_trip_and_tuning_summary(self) -> None:
        rows = _review_rows(self._report())
        rows[0]["analyst_disposition"] = "false-positive"
        rows[0]["analyst_notes"] = "Known scheduled maintenance pattern."
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "review.csv"
            _write_csv(path, rows)
            loaded = _read_review(path)
        summary = _review_summary(loaded)
        self.assertEqual(summary["reviewed_rows"], 1)
        self.assertEqual(summary["dispositions"].get("false-positive"), 1)
        self.assertEqual(summary["false_positive_modules"].get("example_detector"), 1)
        self.assertEqual(len(summary["tuning_candidates"]), 1)

    def test_invalid_disposition_is_rejected(self) -> None:
        rows = _review_rows(self._report())
        rows[0]["analyst_disposition"] = "silence-it"
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "review.csv"
            _write_csv(path, rows)
            with self.assertRaises(ValueError):
                _read_review(path)


if __name__ == "__main__":
    unittest.main()
