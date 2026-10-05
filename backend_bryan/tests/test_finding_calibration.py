from __future__ import annotations

import json
from pathlib import Path

from backend_bryan.integration.analysis_service import analyze_detection_request
from backend_bryan.integration.detector_runtime import ensure_detector_package
from backend_bryan.integration.finding_calibration import (
    CALIBRATION_PROFILES,
    CALIBRATION_VERSION,
    calibrate_finding,
)

ROOT = Path(__file__).resolve().parents[1]
Context, MODULES, _ = ensure_detector_package()
from elevadr_modules.models import Finding


def _finding(*, severity: str, confidence: str, basis: str, title: str = "Test finding", summary: str = "") -> Finding:
    return Finding(
        title=title,
        severity=severity,
        summary=summary or title,
        confidence=confidence,
        detection_basis=basis,
    )


def test_all_75_registry_modules_have_exactly_one_calibration_profile() -> None:
    assert len(MODULES) == 75
    assert len(CALIBRATION_PROFILES) == 75
    assert set(CALIBRATION_PROFILES) == set(MODULES)


def test_explicit_control_policy_violation_is_prioritized_high_with_direct_evidence() -> None:
    finding = _finding(
        severity="medium",
        confidence="medium",
        basis="protocol_log",
        title="Unauthorized S7 write observed",
    )
    calibrate_finding("s7comm_unauthorized_write_stop", finding)
    assert finding.severity == "high"
    assert finding.confidence == "high"
    calibration = finding.metadata["calibration"]
    assert calibration["family"] == "control_policy"
    assert calibration["explicit_policy_violation"] is True
    assert calibration["adjusted"] is True


def test_derived_behavioral_drift_cannot_outrank_explicit_policy_violation() -> None:
    finding = _finding(
        severity="high",
        confidence="high",
        basis="derived",
        title="OT polling cadence changed",
    )
    calibrate_finding("polling_cadence_disruption", finding)
    assert finding.severity == "medium"
    assert finding.confidence == "medium"
    calibration = finding.metadata["calibration"]
    assert calibration["family"] == "behavioral_drift"
    assert calibration["explicit_policy_violation"] is False


def test_port_or_heuristic_evidence_cannot_claim_high_confidence() -> None:
    for basis in ("port", "heuristic"):
        finding = _finding(severity="medium", confidence="high", basis=basis)
        calibrate_finding("protocol_unexpected_high_risk_port", finding)
        assert finding.confidence == "medium"


def test_calibration_is_auditable_and_mirrors_effective_confidence() -> None:
    request = json.loads((ROOT / "examples" / "analysis_request.json").read_text(encoding="utf-8"))
    request["profile"]["selectedModules"] = ["s7comm_unauthorized_write_stop"]
    request["profile"]["authorizedControlActions"] = []
    request["logs"] = {
        "s7comm": [{
            "ts": 1710000000.25,
            "id.orig_h": "10.10.1.50",
            "id.orig_p": 41000,
            "id.resp_h": "10.10.2.20",
            "id.resp_p": 102,
            "function": "write",
        }]
    }
    response = analyze_detection_request(request)
    finding = response["moduleResults"][0]["findings"][0]
    calibration = finding["metadata"]["calibration"]
    assert calibration["version"] == CALIBRATION_VERSION
    assert calibration["severity"] == finding["severity"]
    assert calibration["confidence"] == finding["confidence"]
    assert finding["metadata"]["confidence"] == finding["confidence"]
