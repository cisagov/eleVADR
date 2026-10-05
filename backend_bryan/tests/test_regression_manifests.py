from __future__ import annotations

from backend_bryan.regression.runner import load_manifests, run_manifest, validate_report


def test_known_good_reference_reports_match_regression_manifests() -> None:
    manifests = load_manifests()
    assert len(manifests) == 3
    for manifest in manifests:
        report, _elapsed = run_manifest(manifest, "fixture")
        failures = validate_report(manifest, report)
        assert failures == [], "\n".join(f"{failure.dataset}: {failure.message}" for failure in failures)
