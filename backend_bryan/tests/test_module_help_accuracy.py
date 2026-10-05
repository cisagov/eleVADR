from backend_bryan.integration.module_help_accuracy import audit


def test_module_help_matches_detector_implementation() -> None:
    errors = audit()
    assert errors == [], "\n".join(errors)
