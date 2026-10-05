from backend_bryan.regression.dataset06_runner import cases, run_cases


def test_dataset06_threshold_boundaries() -> None:
    failures = run_cases(verbose=False)
    assert failures == []
    assert len(cases()) >= 16
