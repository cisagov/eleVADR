from backend_bryan.regression.dataset07_runner import run_cases


def test_dataset07_stateful_temporal_isolation() -> None:
    failures = run_cases(verbose=False)
    assert failures == []
