from backend_bryan.regression.dataset10_runner import run_cases


def test_dataset10_performance_scale_regressions() -> None:
    failures = run_cases(verbose=False)
    assert failures == []
