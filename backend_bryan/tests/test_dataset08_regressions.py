from backend_bryan.regression.dataset08_runner import run_cases


def test_dataset08_policy_precedence_conflicts() -> None:
    failures = run_cases(verbose=False)
    assert failures == []
