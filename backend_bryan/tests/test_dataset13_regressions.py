from backend_bryan.regression.dataset13_runner import run_cases

def test_dataset13_regressions() -> None:
    assert run_cases(verbose=False) == []
