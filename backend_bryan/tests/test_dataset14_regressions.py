from backend_bryan.regression.dataset14_runner import run_cases

def test_dataset14_regressions() -> None:
    assert run_cases(verbose=False) == []
