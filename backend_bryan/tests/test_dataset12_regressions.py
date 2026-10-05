from backend_bryan.regression.dataset12_runner import run_cases

def test_dataset12_regressions() -> None:
    assert run_cases(verbose=False) == []
