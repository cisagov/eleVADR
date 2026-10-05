from backend_bryan.regression.dataset11_runner import run_cases

def test_dataset11_regressions() -> None:
    assert run_cases(verbose=False) == []
