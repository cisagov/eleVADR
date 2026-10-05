from __future__ import annotations

from backend_bryan.integration.release_preflight import run_checks


def test_release_preflight_all_checks_pass() -> None:
    results = run_checks()
    failures = [item for item in results if not item.ok]
    assert not failures, "\n".join(f"{item.name}: {item.detail}" for item in failures)
