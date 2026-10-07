from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_platform_ui_polish_contract() -> None:
    app = (ROOT / "frontend/src/app/App.tsx").read_text(encoding="utf-8")
    css = (ROOT / "frontend/src/app/App.css").read_text(encoding="utf-8")
    assert "platform-workspace-view" in app
    assert 'aria-label="Dashboard shortcuts"' in app
    assert 'title="Sign out of eleVADR"' in app
    assert "position: sticky" in css
    assert ".saved-report-delete:hover" in css
    assert ".activity-result.success" in css
    assert "prefers-reduced-motion" in css
    assert "report-comparison summary:focus-visible" in css
