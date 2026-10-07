from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
APP = ROOT / "frontend" / "src" / "app" / "App.tsx"
CSS = ROOT / "frontend" / "src" / "app" / "App.css"


def test_signed_in_platform_uses_workspace_navigation():
    source = APP.read_text(encoding="utf-8")
    assert 'aria-label="Platform workspace"' in source
    for view in ('dashboard', 'reports', 'pcaps', 'activity', 'storage', 'account'):
        assert f'platformView === "{view}"' in source
    assert 'platform-workspace-signout' in source


def test_platform_views_keep_existing_capabilities_separated():
    source = APP.read_text(encoding="utf-8")
    assert 'platformView === "reports" && <section' in source
    assert 'platformView === "pcaps" && <section' in source
    assert 'platformView === "storage" && <section' in source
    assert 'platformView === "activity" && <section' in source
    assert 'platformView === "account" && <section' in source
    assert 'canWriteAnalysis ? <UploadForm' in source


def test_workspace_navigation_has_accessible_focus_and_responsive_styles():
    css = CSS.read_text(encoding="utf-8")
    assert '.platform-workspace-nav button:focus-visible' in css
    assert '.platform-workspace-nav button.is-active' in css
    assert '@media (max-width:700px)' in css
