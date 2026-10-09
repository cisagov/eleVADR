from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
APP = ROOT / "frontend/src/app/App.tsx"
CSS = ROOT / "frontend/src/app/App.css"


def test_signed_in_platform_uses_workspace_navigation():
    source = APP.read_text(encoding="utf-8")
    assert 'aria-label="Platform workspace"' in source
    for view in ('open-file', 'analyses', 'storage', 'administration', 'account'):
        assert f'"{view}"' in source
    assert 'onClick={() => setPlatformView(id)}' in source
    assert 'aria-current={' in source
    assert 'handleSignOut' in source


def test_platform_views_keep_existing_capabilities_separated():
    source = APP.read_text(encoding="utf-8")
    for view in ('analyses', 'storage', 'administration', 'account'):
        assert f'platformView === "{view}"' in source
    assert '<UploadForm' in source
    assert 'canWriteAnalysis ? (' in source
    assert 'className="welcome-account-panel read-only-notice"' in source
    assert 'authState.user.role === "admin"' in source


def test_workspace_navigation_has_accessible_focus_and_responsive_styles():
    css = CSS.read_text(encoding="utf-8")
    assert '.platform-workspace-nav button:focus-visible' in css
    assert '.platform-workspace-nav button.is-active' in css
    assert re.search(r'@media\s*\(max-width:\s*700px\)', css)
