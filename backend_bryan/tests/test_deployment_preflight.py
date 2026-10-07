from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

def test_clean_machine_deployment_contract() -> None:
    preflight = (ROOT / "backend_bryan/integration/deployment_preflight.py").read_text(encoding="utf-8")
    first_run = (ROOT / "first_run_elevadr.bat").read_text(encoding="utf-8")
    validate = (ROOT / "validate_clean_install.bat").read_text(encoding="utf-8")
    start = (ROOT / "start_elevadr.bat").read_text(encoding="utf-8")
    packager = (ROOT / "package_elevadr_upload.ps1").read_text(encoding="utf-8")
    assert "requires ^22.22.3" in preflight
    assert "requirements-platform.txt" in first_run
    assert "npm.cmd ci" in first_run
    assert "setup_elevadr_database.bat" in first_run
    assert "--role admin" in first_run
    assert "enable_auth" in first_run
    assert "deployment_preflight --initialized" in validate
    assert "run_platform_regression_tests.bat" in validate
    assert "npm.cmd start" in start and "pnpm.cmd start" not in start
    assert "first_run_elevadr.bat" in packager
    assert "validate_clean_install.bat" in packager
    assert "DEPLOYMENT_PACKAGE_MANIFEST.json" in packager
