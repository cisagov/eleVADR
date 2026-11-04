from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_operator_guide_tracks_current_platform_workflows() -> None:
    guide = (ROOT / "docs/source/operator-guide.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    index = (ROOT / "docs/source/index.md").read_text(encoding="utf-8")

    required = [
        "first_run_elevadr.bat",
        "start_elevadr.bat",
        "run_platform_regression_tests.bat",
        "run_regression_tests.bat",
        "backup_elevadr.bat",
        "validate_elevadr_backup.bat",
        "restore_elevadr.bat",
        "ELEVADR_CORS_ORIGINS",
        "ELEVADR_MAX_PCAP_UPLOAD_MB",
        "ELEVADR_BACKUP_PASSPHRASE",
        "Analysis History",
        "Report Comparison",
        "Read Only",
    ]
    for token in required:
        assert token in guide

    assert "operator-guide.md" in index
    assert "Operator Guide" in readme
    assert "first_run_elevadr.bat" in readme
    assert ".elevadr-platform.env" not in readme or "secret" in readme.lower()
