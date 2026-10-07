from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from backend_bryan.auth import backup_restore as br


def test_validate_rejects_missing_manifest(tmp_path: Path):
    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("storage/users/x/reports/r.json", "{}")
    with pytest.raises(ValueError, match="manifest"):
        br.validate_backup(archive)


def test_validate_rejects_path_traversal(tmp_path: Path):
    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("../escape.txt", "bad")
    with pytest.raises(ValueError, match="Unsafe archive"):
        br.validate_backup(archive)


def test_validate_rejects_tampered_storage_file(tmp_path: Path):
    stage = tmp_path / "stage"
    (stage / "storage/users/u/reports").mkdir(parents=True)
    report = stage / "storage/users/u/reports/r.json"
    report.write_text("{}", encoding="utf-8")
    manifest = {
        "format": br.FORMAT,
        "createdAt": "2026-01-01T00:00:00+00:00",
        "database": "elevadr",
        "collections": {},
        "storageFiles": {"users/u/reports/r.json": {"size": 2, "sha256": "0" * 64}},
        "settings": {},
        "secretMaterialIncluded": False,
    }
    (stage / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    archive = tmp_path / "tampered.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        for p in stage.rglob("*"):
            if p.is_file():
                zf.write(p, p.relative_to(stage).as_posix())
    with pytest.raises(ValueError, match="Storage backup mismatch"):
        br.validate_backup(archive)


def test_restore_requires_explicit_yes(tmp_path: Path):
    with pytest.raises(ValueError, match="--yes"):
        br.restore_backup(tmp_path / "anything.zip", yes=False)


def test_source_never_packages_platform_env_or_secrets():
    source = Path(br.__file__).read_text(encoding="utf-8")
    assert '".elevadr-platform.env"' in source
    assert '"secretMaterialIncluded": False' in source
    assert "jwt_secret" in source
