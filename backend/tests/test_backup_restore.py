from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from backend.auth import backup_restore as br


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


def _tree(root: Path) -> dict[str, str]:
    return {p.relative_to(root).as_posix(): p.read_text() for p in sorted(root.rglob("*")) if p.is_file()}


def test_replace_storage_contents_keeps_the_directory_itself(tmp_path: Path, monkeypatch):
    storage = tmp_path / "storage"
    (storage / "users" / "old").mkdir(parents=True)
    (storage / "users" / "old" / "a.txt").write_text("old")
    incoming = tmp_path / "incoming"
    (incoming / "users" / "new").mkdir(parents=True)
    (incoming / "users" / "new" / "b.txt").write_text("new")

    # A mounted volume cannot be removed, so rmtree on the root leaves the directory behind.
    real_rmtree = br.shutil.rmtree

    def refuse_root(path, *args, **kwargs):
        if Path(path) == storage:
            raise OSError("Device or resource busy")
        return real_rmtree(path, *args, **kwargs)

    monkeypatch.setattr(br.shutil, "rmtree", refuse_root)

    br._replace_storage_contents(storage, incoming)

    assert _tree(storage) == {"users/new/b.txt": "new"}


def test_failed_restore_puts_the_old_storage_back(tmp_path: Path, monkeypatch):
    storage = tmp_path / "storage"
    (storage / "users" / "old").mkdir(parents=True)
    (storage / "users" / "old" / "a.txt").write_text("old")

    stage_files = tmp_path / "archive-storage"
    (stage_files / "users" / "new").mkdir(parents=True)
    (stage_files / "users" / "new" / "b.txt").write_text("new")

    class FakeClient:
        def __getitem__(self, name):
            return object()

        def close(self):
            pass

    calls = {"restore": 0}

    def fake_restore_database(db, stage, manifest):
        calls["restore"] += 1
        if calls["restore"] == 1:
            raise RuntimeError("database restore failed")

    def fake_extract(archive, dest):
        shutil_copy(stage_files, dest / "storage")

    import shutil as shutil_mod

    def shutil_copy(src, dst):
        shutil_mod.copytree(src, dst)

    cfg = type("Cfg", (), {"mongodb_database": "elevadr"})()
    monkeypatch.setattr(br, "STORAGE_ROOT", storage)
    monkeypatch.setattr(br, "_connect", lambda: (FakeClient(), cfg))
    monkeypatch.setattr(br, "_materialize_archive", lambda archive, base: archive)
    monkeypatch.setattr(br, "_safe_extract", fake_extract)
    monkeypatch.setattr(br, "_validate_extracted", lambda stage: {"database": "elevadr"})
    monkeypatch.setattr(br, "_dump_database", lambda db, out: {})
    monkeypatch.setattr(br, "_restore_database", fake_restore_database)

    with pytest.raises(RuntimeError, match="database restore failed"):
        br.restore_backup(tmp_path / "backup.zip", yes=True)

    assert _tree(storage) == {"users/old/a.txt": "old"}
    assert calls["restore"] == 2


def test_replace_storage_contents_with_no_source_empties_the_directory(tmp_path: Path):
    storage = tmp_path / "storage"
    (storage / "users" / "old").mkdir(parents=True)
    (storage / "users" / "old" / "a.txt").write_text("old")

    br._replace_storage_contents(storage, tmp_path / "missing")

    assert storage.is_dir()
    assert _tree(storage) == {}


def test_replace_storage_contents_creates_a_missing_directory(tmp_path: Path):
    incoming = tmp_path / "incoming"
    (incoming / "users").mkdir(parents=True)
    (incoming / "users" / "b.txt").write_text("new")
    storage = tmp_path / "storage"

    br._replace_storage_contents(storage, incoming)

    assert _tree(storage) == {"users/b.txt": "new"}


def test_source_never_packages_platform_env_or_secrets():
    source = Path(br.__file__).read_text(encoding="utf-8")
    assert '".elevadr-platform.env"' in source
    assert '"secretMaterialIncluded": False' in source
    assert "jwt_secret" in source
