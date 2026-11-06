"""Consistent local backup/validation/restore tooling for eleVADR platform state."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import struct
import tempfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .config import load_auth_config

ROOT = Path(__file__).resolve().parents[2]
STORAGE_ROOT = ROOT / "storage"
BACKUP_ROOT = ROOT / "backups"
FORMAT = "elevadr.platform-backup.v1"
ENCRYPTED_MAGIC = b"EVADRBAK1"



def _backup_passphrase() -> str:
    return os.environ.get("ELEVADR_BACKUP_PASSPHRASE", "")

def _encrypt_file(source: Path, destination: Path, passphrase: str) -> None:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    except ImportError as exc:
        raise RuntimeError("cryptography is required for encrypted backups") from exc
    salt = os.urandom(16); nonce = os.urandom(12)
    key = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(passphrase.encode("utf-8"))
    ciphertext = AESGCM(key).encrypt(nonce, source.read_bytes(), ENCRYPTED_MAGIC)
    destination.write_bytes(ENCRYPTED_MAGIC + salt + nonce + ciphertext)

def _materialize_archive(archive: Path, temp_dir: Path) -> Path:
    raw = archive.read_bytes()[:len(ENCRYPTED_MAGIC)]
    if raw != ENCRYPTED_MAGIC:
        return archive
    passphrase = _backup_passphrase()
    if not passphrase:
        raise ValueError("Encrypted backup requires ELEVADR_BACKUP_PASSPHRASE")
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    except ImportError as exc:
        raise RuntimeError("cryptography is required for encrypted backups") from exc
    data = archive.read_bytes()
    salt = data[len(ENCRYPTED_MAGIC):len(ENCRYPTED_MAGIC)+16]
    nonce = data[len(ENCRYPTED_MAGIC)+16:len(ENCRYPTED_MAGIC)+28]
    ciphertext = data[len(ENCRYPTED_MAGIC)+28:]
    key = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(passphrase.encode("utf-8"))
    try:
        plain = AESGCM(key).decrypt(nonce, ciphertext, ENCRYPTED_MAGIC)
    except Exception as exc:
        raise ValueError("Backup decryption failed; passphrase is missing or incorrect, or archive was modified") from exc
    target = temp_dir / "decrypted.zip"; target.write_bytes(plain); return target


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _connect():
    from pymongo import MongoClient
    cfg = load_auth_config()
    client = MongoClient(cfg.mongodb_uri, serverSelectionTimeoutMS=5000)
    client.admin.command("ping")
    return client, cfg


def _dump_database(db: Any, out: Path) -> dict[str, Any]:
    from bson import BSON
    out.mkdir(parents=True, exist_ok=True)
    result: dict[str, Any] = {}
    for name in sorted(n for n in db.list_collection_names() if not n.startswith("system.")):
        target = out / f"{name}.bsonseq"
        count = 0
        with target.open("wb") as fh:
            for doc in db[name].find({}):
                fh.write(BSON.encode(doc))
                count += 1
        result[name] = {"count": count, "sha256": _sha256(target), "file": f"mongo/{target.name}"}
    return result


def _read_bsonseq(path: Path) -> list[dict[str, Any]]:
    from bson import BSON
    docs: list[dict[str, Any]] = []
    data = path.read_bytes()
    pos = 0
    while pos < len(data):
        if pos + 4 > len(data):
            raise ValueError(f"Truncated BSON sequence: {path.name}")
        size = struct.unpack_from("<i", data, pos)[0]
        if size < 5 or pos + size > len(data):
            raise ValueError(f"Invalid BSON document length in {path.name}")
        docs.append(BSON(data[pos:pos + size]).decode())
        pos += size
    return docs


def _copy_storage(source: Path, dest: Path) -> dict[str, Any]:
    files: dict[str, Any] = {}
    users = source / "users"
    if not users.exists():
        return files
    for src in sorted(p for p in users.rglob("*") if p.is_file()):
        rel = src.relative_to(source).as_posix()
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, target)
        files[rel] = {"size": src.stat().st_size, "sha256": _sha256(target)}
    return files


def create_backup(destination: Path | None = None) -> Path:
    client, cfg = _connect()
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    destination = destination or (BACKUP_ROOT / f"elevadr-backup-{stamp}{'.evbackup' if _backup_passphrase() else '.zip'}")
    destination = destination.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="elevadr-backup-") as td:
        stage = Path(td)
        collections = _dump_database(client[cfg.mongodb_database], stage / "mongo")
        storage_files = _copy_storage(STORAGE_ROOT, stage / "storage")
        manifest = {
            "format": FORMAT,
            "createdAt": datetime.now(UTC).isoformat(),
            "database": cfg.mongodb_database,
            "collections": collections,
            "storageFiles": storage_files,
            "settings": {
                "pcapRetentionDays": cfg.pcap_retention_days,
                "pcapStorageLimitBytes": cfg.pcap_storage_limit_bytes,
            },
            "secretMaterialIncluded": False,
        }
        (stage / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
        tmpzip = destination.with_suffix(destination.suffix + ".tmp")
        if tmpzip.exists():
            tmpzip.unlink()
        with zipfile.ZipFile(tmpzip, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
            for p in sorted(x for x in stage.rglob("*") if x.is_file()):
                zf.write(p, p.relative_to(stage).as_posix())
        passphrase = _backup_passphrase()
        if passphrase:
            _encrypt_file(tmpzip, destination, passphrase)
            tmpzip.unlink(missing_ok=True)
        else:
            tmpzip.replace(destination)
            print("WARNING: backup is not encrypted; protect the archive with filesystem/device encryption or set ELEVADR_BACKUP_PASSPHRASE.")
    client.close()
    validate_backup(destination)
    return destination


def _safe_extract(archive: Path, dest: Path) -> None:
    with zipfile.ZipFile(archive) as zf:
        for info in zf.infolist():
            name = info.filename.replace("\\", "/")
            if name.startswith("/") or ".." in Path(name).parts:
                raise ValueError(f"Unsafe archive member: {info.filename}")
            target = (dest / name).resolve()
            if dest.resolve() not in target.parents and target != dest.resolve():
                raise ValueError(f"Unsafe archive member: {info.filename}")
        zf.extractall(dest)


def _validate_extracted(stage: Path) -> dict[str, Any]:
    manifest_path = stage / "manifest.json"
    if not manifest_path.is_file():
        raise ValueError("Backup is missing manifest.json")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("format") != FORMAT:
        raise ValueError("Unsupported eleVADR backup format")
    if manifest.get("secretMaterialIncluded") is not False:
        raise ValueError("Backup manifest does not assert secret exclusion")
    for name, meta in manifest.get("collections", {}).items():
        path = stage / str(meta["file"])
        if not path.is_file() or _sha256(path) != meta.get("sha256"):
            raise ValueError(f"MongoDB backup hash mismatch: {name}")
        if len(_read_bsonseq(path)) != int(meta.get("count", -1)):
            raise ValueError(f"MongoDB backup count mismatch: {name}")
    for rel, meta in manifest.get("storageFiles", {}).items():
        path = stage / "storage" / rel
        if not path.is_file() or path.stat().st_size != int(meta.get("size", -1)) or _sha256(path) != meta.get("sha256"):
            raise ValueError(f"Storage backup mismatch: {rel}")
    forbidden = {".elevadr-platform.env", "jwt_secret", "mongo_root_password"}
    for p in stage.rglob("*"):
        if p.is_file() and p.name.lower() in forbidden:
            raise ValueError(f"Backup contains forbidden secret file: {p.name}")
    return manifest


def validate_backup(archive: Path) -> dict[str, Any]:
    archive = archive.resolve()
    if not archive.is_file():
        raise FileNotFoundError(archive)
    with tempfile.TemporaryDirectory(prefix="elevadr-validate-") as td:
        base = Path(td); stage = base / "stage"; stage.mkdir()
        materialized = _materialize_archive(archive, base)
        _safe_extract(materialized, stage)
        return _validate_extracted(stage)


def _restore_database(db: Any, stage: Path, manifest: dict[str, Any]) -> None:
    for name in db.list_collection_names():
        if not name.startswith("system."):
            db[name].drop()
    for name, meta in manifest.get("collections", {}).items():
        docs = _read_bsonseq(stage / str(meta["file"]))
        if docs:
            db[name].insert_many(docs, ordered=True)


def restore_backup(archive: Path, *, yes: bool = False) -> None:
    if not yes:
        raise ValueError("Restore requires --yes because it replaces current MongoDB and storage state")
    client, cfg = _connect()
    with tempfile.TemporaryDirectory(prefix="elevadr-restore-") as td:
        base = Path(td)
        stage = base / "incoming"
        stage.mkdir(parents=True)
        materialized = _materialize_archive(archive.resolve(), base)
        _safe_extract(materialized, stage)
        manifest = _validate_extracted(stage)
        if manifest.get("database") != cfg.mongodb_database:
            raise ValueError("Backup database name does not match configured eleVADR database")

        rollback = Path(td) / "rollback"
        old_manifest = _dump_database(client[cfg.mongodb_database], rollback / "mongo")
        old_storage = _copy_storage(STORAGE_ROOT, rollback / "storage")
        rollback_manifest = {"collections": old_manifest, "storageFiles": old_storage}

        new_storage = stage / "storage"
        storage_old = Path(td) / "storage-old"
        try:
            if STORAGE_ROOT.exists():
                shutil.copytree(STORAGE_ROOT, storage_old)
            shutil.rmtree(STORAGE_ROOT, ignore_errors=True)
            if new_storage.exists():
                shutil.copytree(new_storage, STORAGE_ROOT)
            else:
                STORAGE_ROOT.mkdir(parents=True, exist_ok=True)
            _restore_database(client[cfg.mongodb_database], stage, manifest)
        except Exception:
            shutil.rmtree(STORAGE_ROOT, ignore_errors=True)
            if storage_old.exists():
                shutil.copytree(storage_old, STORAGE_ROOT)
            _restore_database(client[cfg.mongodb_database], rollback, rollback_manifest)
            raise
    client.close()


def _summary(manifest: dict[str, Any]) -> str:
    docs = sum(int(v.get("count", 0)) for v in manifest.get("collections", {}).values())
    files = len(manifest.get("storageFiles", {}))
    size = sum(int(v.get("size", 0)) for v in manifest.get("storageFiles", {}).values())
    return f"collections={len(manifest.get('collections', {}))}, documents={docs}, storage_files={files}, storage_bytes={size}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Backup, validate, or restore eleVADR persistent platform state")
    sub = parser.add_subparsers(dest="command", required=True)
    b = sub.add_parser("backup")
    b.add_argument("destination", nargs="?")
    v = sub.add_parser("validate")
    v.add_argument("archive")
    r = sub.add_parser("restore")
    r.add_argument("archive")
    r.add_argument("--yes", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "backup":
            path = create_backup(Path(args.destination) if args.destination else None)
            manifest = validate_backup(path)
            print(f"PASS: backup created and validated: {path}")
            print(_summary(manifest))
        elif args.command == "validate":
            manifest = validate_backup(Path(args.archive))
            print(f"PASS: backup is valid: {Path(args.archive).resolve()}")
            print(_summary(manifest))
        else:
            restore_backup(Path(args.archive), yes=args.yes)
            print("PASS: eleVADR persistent state restored successfully.")
        return 0
    except Exception as exc:
        print(f"ERROR: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
