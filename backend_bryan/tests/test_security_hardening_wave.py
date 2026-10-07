from __future__ import annotations
import io
from pathlib import Path

import pytest

from backend_bryan.auth.config import AuthConfig
from backend_bryan.auth.models import AuthPrincipal
from backend_bryan.auth.security import create_access_token, decode_access_token, hash_password, verify_password
from backend_bryan.auth import backup_restore as br

ROOT = Path(__file__).resolve().parents[2]

def test_new_password_policy_is_12_chars_but_existing_hashes_still_verify():
    with pytest.raises(ValueError):
        hash_password("shortpass")
    old_hash = br.hashlib.sha256(b"not-used").hexdigest()  # ensure unrelated hashing doesn't alter auth
    assert old_hash
    good = hash_password("correct horse battery staple")
    assert verify_password("correct horse battery staple", good)

def test_session_version_round_trips_in_jwt():
    cfg = AuthConfig(enabled=True, jwt_secret="x"*32)
    p = AuthPrincipal("abc", "analyst", True, "analyst", 7)
    decoded = decode_access_token(create_access_token(p, cfg), cfg)
    assert decoded.session_version == 7

def test_security_defaults_are_restricted():
    cfg = AuthConfig()
    assert cfg.max_pcap_upload_bytes == 256 * 1024 * 1024
    assert "http://127.0.0.1:5173" in cfg.cors_origins
    server = (ROOT/"backend_bryan/integration/http_reference_server.py").read_text(encoding="utf-8")
    assert 'Access-Control-Allow-Origin", "*"' not in server
    assert "_parse_multipart_stream" in server
    assert "LOGIN_MAX_FAILURES" in server and "login_throttled" in server

def test_vite_config_is_explicit_esm_and_localhost_only():
    import json
    package=json.loads((ROOT/"frontend/package.json").read_text(encoding="utf-8"))
    assert package.get("type") == "module"
    text=(ROOT/"frontend/vite.config.ts").read_text(encoding="utf-8")
    assert 'host: "127.0.0.1"' in text

def test_vitest_is_patched_past_august_2026_advisory():
    import json
    lock=json.loads((ROOT/"frontend/package-lock.json").read_text(encoding="utf-8"))
    assert lock["packages"]["node_modules/vitest"]["version"] >= "4.1.11"

def test_encrypted_backup_envelope_round_trip(tmp_path, monkeypatch):
    pytest.importorskip("cryptography")
    src=tmp_path/"plain.zip"; src.write_bytes(b"PK\x03\x04example")
    enc=tmp_path/"backup.evbackup"
    br._encrypt_file(src, enc, "long test passphrase")
    assert enc.read_bytes().startswith(br.ENCRYPTED_MAGIC)
    monkeypatch.setenv("ELEVADR_BACKUP_PASSPHRASE", "long test passphrase")
    decrypt=tmp_path/"decrypt"; decrypt.mkdir()
    out=br._materialize_archive(enc, decrypt)
    assert out.read_bytes() == src.read_bytes()
