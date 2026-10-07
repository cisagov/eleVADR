from __future__ import annotations

from pathlib import Path

from backend_bryan.auth.local_runtime import build_mongodb_uri, render_env, write_env

ROOT = Path(__file__).resolve().parents[2]


def test_local_uri_is_loopback_authenticated_and_direct() -> None:
    uri = build_mongodb_uri("root user", "p@ss word", 27018)
    assert uri.startswith("mongodb://root+user:p%40ss+word@127.0.0.1:27018/")
    assert "authSource=admin" in uri
    assert "directConnection=true" in uri


def test_generated_environment_keeps_auth_disabled() -> None:
    text = render_env("elevadr_root", "password123", "x" * 64, 27017)
    assert "ELEVADR_AUTH_ENABLED=false" in text
    assert "ELEVADR_MONGODB_DATABASE=elevadr" in text
    assert "ELEVADR_JWT_ALGORITHM=HS256" in text


def test_runtime_env_creation_refuses_accidental_overwrite(tmp_path: Path) -> None:
    target = tmp_path / ".elevadr-platform.env"
    write_env(target)
    original = target.read_text(encoding="utf-8")
    try:
        write_env(target)
    except FileExistsError:
        pass
    else:
        raise AssertionError("existing runtime secrets must not be silently replaced")
    assert target.read_text(encoding="utf-8") == original


def test_compose_binds_mongodb_to_loopback_and_persists_data() -> None:
    compose = (ROOT / "docker-compose.mongodb.yml").read_text(encoding="utf-8")
    assert "mongodb/mongodb-community-server:8.0.32-ubi9-slim" in compose
    assert '127.0.0.1:${ELEVADR_MONGO_PORT:-27017}:27017' in compose
    assert "elevadr-mongodb-data:/data/db" in compose
    assert "healthcheck:" in compose
    assert "MONGODB_INITDB_ROOT_USERNAME" in compose
    assert "MONGODB_INITDB_ROOT_PASSWORD" in compose


def test_stage1b_scripts_are_present() -> None:
    for name in (
        "setup_elevadr_database.bat",
        "start_elevadr_database.bat",
        "stop_elevadr_database.bat",
        "check_elevadr_database.bat",
        "create_elevadr_user.bat",
    ):
        assert (ROOT / name).is_file(), name


def test_normal_launcher_uses_secret_safe_platform_env_runner() -> None:
    launcher = (ROOT / "start_elevadr.bat").read_text(encoding="utf-8")
    assert "backend_bryan.auth.env_runner backend_bryan.integration.http_reference_server" in launcher
    assert 'for /f "usebackq tokens=1,* delims=="' not in launcher.lower()
    assert "ELEVADR_JWT_SECRET" not in launcher


def test_user_bootstrap_forwards_role_and_uses_platform_env_runner() -> None:
    launcher = (ROOT / "create_elevadr_user.bat").read_text(encoding="utf-8")
    assert "backend_bryan.auth.env_runner backend_bryan.auth.create_user %*" in launcher
    assert "ELEVADR_JWT_SECRET" not in launcher


def test_platform_env_runner_loads_file_as_authoritative_local_configuration(tmp_path: Path, monkeypatch) -> None:
    from backend_bryan.auth.env_runner import apply_platform_env

    env_file = tmp_path / ".elevadr-platform.env"
    env_file.write_text("ELEVADR_AUTH_ENABLED=true\nELEVADR_JWT_SECRET=file-secret\n", encoding="utf-8")
    monkeypatch.setenv("ELEVADR_AUTH_ENABLED", "false")
    monkeypatch.delenv("ELEVADR_JWT_SECRET", raising=False)
    assert apply_platform_env(env_file) is True
    assert __import__("os").environ["ELEVADR_AUTH_ENABLED"] == "true"
    assert __import__("os").environ["ELEVADR_JWT_SECRET"] == "file-secret"
