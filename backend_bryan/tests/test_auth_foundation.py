from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from backend_bryan.auth.config import AuthConfig, load_auth_config
from backend_bryan.auth.models import ANONYMOUS_PRINCIPAL, AuthPrincipal
from backend_bryan.auth.security import create_access_token, decode_access_token, hash_password, verify_password
from backend_bryan.auth.service import AuthenticationService


class FakeUserStore:
    def __init__(self) -> None:
        self.closed = False

    def authenticate(self, username: str, password: str) -> AuthPrincipal | None:
        if username == "analyst" and password == "correct horse battery staple":
            return AuthPrincipal("user-1", "analyst", True, "analyst")
        return None

    def close(self) -> None:
        self.closed = True


def secure_config(**overrides: object) -> AuthConfig:
    values = {
        "enabled": True,
        "jwt_secret": "stage-one-test-secret-that-is-long-enough-123456",
        "jwt_expire_minutes": 60,
    }
    values.update(overrides)
    return AuthConfig(**values)


def test_auth_is_disabled_by_default() -> None:
    with patch.dict(os.environ, {}, clear=True):
        config = load_auth_config()
    assert config.enabled is False
    assert AuthenticationService(config).current_principal(None) == ANONYMOUS_PRINCIPAL


def test_enabled_auth_requires_strong_jwt_secret() -> None:
    with pytest.raises(ValueError, match="at least 32 characters"):
        AuthConfig(enabled=True, jwt_secret="short").validate_for_enabled_mode()


def test_password_hashing_uses_one_way_argon2_verification() -> None:
    password_hash = hash_password("correct horse battery staple")
    assert password_hash != "correct horse battery staple"
    assert password_hash.startswith("$argon2")
    assert verify_password("correct horse battery staple", password_hash)
    assert not verify_password("wrong password", password_hash)


def test_jwt_round_trip_preserves_principal() -> None:
    config = secure_config()
    principal = AuthPrincipal("user-123", "operator", True, "analyst")
    token = create_access_token(principal, config)
    decoded = decode_access_token(token, config)
    assert decoded == principal


def test_login_uses_user_store_and_returns_signed_token() -> None:
    config = secure_config()
    store = FakeUserStore()
    service = AuthenticationService(config, store)
    principal, token = service.login("analyst", "correct horse battery staple")
    assert principal.authenticated
    assert decode_access_token(token, config) == principal
    service.close()
    assert store.closed


def test_invalid_credentials_do_not_issue_token() -> None:
    service = AuthenticationService(secure_config(), FakeUserStore())
    with pytest.raises(PermissionError, match="Invalid username or password"):
        service.login("analyst", "wrong")


def test_auth_disabled_login_is_rejected_without_database() -> None:
    service = AuthenticationService(AuthConfig(enabled=False))
    with pytest.raises(RuntimeError, match="disabled"):
        service.login("anyone", "anything")


def test_bearer_token_required_only_when_auth_enabled() -> None:
    service = AuthenticationService(secure_config(), FakeUserStore())
    with pytest.raises(PermissionError, match="Authentication required"):
        service.current_principal(None)
    principal, token = service.login("analyst", "correct horse battery staple")
    assert service.current_principal(f"Bearer {token}") == principal


def test_stage1_rejects_configurable_jwt_algorithm() -> None:
    with pytest.raises(ValueError, match="must be HS256"):
        secure_config(jwt_algorithm="none").validate_for_enabled_mode()


def test_tampered_jwt_is_rejected() -> None:
    config = secure_config()
    token = create_access_token(AuthPrincipal("user-1", "analyst", True, "analyst"), config)
    head, body, signature = token.split(".")
    replacement = ("A" if signature[0] != "A" else "B") + signature[1:]
    with pytest.raises(ValueError, match="Invalid or expired"):
        decode_access_token(f"{head}.{body}.{replacement}", config)


def test_wrong_signing_secret_is_rejected() -> None:
    token = create_access_token(AuthPrincipal("user-1", "analyst", True, "analyst"), secure_config())
    with pytest.raises(ValueError, match="Invalid or expired"):
        decode_access_token(token, secure_config(jwt_secret="different-stage-one-secret-that-is-long-enough-654321"))


def test_expired_jwt_is_rejected() -> None:
    import jwt
    from datetime import UTC, datetime, timedelta
    config = secure_config()
    now = datetime.now(UTC)
    token = jwt.encode({
        "sub": "user-1", "username": "analyst", "role": "analyst",
        "iat": now - timedelta(minutes=2), "exp": now - timedelta(minutes=1), "iss": "elevadr",
    }, config.jwt_secret, algorithm="HS256")
    with pytest.raises(ValueError, match="Invalid or expired"):
        decode_access_token(token, config)
