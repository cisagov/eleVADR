"""Password hashing and JWT helpers for eleVADR authentication."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from .config import AuthConfig
from .models import AuthPrincipal


def _password_hasher():
    try:
        from argon2 import PasswordHasher
    except ImportError as exc:
        raise RuntimeError("argon2-cffi is required when eleVADR authentication is enabled") from exc
    return PasswordHasher()


_DUMMY_PASSWORD_HASH: str | None = None

def dummy_password_hash() -> str:
    """Return a process-local Argon2 hash used to equalize failed login work."""
    global _DUMMY_PASSWORD_HASH
    if _DUMMY_PASSWORD_HASH is None:
        _DUMMY_PASSWORD_HASH = _password_hasher().hash("elevadr-dummy-password-never-used-for-login")
    return _DUMMY_PASSWORD_HASH

def hash_password(password: str) -> str:
    """Hash a password using Argon2id."""
    if len(password) < 12:
        raise ValueError("New passwords must contain at least 12 characters")
    return _password_hasher().hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password without leaking Argon2 exceptions to callers."""
    try:
        from argon2.exceptions import InvalidHashError, VerifyMismatchError
        return bool(_password_hasher().verify(password_hash, password))
    except (VerifyMismatchError, InvalidHashError, ValueError):
        return False


def create_access_token(principal: AuthPrincipal, config: AuthConfig) -> str:
    """Create a signed short-lived JWT access token."""
    if not principal.authenticated or not principal.user_id:
        raise ValueError("Cannot issue an access token for an anonymous principal")
    try:
        import jwt
    except ImportError as exc:
        raise RuntimeError("PyJWT is required when eleVADR authentication is enabled") from exc
    now = datetime.now(UTC)
    payload: dict[str, Any] = {
        "sub": principal.user_id,
        "username": principal.username,
        "role": principal.role,
        "iat": now,
        "exp": now + timedelta(minutes=config.jwt_expire_minutes),
        "iss": "elevadr",
        "sv": principal.session_version,
    }
    return str(jwt.encode(payload, config.jwt_secret, algorithm=config.jwt_algorithm))


def decode_access_token(token: str, config: AuthConfig) -> AuthPrincipal:
    """Validate a JWT and return its principal."""
    try:
        import jwt
        payload = jwt.decode(
            token,
            config.jwt_secret,
            algorithms=["HS256"],
            issuer="elevadr",
            options={"require": ["exp", "iat", "sub", "iss"]},
        )
    except ImportError as exc:
        raise RuntimeError("PyJWT is required when eleVADR authentication is enabled") from exc
    except Exception as exc:
        raise ValueError("Invalid or expired access token") from exc
    user_id = str(payload.get("sub", "")).strip()
    username = str(payload.get("username", "")).strip()
    role = str(payload.get("role", "analyst")).strip() or "analyst"
    if not user_id or not username:
        raise ValueError("Access token is missing identity claims")
    return AuthPrincipal(user_id, username, True, role, int(payload.get("sv", 0)))
