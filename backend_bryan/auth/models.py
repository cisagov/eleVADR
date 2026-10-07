"""Small authentication domain models independent of MongoDB and HTTP."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AuthPrincipal:
    """Authenticated or anonymous identity exposed to application code."""

    user_id: str | None
    username: str
    authenticated: bool
    role: str = "anonymous"
    session_version: int = 0

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.user_id,
            "username": self.username,
            "authenticated": self.authenticated,
            "role": self.role,
        }


ANONYMOUS_PRINCIPAL = AuthPrincipal(None, "anonymous", False, "anonymous")
