from __future__ import annotations

ROLE_ADMIN = "admin"
ROLE_ANALYST = "analyst"
ROLE_READ_ONLY = "read_only"
SUPPORTED_ROLES = frozenset({ROLE_ADMIN, ROLE_ANALYST, ROLE_READ_ONLY})
WRITE_ROLES = frozenset({ROLE_ADMIN, ROLE_ANALYST})


def can_view(role: str) -> bool:
    return role in SUPPORTED_ROLES


def can_write(role: str) -> bool:
    return role in WRITE_ROLES


def can_manage_users(role: str) -> bool:
    return role == ROLE_ADMIN
