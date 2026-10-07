from __future__ import annotations

import pytest

from backend_bryan.auth.permissions import can_manage_users, can_view, can_write


@pytest.mark.parametrize(
    ("role", "view", "write", "manage"),
    [
        ("admin", True, True, True),
        ("analyst", True, True, False),
        ("read_only", True, False, False),
        ("anonymous", False, False, False),
    ],
)
def test_role_capability_matrix(role, view, write, manage):
    assert can_view(role) is view
    assert can_write(role) is write
    assert can_manage_users(role) is manage


@pytest.mark.parametrize("role", ["read_only", "anonymous", "", "ADMIN"])
def test_non_write_roles_cannot_mutate(role):
    assert can_write(role) is False


@pytest.mark.parametrize("role", ["analyst", "read_only", "anonymous", ""])
def test_only_admin_can_manage_users(role):
    assert can_manage_users(role) is False
