"""Regression coverage for Stage 3 owner identity wiring."""
from __future__ import annotations

from pathlib import Path

from backend_bryan.auth.models import AuthPrincipal


def test_stage3_uses_real_auth_principal_user_id_contract() -> None:
    principal = AuthPrincipal("user-123", "analyst", True, "analyst")
    assert principal.user_id == "user-123"
    assert principal.as_dict()["id"] == "user-123"
    assert not hasattr(principal, "id")

    server = (Path(__file__).resolve().parents[1] / "integration" / "http_reference_server.py").read_text(encoding="utf-8")
    assert "principal.id" not in server
    assert "principal.user_id" in server
