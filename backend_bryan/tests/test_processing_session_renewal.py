"""Processing-session renewal policy regression tests."""
from datetime import UTC, datetime

import pytest

from backend_bryan.auth.config import AuthConfig
from backend_bryan.auth.models import AuthPrincipal
from backend_bryan.auth.security import create_access_token, decode_access_token


def test_renewal_deadline_is_preserved():
    jwt = pytest.importorskip("jwt")
    config = AuthConfig(jwt_secret="x" * 40)
    principal = AuthPrincipal("u1", "analyst", True, "analyst")
    original = create_access_token(principal, config)
    original_claims = jwt.decode(original, config.jwt_secret, algorithms=["HS256"], issuer="elevadr")
    deadline = original_claims["renew_until"]
    assert deadline > int(datetime.now(UTC).timestamp())
    renewed = create_access_token(decode_access_token(original, config), config, renew_until=deadline)
    renewed_claims = jwt.decode(renewed, config.jwt_secret, algorithms=["HS256"], issuer="elevadr")
    assert renewed_claims["renew_until"] == deadline
    assert renewed_claims["sub"] == "u1"
