from __future__ import annotations

from backend_bryan.auth.config import AuthConfig
from backend_bryan.auth.models import ANONYMOUS_PRINCIPAL, AuthPrincipal
from backend_bryan.integration import http_reference_server as server


class FakeAuthService:
    def __init__(self, enabled: bool) -> None:
        self.config = AuthConfig(enabled=enabled, jwt_secret=("x" * 32 if enabled else ""))

    def current_principal(self, authorization: str | None) -> AuthPrincipal:
        if not self.config.enabled:
            return ANONYMOUS_PRINCIPAL
        if authorization != "Bearer valid-token":
            raise PermissionError("Authentication required")
        return AuthPrincipal("user-1", "analyst", True, "analyst")


def handler_with(auth_header: str | None):
    handler = object.__new__(server.Handler)
    handler.headers = {} if auth_header is None else {"Authorization": auth_header}
    responses: list[tuple[int, object]] = []
    handler._json = lambda status, payload: responses.append((status, payload))
    return handler, responses


def test_protected_boundary_is_transparent_when_auth_disabled(monkeypatch) -> None:
    monkeypatch.setattr(server, "_AUTH_SERVICE", FakeAuthService(False))
    handler, responses = handler_with(None)
    assert handler._require_authenticated_request() is True
    assert responses == []


def test_protected_boundary_fails_closed_without_bearer_token(monkeypatch) -> None:
    monkeypatch.setattr(server, "_AUTH_SERVICE", FakeAuthService(True))
    handler, responses = handler_with(None)
    assert handler._require_authenticated_request() is False
    assert responses[0][0] == 401
    assert responses[0][1]["error"] == "authentication_required"


def test_protected_boundary_accepts_valid_bearer_token(monkeypatch) -> None:
    monkeypatch.setattr(server, "_AUTH_SERVICE", FakeAuthService(True))
    handler, responses = handler_with("Bearer valid-token")
    assert handler._require_authenticated_request() is True
    assert responses == []


def test_login_http_contract_exposes_documented_snake_case_fields(monkeypatch) -> None:
    class LoginAuthService(FakeAuthService):
        def login(self, username: str, password: str):
            assert username == "bryan"
            assert password == "correct-password"
            return AuthPrincipal("user-1", "bryan", True, "admin"), "signed-jwt"

    monkeypatch.setattr(server, "_AUTH_SERVICE", LoginAuthService(True))
    handler = object.__new__(server.Handler)
    handler.path = server.AUTH_LOGIN_PATH
    handler.headers = {"Content-Length": "2"}
    handler._read_json = lambda: {"username": "bryan", "password": "correct-password"}
    responses: list[tuple[int, object]] = []
    handler._json = lambda status, payload: responses.append((status, payload))

    handler.do_POST()

    status, payload = responses[-1]
    assert status == 200
    assert payload["access_token"] == "signed-jwt"
    assert payload["token_type"] == "bearer"
    assert payload["expires_in"] == 3600
    assert payload["user"]["username"] == "bryan"
    # Compatibility aliases remain during Stage 1 so the initial candidate does
    # not break any local client that already consumed the camelCase response.
    assert payload["accessToken"] == payload["access_token"]
    assert payload["tokenType"] == payload["token_type"]
    assert payload["expiresIn"] == payload["expires_in"]
