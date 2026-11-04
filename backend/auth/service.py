"""Authentication service kept separate from the analysis engine."""
from __future__ import annotations

from .config import AuthConfig
from .database import UserStore
from .models import ANONYMOUS_PRINCIPAL, AuthPrincipal
from .security import create_access_token, decode_access_token


class AuthenticationService:
    def __init__(self, config: AuthConfig, user_store: UserStore | None = None) -> None:
        self.config = config
        self.user_store = user_store

    def current_principal(self, authorization: str | None) -> AuthPrincipal:
        if not self.config.enabled:
            return ANONYMOUS_PRINCIPAL
        if not authorization or not authorization.startswith("Bearer "):
            raise PermissionError("Authentication required")
        principal = decode_access_token(authorization[7:].strip(), self.config)
        if self.user_store is not None and hasattr(self.user_store, "principal_by_id"):
            current = self.user_store.principal_by_id(str(principal.user_id or ""))
            if current is None or current.session_version != principal.session_version:
                raise PermissionError("Authentication required")
            return current
        return principal

    def login(self, username: str, password: str) -> tuple[AuthPrincipal, str]:
        if not self.config.enabled:
            raise RuntimeError("Authentication is disabled")
        if self.user_store is None:
            raise RuntimeError("Authentication user store is unavailable")
        principal = self.user_store.authenticate(username, password)
        if principal is None:
            raise PermissionError("Invalid username or password")
        return principal, create_access_token(principal, self.config)

    def list_users(self, principal: AuthPrincipal) -> list[dict[str, object]]:
        if principal.role != "admin" or self.user_store is None: raise PermissionError("Administrator access required")
        return self.user_store.list_users()

    def create_user(self, principal: AuthPrincipal, username: str, password: str, role: str, email: str = "") -> dict[str, object]:
        if principal.role != "admin" or self.user_store is None: raise PermissionError("Administrator access required")
        return self.user_store.create_user(username, password, role, email)

    def update_user(self, principal: AuthPrincipal, user_id: str, *, role: str | None = None, disabled: bool | None = None) -> dict[str, object] | None:
        if principal.role != "admin" or self.user_store is None: raise PermissionError("Administrator access required")
        if principal.user_id == user_id and disabled is True: raise ValueError("You cannot disable your own active account")
        return self.user_store.update_user(user_id, role=role, disabled=disabled)

    def change_password(self, principal: AuthPrincipal, current_password: str, new_password: str) -> None:
        if self.user_store is None or not principal.user_id: raise RuntimeError("Authentication user store is unavailable")
        if not self.user_store.change_password(principal.user_id, current_password, new_password): raise PermissionError("Current password is incorrect")

    def logout(self, principal: AuthPrincipal) -> None:
        if self.user_store is not None and principal.user_id and hasattr(self.user_store, "revoke_sessions"):
            self.user_store.revoke_sessions(principal.user_id)

    def close(self) -> None:
        if self.user_store is not None:
            self.user_store.close()
