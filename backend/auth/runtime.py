"""Process-level authentication runtime used by the local reference server."""
from __future__ import annotations

from .config import load_auth_config
from .database import MongoUserStore
from .service import AuthenticationService


def build_auth_service() -> AuthenticationService:
    config = load_auth_config()
    if not config.enabled:
        return AuthenticationService(config)
    store = MongoUserStore(config)
    store.connect()
    return AuthenticationService(config, store)
