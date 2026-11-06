"""MongoDB-backed user repository with lazy optional dependency loading."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from .config import AuthConfig
from .models import AuthPrincipal


class UserStore(Protocol):
    def authenticate(self, username: str, password: str) -> AuthPrincipal | None: ...
    def principal_by_id(self, user_id: str) -> AuthPrincipal | None: ...
    def list_users(self) -> list[dict[str, object]]: ...
    def create_user(self, username: str, password: str, role: str, email: str = "") -> dict[str, object]: ...
    def update_user(self, user_id: str, *, role: str | None = None, disabled: bool | None = None) -> dict[str, object] | None: ...
    def change_password(self, user_id: str, current_password: str, new_password: str) -> bool: ...
    def revoke_sessions(self, user_id: str) -> None: ...
    def close(self) -> None: ...


def ensure_user_indexes(users: Any) -> None:
    """Create/migrate user indexes without treating missing email as a duplicate."""
    ascending = 1  # pymongo.ASCENDING; keep index migration testable without importing pymongo.

    users.create_index([("username_normalized", ascending)], unique=True, name="users_username_unique")
    desired_partial = {"email_normalized": {"$type": "string"}}
    existing = users.index_information().get("users_email_unique")
    if existing is not None:
        # Earlier Stage 1 builds used sparse=True while also storing null, which
        # still permits only one null value in a unique index. Replace that
        # index with a partial unique index that indexes actual strings only.
        if existing.get("partialFilterExpression") != desired_partial:
            users.drop_index("users_email_unique")
    users.create_index(
        [("email_normalized", ascending)],
        unique=True,
        name="users_email_unique",
        partialFilterExpression=desired_partial,
    )


@dataclass(slots=True)
class MongoUserStore:
    """Minimal MongoDB user store used by Stage 1 authentication."""

    config: AuthConfig
    _client: Any = None
    _users: Any = None

    def connect(self) -> None:
        try:
            from pymongo import MongoClient
        except ImportError as exc:
            raise RuntimeError("pymongo is required when eleVADR authentication is enabled") from exc
        self._client = MongoClient(self.config.mongodb_uri, serverSelectionTimeoutMS=3000)
        self._client.admin.command("ping")
        database = self._client[self.config.mongodb_database]
        self._users = database["users"]
        ensure_user_indexes(self._users)

    def authenticate(self, username: str, password: str) -> AuthPrincipal | None:
        from .security import dummy_password_hash, verify_password
        if self._users is None:
            raise RuntimeError("MongoUserStore is not connected")
        normalized = username.strip().lower()
        if not normalized or not password:
            verify_password(password or "", dummy_password_hash())
            return None
        record = self._users.find_one({"username_normalized": normalized, "disabled": {"$ne": True}})
        password_hash = str(record.get("password_hash", "")) if record else dummy_password_hash()
        password_valid = verify_password(password, password_hash)
        if not record or not password_valid:
            return None
        self._users.update_one({"_id": record["_id"]}, {"$set": {"last_login": datetime.now(UTC)}})
        return AuthPrincipal(
            str(record["_id"]),
            str(record.get("username", username)),
            True,
            str(record.get("role", "analyst")),
            int(record.get("session_version", 0)),
        )

    @staticmethod
    def _public_user(record: dict[str, Any]) -> dict[str, object]:
        return {
            "id": str(record["_id"]),
            "username": str(record.get("username", "")),
            "email": str(record.get("email") or ""),
            "role": str(record.get("role", "analyst")),
            "disabled": bool(record.get("disabled", False)),
            "created": record.get("created").isoformat() if hasattr(record.get("created"), "isoformat") else None,
            "lastLogin": record.get("last_login").isoformat() if hasattr(record.get("last_login"), "isoformat") else None,
        }

    def principal_by_id(self, user_id: str) -> AuthPrincipal | None:
        if self._users is None:
            raise RuntimeError("MongoUserStore is not connected")
        try:
            from bson import ObjectId
            query_id: Any = ObjectId(user_id)
        except Exception:
            return None
        record = self._users.find_one({"_id": query_id, "disabled": {"$ne": True}})
        if not record:
            return None
        return AuthPrincipal(str(record["_id"]), str(record.get("username", "")), True, str(record.get("role", "analyst")), int(record.get("session_version", 0)))

    def list_users(self) -> list[dict[str, object]]:
        if self._users is None:
            raise RuntimeError("MongoUserStore is not connected")
        return [self._public_user(record) for record in self._users.find({}).sort("username_normalized", 1)]

    def create_user(self, username: str, password: str, role: str, email: str = "") -> dict[str, object]:
        from .security import hash_password
        if self._users is None:
            raise RuntimeError("MongoUserStore is not connected")
        username = username.strip()
        email = email.strip()
        if not username or len(username) > 128:
            raise ValueError("Username must contain 1 to 128 characters")
        if role not in {"admin", "analyst", "read_only"}:
            raise ValueError("Invalid user role")
        now = datetime.now(UTC)
        document = {"username": username, "username_normalized": username.lower(), "password_hash": hash_password(password), "role": role, "disabled": False, "session_version": 0, "created": now, "updated": now}
        if email:
            document["email"] = email
            document["email_normalized"] = email.lower()
        try:
            result = self._users.insert_one(document)
        except Exception as exc:
            if exc.__class__.__name__ == "DuplicateKeyError":
                raise ValueError("Username or email already exists") from exc
            raise
        document["_id"] = result.inserted_id
        return self._public_user(document)

    def update_user(self, user_id: str, *, role: str | None = None, disabled: bool | None = None) -> dict[str, object] | None:
        if self._users is None:
            raise RuntimeError("MongoUserStore is not connected")
        try:
            from bson import ObjectId
            query_id: Any = ObjectId(user_id)
        except Exception:
            return None
        changes: dict[str, object] = {"updated": datetime.now(UTC)}
        if role is not None:
            if role not in {"admin", "analyst", "read_only"}: raise ValueError("Invalid user role")
            changes["role"] = role
        if disabled is not None:
            changes["disabled"] = bool(disabled)
            if disabled:
                changes["session_version"] = int((self._users.find_one({"_id": query_id}) or {}).get("session_version", 0)) + 1
        record = self._users.find_one_and_update({"_id": query_id}, {"$set": changes}, return_document=True)
        return self._public_user(record) if record else None

    def change_password(self, user_id: str, current_password: str, new_password: str) -> bool:
        from .security import hash_password, verify_password
        if self._users is None:
            raise RuntimeError("MongoUserStore is not connected")
        try:
            from bson import ObjectId
            query_id: Any = ObjectId(user_id)
        except Exception:
            return False
        record = self._users.find_one({"_id": query_id, "disabled": {"$ne": True}})
        if not record or not verify_password(current_password, str(record.get("password_hash", ""))): return False
        self._users.update_one({"_id": query_id}, {"$set": {"password_hash": hash_password(new_password), "updated": datetime.now(UTC)}, "$inc": {"session_version": 1}})
        return True

    def revoke_sessions(self, user_id: str) -> None:
        if self._users is None:
            raise RuntimeError("MongoUserStore is not connected")
        try:
            from bson import ObjectId
            query_id: Any = ObjectId(user_id)
        except Exception:
            return
        self._users.update_one({"_id": query_id}, {"$inc": {"session_version": 1}, "$set": {"updated": datetime.now(UTC)}})

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
        self._client = None
        self._users = None
