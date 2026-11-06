"""MongoDB-backed security/activity audit trail for the eleVADR platform."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
import re

from .config import AuthConfig

_SENSITIVE = re.compile(r"password|token|secret|authorization|cookie|credential|pcap.*content|raw.*pcap", re.I)
_ALLOWED_RESULTS = {"success", "failure", "denied"}


def sanitize_metadata(value: Any, *, depth: int = 0) -> Any:
    """Return bounded audit metadata with secret-like fields removed."""
    if depth > 4:
        return "[truncated]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value[:512]
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in list(value.items())[:32]:
            key_s = str(key)[:80]
            if _SENSITIVE.search(key_s):
                out[key_s] = "[redacted]"
            else:
                out[key_s] = sanitize_metadata(item, depth=depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        return [sanitize_metadata(item, depth=depth + 1) for item in list(value)[:32]]
    return str(value)[:512]


@dataclass(slots=True)
class MongoAuditStore:
    config: AuthConfig
    retention_days: int = 180
    _client: Any = None
    _events: Any = None

    def connect(self) -> None:
        try:
            from pymongo import ASCENDING, DESCENDING, MongoClient
        except ImportError as exc:
            raise RuntimeError("pymongo is required when eleVADR audit history is enabled") from exc
        self._client = MongoClient(self.config.mongodb_uri, serverSelectionTimeoutMS=3000)
        self._client.admin.command("ping")
        self._events = self._client[self.config.mongodb_database]["audit_events"]
        self._events.create_index([("created_at", DESCENDING)], name="audit_created_desc")
        self._events.create_index([("actor_id", ASCENDING), ("created_at", DESCENDING)], name="audit_actor_created")
        self._events.create_index([("created_at", ASCENDING)], expireAfterSeconds=self.retention_days * 86400, name="audit_retention_ttl")

    def record(self, *, action: str, result: str, actor_id: str | None = None, actor_username: str | None = None,
               target_type: str | None = None, target_id: str | None = None, metadata: dict[str, Any] | None = None) -> None:
        if self._events is None:
            return
        if result not in _ALLOWED_RESULTS:
            raise ValueError("Invalid audit result")
        self._events.insert_one({
            "created_at": datetime.now(UTC), "actor_id": actor_id, "actor_username": (actor_username or "")[:128],
            "action": action[:128], "result": result, "target_type": (target_type or "")[:64],
            "target_id": (target_id or "")[:160], "metadata": sanitize_metadata(metadata or {}),
        })

    @staticmethod
    def _public(record: dict[str, Any]) -> dict[str, Any]:
        created = record.get("created_at")
        return {"eventId": str(record.get("_id", "")), "createdAt": created.isoformat() if hasattr(created, "isoformat") else None,
                "actorId": record.get("actor_id"), "actorUsername": record.get("actor_username") or "",
                "action": record.get("action") or "", "result": record.get("result") or "",
                "targetType": record.get("target_type") or "", "targetId": record.get("target_id") or "",
                "metadata": sanitize_metadata(record.get("metadata") or {})}

    def list_for_actor(self, actor_id: str, limit: int = 50) -> list[dict[str, Any]]:
        if self._events is None: return []
        limit = max(1, min(int(limit), 200))
        return [self._public(r) for r in self._events.find({"actor_id": actor_id}).sort("created_at", -1).limit(limit)]

    def list_all(self, limit: int = 100) -> list[dict[str, Any]]:
        if self._events is None: return []
        limit = max(1, min(int(limit), 500))
        return [self._public(r) for r in self._events.find({}).sort("created_at", -1).limit(limit)]

    def close(self) -> None:
        if self._client is not None: self._client.close()
        self._client = None; self._events = None
