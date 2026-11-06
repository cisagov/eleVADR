"""Owner-scoped, bounded saved comparison settings. No report contents are stored."""
from datetime import UTC, datetime
from uuid import uuid4

STATUSES = {"All", "New", "Not observed", "Count changed"}


def validate_comparison(payload):
    if not isinstance(payload, dict):
        raise ValueError("Comparison must be an object")
    if set(payload) - {"id", "name", "currentReportId", "baselineId", "filter", "findingsOnly", "queryOnly"}:
        raise ValueError("Unexpected comparison field")
    name = payload.get("name")
    if not isinstance(name, str) or not 1 <= len(name.strip()) <= 100:
        raise ValueError("Comparison name must be 1-100 characters")
    comparison_id = payload.get("id") or str(uuid4())
    if not isinstance(comparison_id, str) or not 1 <= len(comparison_id) <= 100 or any(c in comparison_id for c in ('/', '\\', '$', '.', '\x00')):
        raise ValueError("Invalid comparison id")
    result = {"id": comparison_id, "name": name.strip()}
    for key in ("currentReportId", "baselineId"):
        value = payload.get(key)
        if not isinstance(value, str) or not 1 <= len(value.strip()) <= 200:
            raise ValueError(f"Invalid {key}")
        result[key] = value.strip()
    value = payload.get("filter", "All")
    if value not in STATUSES:
        raise ValueError("Invalid comparison filter")
    result["filter"] = value
    for key in ("findingsOnly", "queryOnly"):
        value = payload.get(key, False)
        if not isinstance(value, bool):
            raise ValueError(f"{key} must be boolean")
        result[key] = value
    return result


class MongoTopologyComparisonStore:
    def __init__(self, config):
        self.config = config
        self.client = None
        self.collection = None

    def connect(self):
        from pymongo import ASCENDING, DESCENDING, MongoClient
        self.client = MongoClient(self.config.mongodb_uri, serverSelectionTimeoutMS=3000)
        self.client.admin.command("ping")
        self.collection = self.client[self.config.mongodb_database]["topology_saved_comparisons"]
        self.collection.create_index([("owner_id", ASCENDING), ("comparison_id", ASCENDING)], unique=True)
        self.collection.create_index([("owner_id", ASCENDING), ("updated_at", DESCENDING)])

    def close(self):
        if self.client is not None:
            self.client.close()

    def list_for_owner(self, owner_id):
        return [item["data"] for item in self.collection.find({"owner_id": owner_id}).sort("updated_at", -1).limit(100)]

    def save(self, owner_id, payload):
        data = validate_comparison(payload)
        now = datetime.now(UTC)
        data["updatedAt"] = now.isoformat()
        self.collection.update_one(
            {"owner_id": owner_id, "comparison_id": data["id"]},
            {"$set": {"data": data, "updated_at": now}}, upsert=True,
        )
        return data

    def delete(self, owner_id, comparison_id):
        return self.collection.delete_one({"owner_id": owner_id, "comparison_id": comparison_id}).deleted_count == 1
