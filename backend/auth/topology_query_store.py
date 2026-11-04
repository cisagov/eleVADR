"""Owner-scoped MongoDB storage for validated topology query definitions."""
from __future__ import annotations
from datetime import UTC, datetime
from uuid import uuid4

ALLOWED_FIELDS = {"type", "subnet", "purdueLevel", "roleGroup", "service", "suspicious", "findingRelated", "minCount", "startAsset", "maxHops", "direction"}

def validate_query(query):
    if not isinstance(query, dict): raise ValueError("Query must be an object")
    if set(query) - ALLOWED_FIELDS: raise ValueError("Unknown query field")
    clean = {}
    for field, value in query.items():
        if field in {"suspicious", "findingRelated"}:
            if not isinstance(value, bool): raise ValueError(field + " must be a boolean")
        elif field == "maxHops":
            if type(value) is not int or not 1 <= value <= 4: raise ValueError("maxHops must be 1-4")
        elif field == "direction":
            if value not in ("both", "outbound", "inbound"): raise ValueError("Invalid traversal direction")
        elif field == "minCount":
            if type(value) is not int or not 1 <= value <= 100000000: raise ValueError("Invalid minimum count")
        elif not isinstance(value, str) or not 0 < len(value.strip()) <= 120:
            raise ValueError("Invalid query value: " + field)
        clean[field] = value
    return clean

class MongoTopologyQueryStore:
    def __init__(self, config): self.config=config; self.client=None; self.collection=None
    def connect(self):
        from pymongo import MongoClient, ASCENDING, DESCENDING
        self.client=MongoClient(self.config.mongodb_uri, serverSelectionTimeoutMS=3000)
        self.client.admin.command("ping")
        self.collection=self.client[self.config.mongodb_database]["topology_saved_queries"]
        self.collection.create_index([("owner_id", ASCENDING), ("query_id", ASCENDING)], unique=True)
        self.collection.create_index([("owner_id", ASCENDING), ("updated_at", DESCENDING)])
    def close(self):
        if self.client is not None: self.client.close()
    def list_for_owner(self, owner_id):
        return [row["data"] for row in self.collection.find({"owner_id":owner_id}).sort("updated_at",-1).limit(100)]
    def save(self, owner_id, payload):
        if not isinstance(payload,dict): raise ValueError("Invalid query payload")
        name=payload.get("name")
        if not isinstance(name,str) or not 0 < len(name.strip()) <= 100: raise ValueError("Query name must be 1-100 characters")
        query=validate_query(payload.get("query"))
        query_id=payload.get("id") or str(uuid4())
        if not isinstance(query_id,str) or len(query_id)>100 or not query_id or any(ch in query_id for ch in ("/", "\\", "$", ".", "\x00")): raise ValueError("Invalid query id")
        now=datetime.now(UTC)
        data={"id":query_id,"name":name.strip(),"query":query,"updatedAt":now.isoformat()}
        self.collection.update_one({"owner_id":owner_id,"query_id":query_id},{"$set":{"data":data,"updated_at":now}},upsert=True)
        return data
    def delete(self, owner_id, query_id):
        return self.collection.delete_one({"owner_id":owner_id,"query_id":query_id}).deleted_count == 1
