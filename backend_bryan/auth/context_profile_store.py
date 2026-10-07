"""Owner-scoped MongoDB persistence for reusable Analysis Context profiles."""
from __future__ import annotations
from datetime import UTC, datetime
from typing import Any
from .config import AuthConfig

class MongoContextProfileStore:
    def __init__(self, config: AuthConfig): self.config=config; self._client=None; self._profiles=None
    def connect(self)->None:
        from pymongo import ASCENDING, DESCENDING, MongoClient
        self._client=MongoClient(self.config.mongodb_uri, serverSelectionTimeoutMS=3000); self._client.admin.command("ping")
        self._profiles=self._client[self.config.mongodb_database]["context_profiles"]
        self._profiles.create_index([("owner_id",ASCENDING),("profile_id",ASCENDING)],unique=True,name="context_profiles_owner_id")
        self._profiles.create_index([("owner_id",ASCENDING),("updated_at",DESCENDING)],name="context_profiles_owner_updated")
    def close(self)->None:
        if self._client is not None: self._client.close()
    def list_for_owner(self, owner_id:str)->list[dict[str,Any]]:
        if self._profiles is None: raise RuntimeError("Context profile store is not connected")
        return [dict(row.get("profile") or {}) for row in self._profiles.find({"owner_id":owner_id}).sort("updated_at",-1)]
    def save(self, owner_id:str, owner_username:str, profile:dict[str,Any])->dict[str,Any]:
        if self._profiles is None: raise RuntimeError("Context profile store is not connected")
        pid=str(profile.get("id") or "").strip(); name=str(profile.get("name") or "").strip()
        if not pid or not name: raise ValueError("Profile id and name are required")
        now=datetime.now(UTC); clean=dict(profile); clean["id"]=pid; clean["name"]=name; clean["updatedAt"]=now.isoformat().replace("+00:00","Z")
        self._profiles.update_one({"owner_id":owner_id,"profile_id":pid},{"$set":{"owner_username":owner_username,"profile":clean,"updated_at":now},"$setOnInsert":{"created_at":now}},upsert=True)
        return clean
    def delete(self, owner_id:str, profile_id:str)->bool:
        if self._profiles is None: raise RuntimeError("Context profile store is not connected")
        return self._profiles.delete_one({"owner_id":owner_id,"profile_id":profile_id}).deleted_count==1
