"""Retained PCAP metadata, filesystem storage, quotas, and retention."""
from __future__ import annotations
import hashlib, os, re, tempfile, uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from .config import AuthConfig

_SAFE_ID = re.compile(r"^[A-Za-z0-9_.-]{1,160}$")

class StorageQuotaExceeded(RuntimeError):
    """Raised when retaining another capture would exceed the configured quota."""

class MongoCaptureStore:
    def __init__(self, config: AuthConfig) -> None:
        self.config=config; self._client=None; self._captures=None
        default_root=Path(__file__).resolve().parents[2]/"storage"
        self.root=Path(os.environ.get("ELEVADR_STORAGE_ROOT", str(default_root))).resolve()
    def connect(self)->None:
        try: from pymongo import ASCENDING, DESCENDING, MongoClient
        except ImportError as exc: raise RuntimeError("pymongo is required for retained captures") from exc
        self._client=MongoClient(self.config.mongodb_uri, serverSelectionTimeoutMS=3000); self._client.admin.command("ping")
        self._captures=self._client[self.config.mongodb_database]["captures"]
        self._captures.create_index([("owner_id",ASCENDING),("created_at",DESCENDING)],name="captures_owner_created")
        self._captures.create_index([("owner_id",ASCENDING),("sha256",ASCENDING)],unique=True,name="captures_owner_sha_unique")
        self._captures.create_index([("last_used_at",ASCENDING)],name="captures_last_used")
        self.root.mkdir(parents=True,exist_ok=True)
    def close(self)->None:
        if self._client is not None: self._client.close()
        self._client=None; self._captures=None
    @staticmethod
    def _safe(v:str,label:str)->str:
        if not _SAFE_ID.fullmatch(v): raise ValueError(f"Invalid {label}")
        return v
    def _owner_bytes(self, owner_id:str)->int:
        if self._captures is None: raise RuntimeError("Capture store is not connected")
        return sum(int(row.get("size_bytes",0) or 0) for row in self._captures.find({"owner_id":owner_id}))
    def save_bytes(self, owner_id:str, username:str, filename:str, data:bytes)->dict[str,Any]:
        if self._captures is None: raise RuntimeError("Capture store is not connected")
        owner=self._safe(owner_id,"owner id"); digest=hashlib.sha256(data).hexdigest()
        self.cleanup_expired(owner_id)
        existing=self._captures.find_one({"owner_id":owner_id,"sha256":digest})
        if existing:
            self._captures.update_one({"_id":existing["_id"]},{"$set":{"last_used_at":datetime.now(UTC)}})
            return self._public(self._captures.find_one({"_id":existing["_id"]}))
        limit=getattr(self.config,"pcap_storage_limit_bytes",0)
        if limit > 0 and self._owner_bytes(owner_id) + len(data) > limit:
            raise StorageQuotaExceeded("Retaining this PCAP would exceed the account storage limit")
        capture_id=uuid.uuid4().hex; suffix=".pcapng" if filename.lower().endswith(".pcapng") else ".pcap"
        directory=self.root/"users"/owner/"pcaps"; directory.mkdir(parents=True,exist_ok=True); path=directory/f"{capture_id}{suffix}"
        fd,tmp=tempfile.mkstemp(prefix=f".{capture_id}-",suffix=".tmp",dir=directory)
        try:
            with os.fdopen(fd,"wb") as h: h.write(data); h.flush(); os.fsync(h.fileno())
            os.replace(tmp,path)
        finally:
            if os.path.exists(tmp): os.unlink(tmp)
        now=datetime.now(UTC); doc={"capture_id":capture_id,"owner_id":owner_id,"owner_username":username,"filename":filename,"sha256":digest,"size_bytes":len(data),"capture_path":str(path.relative_to(self.root)),"created_at":now,"last_used_at":now}
        self._captures.insert_one(doc); return self._public(doc)
    def _public(self,doc:dict[str,Any]|None)->dict[str,Any]:
        if not doc: return {}
        iso=lambda v:v.isoformat().replace("+00:00","Z") if isinstance(v,datetime) else v
        last=doc.get("last_used_at"); expires=None
        if isinstance(last,datetime) and getattr(self.config,"pcap_retention_days",0) > 0: expires=last+timedelta(days=getattr(self.config,"pcap_retention_days",0))
        return {"captureId":str(doc.get("capture_id","")),"filename":str(doc.get("filename","")),"sha256":str(doc.get("sha256","")),"sizeBytes":int(doc.get("size_bytes",0) or 0),"createdAt":iso(doc.get("created_at")),"lastUsedAt":iso(last),"expiresAt":iso(expires)}
    def list_for_owner(self,owner_id:str,limit:int=100)->list[dict[str,Any]]:
        if self._captures is None: raise RuntimeError("Capture store is not connected")
        self.cleanup_expired(owner_id)
        return [self._public(x) for x in self._captures.find({"owner_id":owner_id}).sort("created_at",-1).limit(max(1,min(limit,500)))]
    def path_for_owner(self,owner_id:str,capture_id:str)->Path|None:
        if self._captures is None: raise RuntimeError("Capture store is not connected")
        capture_id=self._safe(capture_id,"capture id"); row=self._captures.find_one({"owner_id":owner_id,"capture_id":capture_id})
        if not row:return None
        path=(self.root/str(row["capture_path"])).resolve()
        if self.root not in path.parents: raise RuntimeError("Stored capture path escaped storage root")
        return path if path.exists() else None
    def get(self,owner_id:str,capture_id:str)->dict[str,Any]|None:
        if self._captures is None: raise RuntimeError("Capture store is not connected")
        row=self._captures.find_one({"owner_id":owner_id,"capture_id":self._safe(capture_id,"capture id")}); return self._public(row) if row else None
    def delete(self,owner_id:str,capture_id:str)->bool:
        if self._captures is None: raise RuntimeError("Capture store is not connected")
        capture_id=self._safe(capture_id,"capture id"); row=self._captures.find_one({"owner_id":owner_id,"capture_id":capture_id})
        if not row:return False
        path=(self.root/str(row["capture_path"])).resolve()
        if self.root in path.parents:path.unlink(missing_ok=True)
        self._captures.delete_one({"owner_id":owner_id,"capture_id":capture_id}); return True
    def cleanup_expired(self, owner_id:str|None=None)->dict[str,int]:
        if self._captures is None: raise RuntimeError("Capture store is not connected")
        if getattr(self.config,"pcap_retention_days",0) <= 0: return {"expiredCaptures":0,"bytesFreed":0}
        cutoff=datetime.now(UTC)-timedelta(days=getattr(self.config,"pcap_retention_days",0)); query={"last_used_at":{"$lt":cutoff}}
        if owner_id: query["owner_id"]=owner_id
        rows=list(self._captures.find(query)); count=0; freed=0
        for row in rows:
            path=(self.root/str(row.get("capture_path",""))).resolve()
            if self.root in path.parents: path.unlink(missing_ok=True)
            self._captures.delete_one({"_id":row.get("_id")}); count+=1; freed+=int(row.get("size_bytes",0) or 0)
        return {"expiredCaptures":count,"bytesFreed":freed}
    def find_orphans(self)->list[Path]:
        if self._captures is None: raise RuntimeError("Capture store is not connected")
        known={(self.root/str(r.get("capture_path",""))).resolve() for r in self._captures.find({})}
        base=self.root/"users"; found=[]
        if base.exists():
            for p in base.glob("*/pcaps/*"):
                if p.is_file() and not p.name.startswith(".") and p.resolve() not in known: found.append(p.resolve())
        return found
    def remove_orphans(self)->dict[str,int]:
        paths=self.find_orphans(); freed=0
        for p in paths:
            try: freed+=p.stat().st_size
            except OSError: pass
            p.unlink(missing_ok=True)
        return {"orphanFiles":len(paths),"bytesFreed":freed}
    def usage_for_owner(self,owner_id:str)->dict[str,Any]:
        rows=list(self._captures.find({"owner_id":owner_id})) if self._captures is not None else []
        used=sum(int(r.get("size_bytes",0) or 0) for r in rows); limit=getattr(self.config,"pcap_storage_limit_bytes",0)
        return {"ownerId":owner_id,"captureCount":len(rows),"captureBytes":used,"limitBytes":limit,"remainingBytes":max(0,limit-used) if limit>0 else None,"retentionDays":getattr(self.config,"pcap_retention_days",0)}
    def usage_all(self)->list[dict[str,Any]]:
        if self._captures is None: raise RuntimeError("Capture store is not connected")
        owners:dict[str,dict[str,Any]]={}
        for r in self._captures.find({}):
            oid=str(r.get("owner_id","")); row=owners.setdefault(oid,{"ownerId":oid,"username":str(r.get("owner_username","")),"captureCount":0,"captureBytes":0})
            row["captureCount"]+=1; row["captureBytes"]+=int(r.get("size_bytes",0) or 0)
        limit=getattr(self.config,"pcap_storage_limit_bytes",0)
        for row in owners.values(): row.update({"limitBytes":limit,"remainingBytes":max(0,limit-row["captureBytes"]) if limit>0 else None,"retentionDays":getattr(self.config,"pcap_retention_days",0)})
        return sorted(owners.values(),key=lambda x:(-x["captureBytes"],x["ownerId"]))
