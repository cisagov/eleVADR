"""Stage 3 persisted report metadata and filesystem report storage."""
from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .config import AuthConfig

_SAFE_ID = re.compile(r"^[A-Za-z0-9_.-]{1,160}$")


def _report_device_count(report: dict[str, Any]) -> int:
    """Count devices using the same OT/IT/Edge inventories as the viewer."""
    modules = report.get("modules")
    if not isinstance(modules, dict):
        return 0
    return sum(
        len(modules[key])
        for key in ("ot_devices", "it_devices", "edge_devices")
        if isinstance(modules.get(key), list)
    )



def _report_service_count(report: dict[str, Any]) -> int:
    """Count distinct observed services from the report service inventory."""
    modules = report.get("modules")
    if not isinstance(modules, dict):
        return 0
    panel = modules.get("service_count_panel")
    if isinstance(panel, dict) and isinstance(panel.get("service_count"), int):
        return max(0, panel["service_count"])
    panel = modules.get("service_panel")
    if isinstance(panel, dict):
        known, unknown = panel.get("num_known_services"), panel.get("num_unknown_services")
        if isinstance(known, int) and isinstance(unknown, int):
            return max(0, known + unknown)
    return 0


def _report_connection_count(report: dict[str, Any]) -> int:
    """Count observed connection records, not finding connection pairs."""
    modules = report.get("modules")
    if not isinstance(modules, dict):
        return 0
    panel = modules.get("connection_success_panel")
    if isinstance(panel, dict):
        records = panel.get("connections")
        if isinstance(records, list):
            return len(records)
        summary = panel.get("summary")
        if isinstance(summary, dict):
            successful = summary.get("successful_count")
            unsuccessful = summary.get("unsuccessful_count")
            if isinstance(successful, int) and isinstance(unsuccessful, int):
                return max(0, successful + unsuccessful)
    return 0


class MongoReportStore:
    def __init__(self, config: AuthConfig) -> None:
        self.config = config
        self._client: Any = None
        self._reports: Any = None
        default_root = Path(__file__).resolve().parents[2] / "storage"
        self.root = Path(os.environ.get("ELEVADR_STORAGE_ROOT", str(default_root))).resolve()

    def connect(self) -> None:
        try:
            from pymongo import ASCENDING, DESCENDING, MongoClient
        except ImportError as exc:
            raise RuntimeError("pymongo is required for persisted reports") from exc
        self._client = MongoClient(self.config.mongodb_uri, serverSelectionTimeoutMS=3000)
        self._client.admin.command("ping")
        self._reports = self._client[self.config.mongodb_database]["reports"]
        self._reports.create_index([("owner_id", ASCENDING), ("created_at", DESCENDING)], name="reports_owner_created")
        self._reports.create_index([("owner_id", ASCENDING), ("report_id", ASCENDING)], unique=True, name="reports_owner_report_unique")
        self.root.mkdir(parents=True, exist_ok=True)

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
        self._client = None
        self._reports = None

    @staticmethod
    def _safe(value: str, label: str) -> str:
        if not _SAFE_ID.fullmatch(value):
            raise ValueError(f"Invalid {label}")
        return value

    def save(self, owner_id: str, username: str, report: dict[str, Any], source_filename: str, capture_id: str | None = None) -> dict[str, Any]:
        if self._reports is None:
            raise RuntimeError("Report store is not connected")
        owner = self._safe(owner_id, "owner id")
        report_id = self._safe(str(report.get("report_id") or ""), "report id")
        directory = self.root / "users" / owner / "reports"
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{report_id}.json"
        payload = json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        fd, temp_name = tempfile.mkstemp(prefix=f".{report_id}-", suffix=".tmp", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, path)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)
        now = datetime.now(UTC)
        findings = report.get("arch_insights", {}).get("detector_findings", []) if isinstance(report.get("arch_insights"), dict) else []
        doc = {
            "owner_id": owner_id,
            "owner_username": username,
            "report_id": report_id,
            "source_filename": source_filename,
            "updated_at": now,
            "report_path": str(path.relative_to(self.root)),
            "report_version": str(report.get("report_version") or report.get("version") or ""),
            "finding_count": len(findings) if isinstance(findings, list) else 0,
            "device_count": _report_device_count(report),
            "service_count": _report_service_count(report),
            "connection_count": _report_connection_count(report),
            "capture_id": capture_id,
        }
        query = {"owner_id": owner_id, "report_id": report_id}
        self._reports.update_one(
            query,
            {"$set": doc, "$setOnInsert": {"created_at": now, "title": source_filename or report_id}},
            upsert=True,
        )
        stored = self._reports.find_one(query)
        if not stored:
            raise RuntimeError("Persisted report metadata could not be reloaded")
        return self._public(stored)

    @staticmethod
    def _public(doc: dict[str, Any]) -> dict[str, Any]:
        def iso(value: Any) -> Any:
            return value.isoformat().replace("+00:00", "Z") if isinstance(value, datetime) else value
        return {
            "reportId": str(doc.get("report_id", "")),
            "title": str(doc.get("title") or doc.get("source_filename") or doc.get("report_id", "")),
            "sourceFilename": str(doc.get("source_filename", "")),
            "createdAt": iso(doc.get("created_at")),
            "updatedAt": iso(doc.get("updated_at")),
            "reportVersion": str(doc.get("report_version", "")),
            "findingCount": int(doc.get("finding_count", 0) or 0),
            "deviceCount": int(doc.get("device_count", 0) or 0),
            "serviceCount": int(doc.get("service_count", 0) or 0),
            "connectionCount": int(doc.get("connection_count", 0) or 0),
            "captureId": str(doc.get("capture_id") or ""),
        }

    def list_for_owner(self, owner_id: str, limit: int = 100) -> list[dict[str, Any]]:
        if self._reports is None:
            raise RuntimeError("Report store is not connected")
        rows = self._reports.find({"owner_id": owner_id}).sort("created_at", -1).limit(max(1, min(limit, 500)))
        return [self._public(row) for row in rows]

    def repair_device_counts_for_owner(self, owner_id: str, *, dry_run: bool = True) -> dict[str, int]:
        """Reconcile legacy metadata from retained JSON; never change report files.

        Explicit maintenance operation, not part of normal listing.
        Missing or invalid report files are skipped without replacing counts with zero.
        """
        if self._reports is None:
            raise RuntimeError("Report store is not connected")
        owner = self._safe(owner_id, "owner id")
        stats = {"checked": 0, "different": 0, "updated": 0, "skipped": 0}
        for row in self._reports.find({"owner_id": owner}):
            stats["checked"] += 1
            try:
                report_id = self._safe(str(row["report_id"]), "report id")
                candidate = (self.root / str(row["report_path"])).resolve()
                expected = (self.root / "users" / owner / "reports" / f"{report_id}.json").resolve()
                if candidate != expected or self.root not in candidate.parents:
                    raise ValueError("Stored report path is not the expected owner path")
                report = json.loads(candidate.read_text(encoding="utf-8"))
                if not isinstance(report, dict) or report.get("report_id") != report_id:
                    raise ValueError("Stored report identity does not match metadata")
                modules = report.get("modules")
                if not isinstance(modules, dict) or not all(
                    isinstance(modules.get(key), list)
                    for key in ("ot_devices", "it_devices", "edge_devices")
                ):
                    raise ValueError("Report does not contain a complete device inventory")
                count = _report_device_count(report)
            except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
                stats["skipped"] += 1
                continue
            if row.get("device_count") == count:
                continue
            stats["different"] += 1
            if not dry_run:
                self._reports.update_one(
                    {"owner_id": owner, "report_id": report_id},
                    {"$set": {"device_count": count}},
                )
                stats["updated"] += 1
        return stats

    def repair_activity_counts_for_owner(self, owner_id: str, *, dry_run: bool = True) -> dict[str, int]:
        """Reconcile service and connection counts without modifying report JSON.

        Requires an exact owner-scoped report path and usable inventory panels.
        """
        if self._reports is None:
            raise RuntimeError("Report store is not connected")
        owner = self._safe(owner_id, "owner id")
        stats = {"checked": 0, "different": 0, "updated": 0, "skipped": 0}
        for row in self._reports.find({"owner_id": owner}):
            stats["checked"] += 1
            try:
                report_id = self._safe(str(row["report_id"]), "report id")
                candidate = (self.root / str(row["report_path"])).resolve()
                expected = (self.root / "users" / owner / "reports" / f"{report_id}.json").resolve()
                if candidate != expected or self.root not in candidate.parents:
                    raise ValueError("Report path does not match owner-scoped path")
                report = json.loads(candidate.read_text(encoding="utf-8"))
                if not isinstance(report, dict) or report.get("report_id") != report_id:
                    raise ValueError("Stored report identity mismatch")
                modules = report.get("modules")
                if not isinstance(modules, dict):
                    raise ValueError("No report modules")
                service_panel = modules.get("service_count_panel")
                service_fallback = modules.get("service_panel")
                connection_panel = modules.get("connection_success_panel")
                if not (
                    (isinstance(service_panel, dict) and isinstance(service_panel.get("service_count"), int))
                    or (isinstance(service_fallback, dict)
                        and isinstance(service_fallback.get("num_known_services"), int)
                        and isinstance(service_fallback.get("num_unknown_services"), int))
                ) or not (isinstance(connection_panel, dict) and (
                    isinstance(connection_panel.get("connections"), list)
                    or (isinstance(connection_panel.get("summary"), dict)
                        and isinstance(connection_panel["summary"].get("successful_count"), int)
                        and isinstance(connection_panel["summary"].get("unsuccessful_count"), int))
                )):
                    raise ValueError("Missing service or connection inventory")
                counts = {"service_count": _report_service_count(report),
                          "connection_count": _report_connection_count(report)}
            except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
                stats["skipped"] += 1
                continue
            if all(row.get(key) == value for key, value in counts.items()):
                continue
            stats["different"] += 1
            if not dry_run:
                self._reports.update_one(
                    {"owner_id": owner, "report_id": report_id}, {"$set": counts}
                )
                stats["updated"] += 1
        return stats

    def rename(self, owner_id: str, report_id: str, title: str) -> dict[str, Any] | None:
        if self._reports is None: raise RuntimeError("Report store is not connected")
        report_id = self._safe(report_id, "report id")
        clean_title = title.strip()
        if not clean_title or len(clean_title) > 160: raise ValueError("Report title must contain 1 to 160 characters")
        query = {"owner_id": owner_id, "report_id": report_id}
        if not self._reports.find_one(query): return None
        self._reports.update_one(query, {"$set": {"title": clean_title, "updated_at": datetime.now(UTC)}})
        stored = self._reports.find_one(query)
        return self._public(stored) if stored else None

    def load(self, owner_id: str, report_id: str) -> dict[str, Any] | None:
        if self._reports is None:
            raise RuntimeError("Report store is not connected")
        report_id = self._safe(report_id, "report id")
        row = self._reports.find_one({"owner_id": owner_id, "report_id": report_id})
        if not row:
            return None
        path = (self.root / str(row["report_path"])).resolve()
        if self.root not in path.parents:
            raise RuntimeError("Stored report path escaped storage root")
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None

    def delete(self, owner_id: str, report_id: str) -> bool:
        if self._reports is None:
            raise RuntimeError("Report store is not connected")
        report_id = self._safe(report_id, "report id")
        row = self._reports.find_one({"owner_id": owner_id, "report_id": report_id})
        if not row:
            return False
        path = (self.root / str(row["report_path"])).resolve()
        if self.root in path.parents:
            path.unlink(missing_ok=True)
        self._reports.delete_one({"owner_id": owner_id, "report_id": report_id})
        return True

    def usage_for_owner(self, owner_id: str) -> dict[str, Any]:
        if self._reports is None: raise RuntimeError("Report store is not connected")
        rows=list(self._reports.find({"owner_id":owner_id})); total=0
        for row in rows:
            path=(self.root/str(row.get("report_path",""))).resolve()
            if self.root in path.parents:
                try: total += path.stat().st_size
                except OSError: pass
        return {"reportCount":len(rows),"reportBytes":total}

    def usage_all(self) -> dict[str, dict[str, Any]]:
        if self._reports is None: raise RuntimeError("Report store is not connected")
        result:dict[str,dict[str,Any]]={}
        for row in self._reports.find({}):
            oid=str(row.get("owner_id","")); item=result.setdefault(oid,{"reportCount":0,"reportBytes":0})
            item["reportCount"]+=1
            path=(self.root/str(row.get("report_path",""))).resolve()
            if self.root in path.parents:
                try:item["reportBytes"]+=path.stat().st_size
                except OSError:pass
        return result
