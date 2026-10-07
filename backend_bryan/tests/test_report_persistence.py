from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from backend_bryan.auth.report_store import MongoReportStore


class Result:
    pass


class FakeCursor(list):
    def sort(self, *_args):
        self[:] = sorted(self, key=lambda x: x.get("created_at"), reverse=True); return self
    def limit(self, n): return self[:n]


class FakeCollection:
    def __init__(self): self.rows = []
    def update_one(self, query, update, upsert=False):
        set_paths = set(update.get("$set", {}))
        insert_paths = set(update.get("$setOnInsert", {}))
        overlap = set_paths & insert_paths
        if overlap:
            raise RuntimeError(f"Conflicting update paths: {sorted(overlap)}")
        row = next((r for r in self.rows if all(r.get(k)==v for k,v in query.items())), None)
        if row is None:
            row = dict(query); self.rows.append(row)
            row.update(update.get("$setOnInsert", {}))
        row.update(update.get("$set", {})); return Result()
    def find(self, query): return FakeCursor([r.copy() for r in self.rows if all(r.get(k)==v for k,v in query.items())])
    def find_one(self, query): return next((r.copy() for r in self.rows if all(r.get(k)==v for k,v in query.items())), None)
    def delete_one(self, query): self.rows[:] = [r for r in self.rows if not all(r.get(k)==v for k,v in query.items())]; return Result()


def store(tmp_path: Path) -> MongoReportStore:
    value = MongoReportStore(SimpleNamespace())
    value.root = tmp_path.resolve(); value.root.mkdir(exist_ok=True)
    value._reports = FakeCollection()
    return value


def test_report_persistence_is_owner_scoped_and_deletable(tmp_path: Path):
    s = store(tmp_path)
    report = {"report_id": "report-123", "report_version": "2.0", "summary": {"total_devices": 4}, "arch_insights": {"detector_findings": [{}, {}]}}
    meta = s.save("user-a", "alice", report, "plant.pcap")
    assert meta["findingCount"] == 2
    assert meta["deviceCount"] == 4
    assert s.load("user-a", "report-123") == report
    assert s.load("user-b", "report-123") is None
    assert s.list_for_owner("user-b") == []
    assert s.delete("user-b", "report-123") is False
    assert s.delete("user-a", "report-123") is True
    assert s.load("user-a", "report-123") is None


def test_report_path_is_under_owner_storage(tmp_path: Path):
    s = store(tmp_path)
    s.save("user-a", "alice", {"report_id": "r1"}, "capture.pcap")
    path = tmp_path / "users" / "user-a" / "reports" / "r1.json"
    assert path.is_file()
    assert json.loads(path.read_text()) ["report_id"] == "r1"


def test_repeat_save_preserves_created_at_without_mongo_update_conflict(tmp_path: Path):
    s = store(tmp_path)
    first = s.save("user-a", "alice", {"report_id": "repeat-1"}, "first.pcap")
    second = s.save("user-a", "alice", {"report_id": "repeat-1"}, "second.pcap")
    assert first["createdAt"] == second["createdAt"]
    assert second["sourceFilename"] == "second.pcap"
    assert len(s._reports.rows) == 1

def test_report_rename_is_owner_scoped_and_preserves_report_json(tmp_path: Path):
    s = store(tmp_path)
    report = {"report_id": "rename-1", "report_version": "2.0"}
    original = s.save("user-a", "alice", report, "plant.pcap")
    assert original["title"] == "plant.pcap"
    assert s.rename("user-b", "rename-1", "Other") is None
    renamed = s.rename("user-a", "rename-1", "  Pump Station Review  ")
    assert renamed is not None and renamed["title"] == "Pump Station Review"
    assert s.load("user-a", "rename-1") == report


def test_report_rename_validates_title(tmp_path: Path):
    s = store(tmp_path)
    s.save("user-a", "alice", {"report_id": "rename-2"}, "capture.pcap")
    for title in ("", "   ", "x" * 161):
        try:
            s.rename("user-a", "rename-2", title)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid report title was accepted")
