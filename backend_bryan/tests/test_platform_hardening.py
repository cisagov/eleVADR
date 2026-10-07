from __future__ import annotations

import json
from pathlib import Path

import pytest

from backend_bryan.auth.capture_store import MongoCaptureStore
from backend_bryan.auth.models import AuthPrincipal
from backend_bryan.auth.report_store import MongoReportStore


class Cursor(list):
    def sort(self, *args): return self
    def limit(self, n): return Cursor(self[:n])


class Collection:
    def __init__(self): self.rows = []
    def find_one(self, q): return next((r for r in self.rows if all(r.get(k) == v for k, v in q.items())), None)
    def find(self, q): return Cursor([r for r in self.rows if all(r.get(k) == v for k, v in q.items())])
    def insert_one(self, d):
        row = dict(d); row.setdefault('_id', len(self.rows) + 1); self.rows.append(row)
    def update_one(self, q, update, upsert=False):
        overlap = set(update.get('$set', {})) & set(update.get('$setOnInsert', {}))
        if overlap: raise RuntimeError(f'conflicting update paths: {sorted(overlap)}')
        row = self.find_one(q)
        inserted = row is None
        if row is None and upsert:
            row = dict(q); self.rows.append(row)
        if row is not None:
            if inserted: row.update(update.get('$setOnInsert', {}))
            row.update(update.get('$set', {}))
    def delete_one(self, q): self.rows = [r for r in self.rows if not all(r.get(k) == v for k, v in q.items())]


class Config:
    mongodb_uri = 'mongodb://unused'
    mongodb_database = 'elevadr'


def report_store(tmp_path: Path) -> MongoReportStore:
    s = MongoReportStore(Config()); s.root = tmp_path; s._reports = Collection(); return s


def capture_store(tmp_path: Path) -> MongoCaptureStore:
    s = MongoCaptureStore(Config()); s.root = tmp_path; s._captures = Collection(); return s


def report(report_id='r1'):
    return {'report_id': report_id, 'report_version': 'v1', 'summary': {'total_devices': 2}, 'arch_insights': {'detector_findings': []}}


def test_real_auth_principal_uses_user_id_not_id():
    p = AuthPrincipal('u1', 'alice', True, 'analyst')
    assert p.user_id == 'u1'
    assert not hasattr(p, 'id')
    assert p.as_dict()['id'] == 'u1'


def test_reports_are_owner_isolated_for_list_load_rename_and_delete(tmp_path):
    s = report_store(tmp_path)
    s.save('alice', 'alice', report('r1'), 'a.pcap')
    assert len(s.list_for_owner('alice')) == 1
    assert s.list_for_owner('bob') == []
    assert s.load('bob', 'r1') is None
    assert s.rename('bob', 'r1', 'stolen') is None
    assert s.delete('bob', 'r1') is False
    assert s.load('alice', 'r1')['report_id'] == 'r1'


def test_report_path_escape_is_rejected(tmp_path):
    s = report_store(tmp_path)
    s._reports.rows.append({'owner_id': 'alice', 'report_id': 'r1', 'report_path': '../outside.json'})
    with pytest.raises(RuntimeError, match='escaped storage root'):
        s.load('alice', 'r1')


def test_missing_persisted_report_file_fails_closed(tmp_path):
    s = report_store(tmp_path)
    s._reports.rows.append({'owner_id': 'alice', 'report_id': 'r1', 'report_path': 'users/alice/reports/missing.json'})
    assert s.load('alice', 'r1') is None


def test_corrupt_persisted_report_is_not_silently_accepted(tmp_path):
    s = report_store(tmp_path)
    p = tmp_path/'users'/'alice'/'reports'/'r1.json'; p.parent.mkdir(parents=True); p.write_text('{bad json', encoding='utf-8')
    s._reports.rows.append({'owner_id': 'alice', 'report_id': 'r1', 'report_path': 'users/alice/reports/r1.json'})
    with pytest.raises(json.JSONDecodeError):
        s.load('alice', 'r1')


def test_capture_owner_isolation_includes_delete(tmp_path):
    s = capture_store(tmp_path)
    cap = s.save_bytes('alice', 'alice', 'a.pcap', b'pcap')
    assert s.path_for_owner('bob', cap['captureId']) is None
    assert s.delete('bob', cap['captureId']) is False
    assert s.path_for_owner('alice', cap['captureId']).exists()


def test_same_capture_bytes_are_deduplicated_only_within_owner(tmp_path):
    s = capture_store(tmp_path)
    a1 = s.save_bytes('alice', 'alice', 'a.pcap', b'same')
    a2 = s.save_bytes('alice', 'alice', 'copy.pcap', b'same')
    b = s.save_bytes('bob', 'bob', 'a.pcap', b'same')
    assert a1['captureId'] == a2['captureId']
    assert a1['captureId'] != b['captureId']


def test_capture_delete_does_not_remove_saved_reports(tmp_path):
    cs = capture_store(tmp_path); rs = report_store(tmp_path)
    cap = cs.save_bytes('alice', 'alice', 'a.pcap', b'pcap')
    rs.save('alice', 'alice', report('r1'), 'a.pcap', cap['captureId'])
    assert cs.delete('alice', cap['captureId'])
    assert rs.load('alice', 'r1')['report_id'] == 'r1'
