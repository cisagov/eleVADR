from datetime import UTC, datetime, timedelta
from pathlib import Path
from backend_bryan.auth.capture_store import MongoCaptureStore, StorageQuotaExceeded

class Cursor(list):
    def sort(self,*a): return self
    def limit(self,n): return Cursor(self[:n])
class Collection:
    def __init__(self): self.rows=[]
    def _match(self,r,q):
        for k,v in q.items():
            rv=r.get(k)
            if isinstance(v,dict) and '$lt' in v:
                if rv is None or not rv < v['$lt']: return False
            elif rv != v:return False
        return True
    def find_one(self,q): return next((r for r in self.rows if self._match(r,q)),None)
    def insert_one(self,d): d=dict(d); d['_id']=len(self.rows)+1; self.rows.append(d)
    def update_one(self,q,u,**kw):
        r=self.find_one(q)
        if r:
            for k,v in u.get('$set',{}).items(): r[k]=v
    def find(self,q): return Cursor([r for r in self.rows if self._match(r,q)])
    def delete_one(self,q): self.rows=[r for r in self.rows if not self._match(r,q)]
class Config:
    mongodb_uri='mongodb://unused'; mongodb_database='elevadr'; pcap_retention_days=30; pcap_storage_limit_bytes=10

def store(tmp_path, config=Config()):
    s=MongoCaptureStore(config); s.root=tmp_path; s._captures=Collection(); return s

def test_quota_rejects_new_capture_but_allows_deduplicated_capture(tmp_path):
    s=store(tmp_path); first=s.save_bytes('u','user','a.pcap',b'123456')
    assert s.save_bytes('u','user','a.pcap',b'123456')['captureId']==first['captureId']
    try:s.save_bytes('u','user','b.pcap',b'abcdef')
    except StorageQuotaExceeded: pass
    else: raise AssertionError('quota should reject capture')

def test_expired_cleanup_deletes_capture_not_reports(tmp_path):
    s=store(tmp_path); item=s.save_bytes('u','user','a.pcap',b'1234'); row=s._captures.rows[0]; row['last_used_at']=datetime.now(UTC)-timedelta(days=31)
    report=tmp_path/'users'/'u'/'reports'/'r.json'; report.parent.mkdir(parents=True); report.write_text('{}')
    result=s.cleanup_expired('u')
    assert result['expiredCaptures']==1 and not (tmp_path/'users'/'u'/'pcaps'/f"{item['captureId']}.pcap").exists() and report.exists()

def test_orphan_detection_and_cleanup(tmp_path):
    s=store(tmp_path); s.save_bytes('u','user','a.pcap',b'1234')
    orphan=tmp_path/'users'/'u'/'pcaps'/'orphan.pcap'; orphan.write_bytes(b'orphan')
    assert orphan.resolve() in s.find_orphans(); result=s.remove_orphans(); assert result['orphanFiles']==1 and not orphan.exists()

def test_usage_exposes_retention_limit_and_remaining_bytes(tmp_path):
    s=store(tmp_path); s.save_bytes('u','user','a.pcap',b'1234'); usage=s.usage_for_owner('u')
    assert usage['captureBytes']==4 and usage['limitBytes']==10 and usage['remainingBytes']==6 and usage['retentionDays']==30

def test_zero_policy_keeps_retention_and_quota_disabled(tmp_path):
    class Unlimited:
        mongodb_uri='mongodb://unused'; mongodb_database='elevadr'; pcap_retention_days=0; pcap_storage_limit_bytes=0
    s=store(tmp_path, Unlimited()); s.save_bytes('u','user','a.pcap',b'x'*100)
    assert s.cleanup_expired('u')['expiredCaptures']==0
    assert s.usage_for_owner('u')['remainingBytes'] is None
