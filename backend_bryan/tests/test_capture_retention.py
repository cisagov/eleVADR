from pathlib import Path
from backend_bryan.auth.capture_store import MongoCaptureStore

class Cursor(list):
    def sort(self,*a): return self
    def limit(self,n): return Cursor(self[:n])
class Collection:
    def __init__(self): self.rows=[]
    def find_one(self,q): return next((r for r in self.rows if all(r.get(k)==v for k,v in q.items())),None)
    def insert_one(self,d): d=dict(d); d['_id']=len(self.rows)+1; self.rows.append(d)
    def update_one(self,q,u,**kw):
        r=self.find_one(q)
        if r:
            for k,v in u.get('$set',{}).items(): r[k]=v
    def find(self,q): return Cursor([r for r in self.rows if all(r.get(k)==v for k,v in q.items())])
    def delete_one(self,q): self.rows=[r for r in self.rows if not all(r.get(k)==v for k,v in q.items())]
class Config: mongodb_uri='mongodb://unused'; mongodb_database='elevadr'

def store(tmp_path):
    s=MongoCaptureStore(Config()); s.root=tmp_path; s._captures=Collection(); return s

def test_capture_is_deduplicated_per_owner_and_owner_isolated(tmp_path):
    s=store(tmp_path); a=s.save_bytes('user-a','a','plant.pcap',b'pcap-data'); again=s.save_bytes('user-a','a','plant.pcap',b'pcap-data'); b=s.save_bytes('user-b','b','plant.pcap',b'pcap-data')
    assert a['captureId']==again['captureId']; assert b['captureId']!=a['captureId']; assert len(s.list_for_owner('user-a'))==1
    assert s.path_for_owner('user-b',a['captureId']) is None

def test_deleting_capture_removes_only_capture_file_and_metadata(tmp_path):
    s=store(tmp_path); a=s.save_bytes('user-a','a','plant.pcap',b'pcap-data'); path=s.path_for_owner('user-a',a['captureId']); assert path and path.exists()
    report_file=tmp_path/'users'/'user-a'/'reports'/'report.json'; report_file.parent.mkdir(parents=True); report_file.write_text('{}')
    assert s.delete('user-a',a['captureId']); assert not path.exists(); assert report_file.exists(); assert not s.delete('user-a',a['captureId'])
