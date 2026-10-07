from datetime import UTC, datetime
from backend_bryan.auth.audit_store import MongoAuditStore, sanitize_metadata

class Cursor(list):
    def sort(self,*a,**k): return self
    def limit(self,n): return Cursor(self[:n])
class Events:
    def __init__(self): self.rows=[]
    def insert_one(self,d): d=dict(d); d['_id']=len(self.rows)+1; self.rows.append(d)
    def find(self,q):
        rows=self.rows
        if 'actor_id' in q: rows=[r for r in rows if r.get('actor_id')==q['actor_id']]
        return Cursor(list(reversed(rows)))

def store():
    s=object.__new__(MongoAuditStore); s.config=None; s.retention_days=180; s._client=None; s._events=Events(); return s

def test_audit_redacts_sensitive_metadata_recursively():
    clean=sanitize_metadata({'password':'secret','nested':{'access_token':'abc','safe':'ok'},'authorization':'Bearer nope'})
    assert clean['password']=='[redacted]' and clean['nested']['access_token']=='[redacted]' and clean['nested']['safe']=='ok'

def test_actor_history_isolated_and_admin_history_combined():
    s=store(); s.record(action='report.open',result='success',actor_id='a',actor_username='alice'); s.record(action='capture.delete',result='success',actor_id='b',actor_username='bob')
    mine=s.list_for_actor('a'); assert len(mine)==1 and mine[0]['actorUsername']=='alice'
    assert len(s.list_all())==2

def test_invalid_audit_result_rejected():
    s=store()
    try: s.record(action='x',result='maybe')
    except ValueError: pass
    else: raise AssertionError('invalid result accepted')
