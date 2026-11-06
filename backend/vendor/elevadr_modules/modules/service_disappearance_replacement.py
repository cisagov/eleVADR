from __future__ import annotations
from collections import defaultdict
from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata

class ServiceDisappearanceReplacementModule(AnalysisModule):
    metadata=ModuleMetadata(id="service_disappearance_replacement",name="Service Disappearance / Replacement",description="Detects OT endpoints where a baseline service disappears and a different service appears after the baseline.",category="security_analysis",required_logs=("conn",))
    def analyze(self,context:AnalysisContext)->ModuleResult:
        p=_policy(context.metadata); baseline=float(p.get('baseline_seconds',300) or 300); minbase=int(p.get('minimum_baseline_observations',3) or 3); ot={str(x) for x in p.get('ot_hosts',[])} or _ot_hosts(context.metadata)
        rows=[]
        for r in context.connections:
            ts=_float(_first(r,'timestamp','ts')); dst=str(_first(r,'destination_ip','id.resp_h') or ''); svc=_service(r)
            if ts is None or not dst or not svc or (ot and dst not in ot):continue
            rows.append((ts,dst,svc,r))
        if not rows:return ModuleResult(self.metadata.id,[],{'observations':0,'findings':0},{'inspected_logs':['conn']},[])
        start=min(x[0] for x in rows); end=start+baseline; by=defaultdict(list)
        for x in rows:by[x[1]].append(x)
        findings=[]
        for host,items in sorted(by.items()):
            base=[x for x in items if x[0]<=end]; post=[x for x in items if x[0]>end]
            if len(base)<minbase or not post:continue
            b={x[2] for x in base}; a={x[2] for x in post}; disappeared=sorted(b-a); appeared=sorted(a-b)
            if not disappeared or not appeared:continue
            findings.append(Finding(title="OT service disappeared and was replaced",severity="medium",summary=f"{host} lost baseline service(s) {', '.join(disappeared)} and exposed new service(s) {', '.join(appeared)} after baseline.",confidence="medium",detection_basis="derived",devices=[host],services=sorted(b|a),flows=[x[3] for x in post[:10]],timestamps=[x[0] for x in post[:10]],tags=['ot','service-drift','replacement'],metadata={'baseline_services':sorted(b),'disappeared_services':disappeared,'new_services':appeared,'baseline_end':end}))
        return ModuleResult(self.metadata.id,findings,{'observations':len(rows),'hosts':len(by),'findings':len(findings)},{'inspected_logs':['conn'],'baseline_start':start,'baseline_end':end},[])
def _service(r):
    s=str(_first(r,'service') or '').strip().lower(); p=_first(r,'destination_port','id.resp_p'); proto=str(_first(r,'protocol','proto') or '').lower()
    return s if s and s!='-' else (f"{proto}/{p}" if p not in (None,'') else '')
def _ot_hosts(m):
    out=set()
    for a in m.get('asset_inventory',[]) if isinstance(m.get('asset_inventory'),list) else []:
        if str(a.get('role','')).lower()=='ot' or any(t in str(a.get('asset_type','')).lower() for t in ('plc','rtu','hmi','controller')):
            if a.get('ip'):out.add(str(a['ip']))
            out.update(str(x) for x in a.get('ips',[]) if x)
    return out
def _first(r,*ks):
    for k in ks:
        if r.get(k) not in (None,''):return r[k]
def _float(v):
    try:return float(v)
    except (TypeError,ValueError):return None
def _policy(m):
    v=m.get('service_disappearance_replacement_policy'); return dict(v) if isinstance(v,dict) else {}
