from __future__ import annotations
from collections import defaultdict
from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata

_DEFAULT_PORTS={22,3389,5900,5901,5938,6129}
class RemoteAccessSessionAnomalyModule(AnalysisModule):
    metadata=ModuleMetadata(id="remote_access_session_anomaly",name="Remote Access Session Anomaly",description="Detects authorized remote-access sources that fan out to unusual OT targets after a baseline.",category="security_analysis",required_logs=("conn",))
    def analyze(self,context:AnalysisContext)->ModuleResult:
        p=_policy(context.metadata); baseline=float(p.get('baseline_seconds',300) or 300); minimum=int(p.get('minimum_new_targets',2) or 2); ports={int(x) for x in p.get('remote_access_ports',_DEFAULT_PORTS)}; authorized={str(x) for x in p.get('authorized_sources',[])}
        rows=[]
        for r in context.connections:
            ts=_float(_first(r,'timestamp','ts')); s=str(_first(r,'source_ip','id.orig_h') or ''); d=str(_first(r,'destination_ip','id.resp_h') or ''); port=_int(_first(r,'destination_port','id.resp_p'))
            service=str(_first(r,'service') or '').lower()
            if ts is None or not s or not d or not (port in ports or service in {'ssh','rdp','vnc'}):continue
            if authorized and s not in authorized:continue
            rows.append((ts,s,d,port,service,r))
        if not rows:return ModuleResult(self.metadata.id,[],{'remote_sessions':0,'findings':0},{'inspected_logs':['conn']},[])
        start=min(x[0] for x in rows); end=start+baseline; base=defaultdict(set); post=defaultdict(list)
        for x in rows:
            (base[x[1]].add(x[2]) if x[0]<=end else post[x[1]].append(x))
        findings=[]
        for src,items in sorted(post.items()):
            new=sorted({x[2] for x in items if x[2] not in base[src]})
            if len(new)<minimum:continue
            evidence=[x for x in items if x[2] in new]
            findings.append(Finding(title="Remote-access target pattern changed",severity="medium",summary=f"{src} accessed {len(new)} new remote-access target(s) after the baseline.",confidence="medium",detection_basis="derived",devices=[src,*new[:10]],services=sorted({x[4] or 'remote-access' for x in evidence}),ports=sorted({x[3] for x in evidence if x[3] is not None}),flows=[x[5] for x in evidence[:10]],timestamps=[x[0] for x in evidence[:10]],tags=['remote-access','baseline-drift','lateral-movement'],metadata={'baseline_targets':sorted(base[src]),'new_targets':new,'baseline_end':end}))
        return ModuleResult(self.metadata.id,findings,{'remote_sessions':len(rows),'sources':len(set(x[1] for x in rows)),'findings':len(findings)},{'inspected_logs':['conn'],'baseline_start':start,'baseline_end':end,'authorized_sources':sorted(authorized)},[])
def _first(r,*ks):
    for k in ks:
        if r.get(k) not in (None,''):return r[k]
def _float(v):
    try:return float(v)
    except (TypeError,ValueError):return None
def _int(v):
    try:return int(v)
    except (TypeError,ValueError):return None
def _policy(m):
    v=m.get('remote_access_session_anomaly_policy'); return dict(v) if isinstance(v,dict) else {}
