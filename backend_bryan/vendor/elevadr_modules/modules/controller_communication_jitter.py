from __future__ import annotations
from collections import defaultdict
from statistics import median
from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata

class ControllerCommunicationJitterModule(AnalysisModule):
    metadata=ModuleMetadata(id="controller_communication_jitter",name="Controller Communication Jitter",description="Detects increased timing variance in established controller communications after a baseline.",category="security_analysis",required_logs=("conn",))
    def analyze(self,context:AnalysisContext)->ModuleResult:
        p=_policy(context.metadata); baseline=float(p.get('baseline_seconds',300) or 300); minobs=int(p.get('minimum_baseline_observations',6) or 6); mult=float(p.get('jitter_multiplier',3.0) or 3.0); floor=float(p.get('minimum_post_jitter_ratio',0.25) or 0.25); controllers={str(x) for x in p.get('controller_hosts',[])} or _controllers(context.metadata)
        by=defaultdict(list)
        for r in context.connections:
            ts=_float(_first(r,'timestamp','ts')); s=str(_first(r,'source_ip','id.orig_h') or ''); d=str(_first(r,'destination_ip','id.resp_h') or '')
            if ts is None or not s or not d:continue
            if controllers and s not in controllers and d not in controllers:continue
            by[(s,d)].append((ts,r))
        allts=[x[0] for v in by.values() for x in v]
        if not allts:return ModuleResult(self.metadata.id,[],{'series':0,'findings':0},{'inspected_logs':['conn']},[])
        start=min(allts); end=start+baseline; findings=[]
        for (s,d),items in sorted(by.items()):
            times=sorted(x[0] for x in items); bt=[t for t in times if t<=end]; pt=[t for t in times if t>end]
            if len(bt)<minobs or len(pt)<3:continue
            bi=[b-a for a,b in zip(bt,bt[1:]) if b>a]; pi=[b-a for a,b in zip(pt,pt[1:]) if b>a]
            if len(bi)<2 or len(pi)<2:continue
            bj=_jitter(bi); pj=_jitter(pi); pm=median(pi)
            if pj < max(bj*mult, pm*floor):continue
            rows=[r for t,r in items if t>end]
            findings.append(Finding(title="Controller communication jitter increased",severity="medium",summary=f"Timing jitter for {s} -> {d} increased from {bj:.3g}s baseline MAD to {pj:.3g}s.",confidence="medium",detection_basis="derived",devices=[s,d],flows=rows[:10],timestamps=pt[:10],tags=['ot','controller','timing','jitter'],metadata={'baseline_jitter_mad':bj,'post_baseline_jitter_mad':pj,'post_median_interval':pm,'jitter_multiplier':mult,'baseline_end':end}))
        return ModuleResult(self.metadata.id,findings,{'series':len(by),'findings':len(findings)},{'inspected_logs':['conn'],'baseline_start':start,'baseline_end':end},[])
def _jitter(v):
    m=median(v); return median([abs(x-m) for x in v])
def _controllers(m):
    out=set()
    for a in m.get('asset_inventory',[]) if isinstance(m.get('asset_inventory'),list) else []:
        if any(t in (str(a.get('role',''))+' '+str(a.get('asset_type',''))).lower() for t in ('plc','rtu','controller')):
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
    v=m.get('controller_communication_jitter_policy'); return dict(v) if isinstance(v,dict) else {}
