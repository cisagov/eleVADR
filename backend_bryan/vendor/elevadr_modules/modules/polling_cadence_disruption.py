from __future__ import annotations
from collections import defaultdict
from statistics import median
from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata

class PollingCadenceDisruptionModule(AnalysisModule):
    metadata=ModuleMetadata(id="polling_cadence_disruption",name="Polling Cadence Disruption",description="Detects established periodic OT polling whose post-baseline interval shifts materially from its learned cadence.",category="security_analysis",required_logs=("conn",))
    def analyze(self,context:AnalysisContext)->ModuleResult:
        p=_policy(context.metadata); baseline=float(p.get('baseline_seconds',300) or 300); minobs=int(p.get('minimum_baseline_observations',5) or 5); ratio=float(p.get('interval_change_ratio',0.5) or 0.5)
        by=defaultdict(list)
        for r in context.connections:
            ts=_float(_first(r,'timestamp','ts')); s=str(_first(r,'source_ip','id.orig_h') or ''); d=str(_first(r,'destination_ip','id.resp_h') or ''); port=_first(r,'destination_port','id.resp_p')
            if ts is not None and s and d:by[(s,d,str(port))].append((ts,r))
        allts=[x[0] for v in by.values() for x in v]
        if not allts:return ModuleResult(self.metadata.id,[],{'series':0,'findings':0},{'inspected_logs':['conn']},[])
        start=min(allts); end=start+baseline; findings=[]
        for key,items in sorted(by.items()):
            times=sorted(x[0] for x in items); bt=[t for t in times if t<=end]; pt=[t for t in times if t>end]
            if len(bt)<minobs or len(pt)<2:continue
            bints=[b-a for a,b in zip(bt,bt[1:]) if b>a]; pints=[b-a for a,b in zip(pt,pt[1:]) if b>a]
            if not bints or not pints:continue
            bm=median(bints); pm=median(pints)
            if bm<=0 or abs(pm-bm)/bm<ratio:continue
            rows=[r for t,r in items if t>end]
            findings.append(Finding(title="OT polling cadence changed",severity="medium",summary=f"Polling cadence for {key[0]} -> {key[1]} shifted from {bm:.3g}s to {pm:.3g}s median interval.",confidence="medium",detection_basis="derived",devices=[key[0],key[1]],flows=rows[:10],timestamps=pt[:10],tags=['ot','polling','cadence','baseline-drift'],metadata={'baseline_median_interval':bm,'post_baseline_median_interval':pm,'change_ratio':abs(pm-bm)/bm,'baseline_end':end}))
        return ModuleResult(self.metadata.id,findings,{'series':len(by),'findings':len(findings)},{'inspected_logs':['conn'],'baseline_start':start,'baseline_end':end},[])
def _first(r,*ks):
    for k in ks:
        if r.get(k) not in (None,''):return r[k]
def _float(v):
    try:return float(v)
    except (TypeError,ValueError):return None
def _policy(m):
    v=m.get('polling_cadence_disruption_policy'); return dict(v) if isinstance(v,dict) else {}
