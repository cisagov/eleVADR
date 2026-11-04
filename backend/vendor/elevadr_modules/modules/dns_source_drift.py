from __future__ import annotations
from collections import defaultdict
from typing import Any
from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata

class DnsSourceDriftModule(AnalysisModule):
    metadata=ModuleMetadata(id="dns_source_drift", name="DNS Resolver Source Drift", description="Detects OT clients that use DNS resolvers outside explicitly trusted infrastructure or change resolver after a capture baseline.", category="security_analysis", required_logs=("dns",))
    def analyze(self, context: AnalysisContext)->ModuleResult:
        pol=_policy(context.metadata); trusted={str(x) for x in pol.get('trusted_resolvers',[]) if str(x)}; baseline=float(pol.get('baseline_seconds',300) or 300)
        rows=[r for r in (_norm(x) for x in context.dns) if r]
        if not rows: return ModuleResult(self.metadata.id,[],{'dns_events':0,'findings':0},{'inspected_logs':['dns']},[])
        ts=[r['ts'] for r in rows if r['ts'] is not None]; start=min(ts) if ts else None; end=(start+baseline) if start is not None else None
        base=defaultdict(set); drift=defaultdict(list)
        for r in rows:
            if end is not None and r['ts'] is not None and r['ts']<=end: base[r['client']].add(r['resolver'])
        for r in rows:
            bad= bool(trusted and r['resolver'] not in trusted)
            changed= bool(end is not None and r['ts'] is not None and r['ts']>end and base.get(r['client']) and r['resolver'] not in base[r['client']])
            if bad or changed: drift[(r['client'],r['resolver'])].append((r,bad,changed))
        fs=[]
        for (client,resolver),items in sorted(drift.items()):
            fs.append(Finding(title="DNS resolver source drift observed",severity="medium",summary=f"{client} used DNS resolver {resolver} outside its expected resolver set.",confidence="high",detection_basis="protocol_log",devices=[client,resolver],services=['dns'],ports=[53],flows=[i[0]['raw'] for i in items[:10]],timestamps=[i[0]['ts'] for i in items if i[0]['ts'] is not None][:10],tags=['dns','ot','configuration-drift'],metadata={'trusted_resolvers':sorted(trusted),'baseline_resolvers':sorted(base.get(client,set())),'outside_trusted_infrastructure':any(i[1] for i in items),'post_baseline_change':any(i[2] for i in items)}))
        return ModuleResult(self.metadata.id,fs,{'dns_events':len(rows),'resolver_drifts':len(drift),'findings':len(fs)},{'inspected_logs':['dns'],'trusted_resolvers':sorted(trusted),'baseline_start':start,'baseline_end':end,'notes':['Observed DNS traffic is evidence only and never makes a resolver trusted.']},[] if trusted else ['No trusted DNS resolvers configured; only within-capture post-baseline drift can be detected.'])

def _norm(r):
    c=str(_first(r,'source_ip','id.orig_h','client_ip') or '').strip(); s=str(_first(r,'destination_ip','id.resp_h','server_ip','resolver_ip') or '').strip()
    if not c or not s:return None
    try:t=float(_first(r,'timestamp','ts'))
    except (TypeError,ValueError):t=None
    return {'client':c,'resolver':s,'ts':t,'raw':r}
def _policy(m):
    v=m.get('dns_source_drift_policy'); return dict(v) if isinstance(v,dict) else {}
def _first(r,*ks):
    for k in ks:
        if r.get(k) not in (None,''): return r[k]
