from __future__ import annotations
from collections import defaultdict
from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata

class NtpSourceDriftModule(AnalysisModule):
    metadata=ModuleMetadata(id="ntp_source_drift", name="NTP Source Drift", description="Detects NTP clients that use servers outside explicitly trusted time infrastructure or change server after a capture baseline.", category="security_analysis", required_logs=("ntp",))
    def analyze(self,context):
        pol=_policy(context.metadata); trusted={str(x) for x in pol.get('trusted_servers',[]) if str(x)}; baseline=float(pol.get('baseline_seconds',300) or 300)
        rows=[r for r in (_norm(x) for x in context.ntp) if r]; ts=[r['ts'] for r in rows if r['ts'] is not None]; start=min(ts) if ts else None; end=start+baseline if start is not None else None
        base=defaultdict(set); drift=defaultdict(list)
        for r in rows:
            if end is not None and r['ts'] is not None and r['ts']<=end: base[r['client']].add(r['server'])
        for r in rows:
            bad=bool(trusted and r['server'] not in trusted); changed=bool(end is not None and r['ts'] is not None and r['ts']>end and base.get(r['client']) and r['server'] not in base[r['client']])
            if bad or changed: drift[(r['client'],r['server'])].append((r,bad,changed))
        fs=[]
        for (client,server),items in sorted(drift.items()):
            fs.append(Finding(title="NTP source drift observed",severity="medium",summary=f"{client} used NTP server {server} outside its expected time-source set.",confidence="high",detection_basis="protocol_log",devices=[client,server],services=['ntp'],ports=[123],flows=[i[0]['raw'] for i in items[:10]],timestamps=[i[0]['ts'] for i in items if i[0]['ts'] is not None][:10],tags=['ntp','ot','configuration-drift'],metadata={'trusted_servers':sorted(trusted),'baseline_servers':sorted(base.get(client,set())),'outside_trusted_infrastructure':any(i[1] for i in items),'post_baseline_change':any(i[2] for i in items)}))
        return ModuleResult(self.metadata.id,fs,{'ntp_events':len(rows),'source_drifts':len(drift),'findings':len(fs)},{'inspected_logs':['ntp'],'trusted_servers':sorted(trusted),'baseline_start':start,'baseline_end':end,'notes':['Observed NTP traffic never makes a time source trusted.']},[] if trusted else ['No trusted NTP servers configured; only within-capture post-baseline drift can be detected.'])
def _norm(r):
    c=str(_first(r,'source_ip','id.orig_h','client_ip') or '').strip(); s=str(_first(r,'destination_ip','id.resp_h','server_ip') or '').strip()
    if not c or not s:return None
    try:t=float(_first(r,'timestamp','ts'))
    except (TypeError,ValueError):t=None
    return {'client':c,'server':s,'ts':t,'raw':r}
def _policy(m):
    v=m.get('ntp_source_drift_policy'); return dict(v) if isinstance(v,dict) else {}
def _first(r,*ks):
    for k in ks:
        if r.get(k) not in (None,''):return r[k]
