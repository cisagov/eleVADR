from __future__ import annotations
from collections import defaultdict
from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata

RESET_STATES={'RSTO','RSTR','RSTOS0','RSTRH','REJ','SHR','SH'}
class TcpResetAbortSurgeModule(AnalysisModule):
    metadata=ModuleMetadata(id="tcp_reset_abort_surge",name="TCP Reset / Connection-Abort Surge",description="Detects bursts of reset/rejected/aborted TCP sessions against the same destination.",category="security_analysis",required_logs=("conn",))
    def analyze(self,context):
        pol=_policy(context.metadata); minimum=int(pol.get('minimum_events',10) or 10); window=float(pol.get('window_seconds',60) or 60); ratio=float(pol.get('minimum_failure_ratio',0.6) or 0.6)
        rows=[]
        for r in context.connections:
            if str(_first(r,'protocol','proto') or '').lower() not in ('tcp',''):continue
            try:t=float(_first(r,'timestamp','ts'))
            except (TypeError,ValueError):continue
            rows.append({'ts':t,'src':str(_first(r,'source_ip','id.orig_h') or ''),'dst':str(_first(r,'destination_ip','id.resp_h') or ''),'state':str(_first(r,'connection_state','conn_state','zeek_state','state') or ''),'raw':r})
        by=defaultdict(list)
        for r in rows:
            if r['dst']:by[r['dst']].append(r)
        fs=[]
        for dst,allrows in sorted(by.items()):
            allrows=sorted(allrows,key=lambda x:x['ts']); best=None
            for i,a in enumerate(allrows):
                cur=[x for x in allrows[i:] if x['ts']-a['ts']<=window]; bad=[x for x in cur if x['state'].upper() in RESET_STATES]
                if len(bad)>=minimum and len(bad)/max(1,len(cur))>=ratio and (best is None or len(bad)>len(best[1])):best=(cur,bad)
            if best:
                cur,bad=best; srcs=sorted({x['src'] for x in bad if x['src']}); fs.append(Finding(title="TCP reset / connection-abort surge observed",severity="medium",summary=f"{len(bad)} reset/rejected TCP sessions targeted {dst} within {window:g} seconds.",confidence="high",detection_basis="derived",devices=[dst,*srcs[:5]],services=sorted({str(_first(x['raw'],'service') or 'tcp') for x in bad}),flows=[x['raw'] for x in bad[:10]],timestamps=[x['ts'] for x in bad[:10]],tags=['tcp','availability','reset-surge'],metadata={'failure_events':len(bad),'window_connections':len(cur),'failure_ratio':len(bad)/len(cur),'window_seconds':window,'states':sorted({x['state'] for x in bad})}))
        return ModuleResult(self.metadata.id,fs,{'tcp_connections':len(rows),'destinations':len(by),'findings':len(fs)},{'inspected_logs':['conn'],'failure_states':sorted(RESET_STATES)},[])
def _policy(m):
    v=m.get('tcp_reset_abort_policy');return dict(v) if isinstance(v,dict) else {}
def _first(r,*ks):
    for k in ks:
        if r.get(k) not in (None,''):return r[k]
