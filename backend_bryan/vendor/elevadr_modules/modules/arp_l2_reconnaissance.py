from __future__ import annotations
from collections import defaultdict
from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata

class ArpL2ReconnaissanceModule(AnalysisModule):
    metadata=ModuleMetadata(id="arp_l2_reconnaissance",name="ARP / L2 Reconnaissance",description="Detects hosts rapidly probing many distinct IPv4 targets with ARP requests.",category="security_analysis",required_logs=("arp",))
    def analyze(self,context):
        pol=_policy(context.metadata); minimum=int(pol.get('minimum_targets',20) or 20); window=float(pol.get('window_seconds',60) or 60); ignored={str(x) for x in pol.get('ignored_sources',[])}
        ev=[e for e in (_norm(r) for r in context.arp) if e and e['sender'] not in ignored and e['target'] and e['sender']!=e['target']]; by=defaultdict(list)
        for e in ev:by[e['sender']].append(e)
        fs=[]
        for src,rows in sorted(by.items()):
            rows=sorted(rows,key=lambda x:x['ts'] if x['ts'] is not None else -1); best=[]
            for i,a in enumerate(rows):
                if a['ts'] is None:continue
                cur=[x for x in rows[i:] if x['ts'] is not None and x['ts']-a['ts']<=window]; targets={x['target'] for x in cur}
                if len(targets)>=minimum and len(targets)>len({x['target'] for x in best}):best=cur
            if best:
                targets=sorted({x['target'] for x in best}); fs.append(Finding(title="ARP reconnaissance sweep observed",severity="medium",summary=f"{src} probed {len(targets)} distinct ARP targets within {window:g} seconds.",confidence="high",detection_basis="protocol_log",devices=[src,*targets[:5]],services=['arp'],flows=[x['raw'] for x in best[:10]],timestamps=[x['ts'] for x in best[:10]],tags=['arp','layer2','reconnaissance'],metadata={'distinct_targets':len(targets),'window_seconds':window,'minimum_targets':minimum,'targets':targets[:100]}))
        return ModuleResult(self.metadata.id,fs,{'arp_requests':len(ev),'sources':len(by),'findings':len(fs)},{'inspected_logs':['arp'],'notes':['ARP requests are treated as observations only; they do not alter asset authorization.']},[])
def _norm(r):
    op=str(_first(r,'operation','op','opcode') or '').lower();
    if op and not ('request' in op or op in {'1','who-has'}):return None
    s=str(_first(r,'sender_ip','spa','src_ip') or '').strip(); t=str(_first(r,'target_ip','tpa','dst_ip') or '').strip()
    try:ts=float(_first(r,'timestamp','ts'))
    except (TypeError,ValueError):ts=None
    return {'sender':s,'target':t,'ts':ts,'raw':r} if s and t else None
def _policy(m):
    v=m.get('arp_reconnaissance_policy'); return dict(v) if isinstance(v,dict) else {}
def _first(r,*ks):
    for k in ks:
        if r.get(k) not in (None,''):return r[k]
