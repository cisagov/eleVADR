from __future__ import annotations
import ipaddress
from collections import defaultdict
from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata

class UnexpectedMulticastBehaviorModule(AnalysisModule):
    metadata=ModuleMetadata(id="unexpected_multicast_behavior",name="Unexpected Multicast Behavior",description="Detects OT hosts initiating multicast traffic to groups outside explicitly allowed multicast destinations.",category="security_analysis",required_logs=("conn",))
    def analyze(self,context):
        pol=_policy(context.metadata); allowed=[str(x) for x in pol.get('allowed_groups',[])]; minimum=int(pol.get('minimum_flows',3) or 3); ot=_ot_hosts(context.metadata)
        groups=defaultdict(list)
        for r in context.connections:
            s=str(_first(r,'source_ip','id.orig_h') or ''); d=str(_first(r,'destination_ip','id.resp_h') or '')
            if not s or not _multicast(d) or (ot and s not in ot) or _match(d,allowed):continue
            groups[(s,d)].append(r)
        fs=[]
        for (s,d),rows in sorted(groups.items()):
            if len(rows)<minimum:continue
            fs.append(Finding(title="Unexpected OT multicast destination observed",severity="medium",summary=f"{s} originated {len(rows)} multicast flow(s) to unapproved group {d}.",confidence="high",detection_basis="derived",devices=[s,d],services=sorted({str(_first(r,'service') or 'unknown') for r in rows}),connection_pairs=[{'source':s,'destination':d,'port':_first(r,'destination_port','id.resp_p'),'service':_first(r,'service')} for r in rows[:10]],flows=rows[:10],timestamps=[x for r in rows if (x:=_first(r,'timestamp','ts')) is not None][:10],tags=['ot','multicast','configuration-drift'],metadata={'flow_count':len(rows),'allowed_groups':allowed}))
        return ModuleResult(self.metadata.id,fs,{'multicast_pairs':len(groups),'findings':len(fs)},{'inspected_logs':['conn'],'allowed_groups':allowed,'notes':['Observed multicast groups never become allowed groups automatically.']},[])
def _ot_hosts(m):
    out=set()
    for a in m.get('asset_inventory',[]) if isinstance(m.get('asset_inventory'),list) else []:
        if str(a.get('role','')).lower()=='ot' or any(x in str(a.get('asset_type','')).lower() for x in ('plc','rtu','hmi','controller')):
            for k in ('ip',):
                if a.get(k):out.add(str(a[k]))
            out.update(str(x) for x in a.get('ips',[]) if x)
    return out
def _multicast(s):
    try:return ipaddress.ip_address(s).is_multicast
    except ValueError:return False
def _match(ip,rules):
    a=ipaddress.ip_address(ip)
    for r in rules:
        try:
            if '/' in r and a in ipaddress.ip_network(r,strict=False):return True
            if a==ipaddress.ip_address(r):return True
        except ValueError:pass
    return False
def _policy(m):
    v=m.get('unexpected_multicast_policy');return dict(v) if isinstance(v,dict) else {}
def _first(r,*ks):
    for k in ks:
        if r.get(k) not in (None,''):return r[k]
