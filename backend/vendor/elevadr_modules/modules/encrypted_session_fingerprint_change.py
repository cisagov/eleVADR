from __future__ import annotations
from collections import defaultdict, Counter
from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata

_FP_FIELDS=("ja3","ja3_hash","ja3s","ja3s_hash","client_ja3","server_ja3","cipher","version","server_name")
class EncryptedSessionFingerprintChangeModule(AnalysisModule):
    metadata=ModuleMetadata(id="encrypted_session_fingerprint_change",name="Encrypted Session Fingerprint Change",description="Detects established TLS endpoint pairs whose observed TLS fingerprint changes after a capture baseline.",category="security_analysis",required_logs=("ssl",))
    def analyze(self,context:AnalysisContext)->ModuleResult:
        p=_policy(context.metadata); baseline=float(p.get('baseline_seconds',300) or 300); minimum=int(p.get('minimum_baseline_observations',3) or 3); ignored={str(x) for x in p.get('ignored_hosts',[])}
        rows=[]
        for r in context.ssl:
            ts=_float(_first(r,'timestamp','ts')); s=str(_first(r,'source_ip','id.orig_h') or ''); d=str(_first(r,'destination_ip','id.resp_h') or '')
            fp=_fingerprint(r)
            if ts is None or not s or not d or not fp or s in ignored or d in ignored: continue
            rows.append((ts,s,d,fp,r))
        if not rows:return ModuleResult(self.metadata.id,[],{'tls_observations':0,'findings':0},{'inspected_logs':['ssl']},[])
        start=min(x[0] for x in rows); end=start+baseline; by=defaultdict(list)
        for x in rows:by[(x[1],x[2])].append(x)
        findings=[]
        for (s,d),items in sorted(by.items()):
            base=[x for x in items if x[0]<=end]
            if len(base)<minimum:continue
            counts=Counter(x[3] for x in base); expected,count=counts.most_common(1)[0]
            changed=[x for x in items if x[0]>end and x[3]!=expected]
            if not changed:continue
            observed=sorted({x[3] for x in changed})
            findings.append(Finding(title="Encrypted-session fingerprint changed",severity="medium",summary=f"TLS fingerprint for {s} -> {d} changed after the established baseline.",confidence="high",detection_basis="protocol_log",devices=[s,d],services=['tls'],flows=[x[4] for x in changed[:10]],timestamps=[x[0] for x in changed[:10]],tags=['tls','baseline-drift','fingerprint-change'],metadata={'baseline_fingerprint':expected,'baseline_observations':count,'observed_fingerprints':observed,'baseline_end':end}))
        return ModuleResult(self.metadata.id,findings,{'tls_observations':len(rows),'endpoint_pairs':len(by),'findings':len(findings)},{'inspected_logs':['ssl'],'baseline_start':start,'baseline_end':end},[])
def _fingerprint(r):
    values=[]
    for k in _FP_FIELDS:
        v=r.get(k)
        if v not in (None,'','-'): values.append(f"{k}={v}")
    return '|'.join(values)
def _first(r,*ks):
    for k in ks:
        if r.get(k) not in (None,''):return r[k]
def _float(v):
    try:return float(v)
    except (TypeError,ValueError):return None
def _policy(m):
    v=m.get('encrypted_session_fingerprint_policy'); return dict(v) if isinstance(v,dict) else {}
