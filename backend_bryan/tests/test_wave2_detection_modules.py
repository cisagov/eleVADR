from __future__ import annotations
from backend_bryan.adapters.detection_context_adapter import compile_detection_context_metadata
from backend_bryan.integration.detector_runtime import ensure_detector_package
Context, MODULES, _ = ensure_detector_package()


def test_dns_source_drift_honors_trusted_dns():
    md=compile_detection_context_metadata({'schemaVersion':3,'id':'x','name':'x','segments':[],'assets':[],'infrastructure':[{'kind':'dns','value':'10.0.0.53'}],'communicationPairs':[],'allowedHosts':[],'allowedSegmentPairs':[],'approvedExternalDestinations':[],'authorizedControlActions':[],'captureScope':{},'scan':{},'modulePolicies':{}})
    ctx=Context(dns=[{'ts':0,'id.orig_h':'10.0.0.20','id.resp_h':'10.0.0.53'},{'ts':400,'id.orig_h':'10.0.0.20','id.resp_h':'8.8.8.8'}],metadata=md)
    r=MODULES['dns_source_drift'].analyze(ctx); assert len(r.findings)==1; assert r.findings[0].devices==['10.0.0.20','8.8.8.8']


def test_ntp_source_drift_honors_trusted_ntp():
    md=compile_detection_context_metadata({'schemaVersion':3,'id':'x','name':'x','segments':[],'assets':[],'infrastructure':[{'kind':'ntp','value':'10.0.0.123'}],'communicationPairs':[],'allowedHosts':[],'allowedSegmentPairs':[],'approvedExternalDestinations':[],'authorizedControlActions':[],'captureScope':{},'scan':{},'modulePolicies':{}})
    ctx=Context(ntp=[{'ts':0,'id.orig_h':'10.0.0.20','id.resp_h':'10.0.0.123'},{'ts':400,'id.orig_h':'10.0.0.20','id.resp_h':'129.6.15.28'}],metadata=md)
    r=MODULES['ntp_source_drift'].analyze(ctx); assert len(r.findings)==1


def test_arp_l2_reconnaissance_threshold():
    ctx=Context(arp=[{'ts':float(i),'operation':'request','sender_ip':'10.1.0.10','target_ip':f'10.1.0.{i+20}'} for i in range(20)],metadata={})
    r=MODULES['arp_l2_reconnaissance'].analyze(ctx); assert len(r.findings)==1; assert r.findings[0].metadata['distinct_targets']==20


def test_unexpected_multicast_behavior_requires_unapproved_group():
    md={'asset_inventory':[{'ip':'10.2.0.20','ips':['10.2.0.20'],'role':'ot','asset_type':'PLC'}],'unexpected_multicast_policy':{'allowed_groups':['239.1.1.1'],'minimum_flows':3}}
    rows=[{'timestamp':i,'source_ip':'10.2.0.20','destination_ip':'239.1.1.1','protocol':'udp'} for i in range(3)] + [{'timestamp':10+i,'source_ip':'10.2.0.20','destination_ip':'239.9.9.9','protocol':'udp'} for i in range(3)]
    r=MODULES['unexpected_multicast_behavior'].analyze(Context(connections=rows,metadata=md)); assert len(r.findings)==1; assert '239.9.9.9' in r.findings[0].devices


def test_tcp_reset_abort_surge_threshold():
    rows=[{'timestamp':float(i),'source_ip':f'10.3.0.{i+1}','destination_ip':'10.3.0.50','protocol':'tcp','connection_state':'RSTR'} for i in range(10)]
    r=MODULES['tcp_reset_abort_surge'].analyze(Context(connections=rows,metadata={})); assert len(r.findings)==1; assert r.findings[0].metadata['failure_events']==10
