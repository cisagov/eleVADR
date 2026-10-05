from __future__ import annotations

from backend_bryan.integration.detector_runtime import ensure_detector_package

Context, MODULES, _ = ensure_detector_package()


def test_encrypted_session_fingerprint_change():
    ssl=[]
    for i,t in enumerate([0,20,40,400]):
        ssl.append({'ts':t,'id.orig_h':'10.0.0.10','id.resp_h':'10.0.0.20','ja3':'aaa' if t<300 else 'bbb','version':'TLSv13','cipher':'4865'})
    r=MODULES['encrypted_session_fingerprint_change'].analyze(Context(ssl=ssl,metadata={'encrypted_session_fingerprint_policy':{'baseline_seconds':300,'minimum_baseline_observations':3}}))
    assert len(r.findings)==1


def test_remote_access_session_anomaly():
    rows=[
        {'ts':0,'id.orig_h':'10.0.1.5','id.resp_h':'10.0.0.10','id.resp_p':3389,'proto':'tcp','service':'rdp'},
        {'ts':20,'id.orig_h':'10.0.1.5','id.resp_h':'10.0.0.10','id.resp_p':3389,'proto':'tcp','service':'rdp'},
        {'ts':400,'id.orig_h':'10.0.1.5','id.resp_h':'10.0.0.20','id.resp_p':3389,'proto':'tcp','service':'rdp'},
        {'ts':410,'id.orig_h':'10.0.1.5','id.resp_h':'10.0.0.30','id.resp_p':3389,'proto':'tcp','service':'rdp'},
    ]
    md={'remote_access_session_anomaly_policy':{'baseline_seconds':300,'minimum_new_targets':2,'authorized_sources':['10.0.1.5']}}
    r=MODULES['remote_access_session_anomaly'].analyze(Context(connections=rows,metadata=md))
    assert len(r.findings)==1


def test_service_disappearance_replacement():
    rows=[]
    for t in [0,30,60]: rows.append({'ts':t,'id.orig_h':'10.0.1.5','id.resp_h':'10.0.0.10','id.resp_p':502,'proto':'tcp','service':'modbus'})
    for t in [400,430,460]: rows.append({'ts':t,'id.orig_h':'10.0.1.5','id.resp_h':'10.0.0.10','id.resp_p':102,'proto':'tcp','service':'s7comm'})
    md={'service_disappearance_replacement_policy':{'baseline_seconds':300,'minimum_baseline_observations':3,'ot_hosts':['10.0.0.10']}}
    r=MODULES['service_disappearance_replacement'].analyze(Context(connections=rows,metadata=md))
    assert len(r.findings)==1


def test_polling_cadence_disruption():
    times=[0,10,20,30,40,50,400,430,460,490]
    rows=[{'ts':t,'id.orig_h':'10.0.1.5','id.resp_h':'10.0.0.10','id.resp_p':502,'proto':'tcp','service':'modbus'} for t in times]
    md={'polling_cadence_disruption_policy':{'baseline_seconds':300,'minimum_baseline_observations':5,'interval_change_ratio':0.5}}
    r=MODULES['polling_cadence_disruption'].analyze(Context(connections=rows,metadata=md))
    assert len(r.findings)==1


def test_controller_communication_jitter():
    times=[0,10,20,30,40,50,60,400,405,425,433,470]
    rows=[{'ts':t,'id.orig_h':'10.0.0.10','id.resp_h':'10.0.1.5','id.resp_p':20000,'proto':'tcp'} for t in times]
    md={'controller_communication_jitter_policy':{'baseline_seconds':300,'minimum_baseline_observations':6,'jitter_multiplier':3,'minimum_post_jitter_ratio':0.2,'controller_hosts':['10.0.0.10']}}
    r=MODULES['controller_communication_jitter'].analyze(Context(connections=rows,metadata=md))
    assert len(r.findings)==1
