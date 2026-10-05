from __future__ import annotations
from backend_bryan.tests import test_wave2_detection_modules as t
from backend_bryan.integration.detector_runtime import ensure_detector_package

WAVE2={'dns_source_drift','ntp_source_drift','arp_l2_reconnaissance','unexpected_multicast_behavior','tcp_reset_abort_surge'}

def main()->int:
    _, modules, _=ensure_detector_package(); failures=[]; passed=0
    checks=[('Registry contains 75 modules including all five Wave 2 additions',lambda: (_ for _ in ()).throw(AssertionError(len(modules))) if len(modules)!=75 or not WAVE2.issubset(modules) else None),
    ('DNS resolver drift honors trusted infrastructure',t.test_dns_source_drift_honors_trusted_dns),('NTP source drift honors trusted infrastructure',t.test_ntp_source_drift_honors_trusted_ntp),('ARP/L2 reconnaissance detects 20-target sweep',t.test_arp_l2_reconnaissance_threshold),('Unexpected multicast honors approved group and catches unapproved group',t.test_unexpected_multicast_behavior_requires_unapproved_group),('TCP reset/abort surge detects threshold burst',t.test_tcp_reset_abort_surge_threshold)]
    print('\n=== Wave 2 detector acceptance: five additional network/OT modules ===')
    for name,fn in checks:
        try: fn(); print('PASS ',name); passed+=1
        except Exception as e: print('FAIL ',name,':',e); failures.append(name)
    print(f"{'FAIL' if failures else 'PASS'}: Wave 2 detector acceptance verified {passed} cases.")
    return 1 if failures else 0
if __name__=='__main__': raise SystemExit(main())
