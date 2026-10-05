from __future__ import annotations
from backend_bryan.integration.detector_runtime import ensure_detector_package
from backend_bryan.tests import test_wave3_detection_modules as t
WAVE3={'encrypted_session_fingerprint_change','remote_access_session_anomaly','service_disappearance_replacement','polling_cadence_disruption','controller_communication_jitter'}
def main()->int:
    _C,modules,_=ensure_detector_package(); failures=[]; passed=0
    checks=[
      ('Registry contains 75 modules including all five Wave 3 additions',lambda: (_ for _ in ()).throw(AssertionError(len(modules))) if len(modules)!=75 or not WAVE3.issubset(modules) else None),
      ('Encrypted-session fingerprint change detects post-baseline TLS drift',t.test_encrypted_session_fingerprint_change),
      ('Remote-access anomaly detects new target fan-out',t.test_remote_access_session_anomaly),
      ('Service disappearance/replacement detects OT service swap',t.test_service_disappearance_replacement),
      ('Polling cadence disruption detects interval shift',t.test_polling_cadence_disruption),
      ('Controller communication jitter detects timing variance increase',t.test_controller_communication_jitter),
    ]
    print('\n=== Wave 3 detector acceptance: five behavioral/timing modules ===')
    for label,fn in checks:
        try: fn(); passed+=1; print('PASS ',label)
        except Exception as exc: failures.append(f'{label}: {type(exc).__name__}: {exc}'); print('FAIL ',label,exc)
    print(('FAIL' if failures else 'PASS')+f': Wave 3 detector acceptance verified {passed} cases.')
    return 1 if failures else 0
if __name__=='__main__': raise SystemExit(main())
