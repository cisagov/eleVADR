# Wave 3 detector expansion: 70 -> 75 modules

Wave 3 adds five behavioral/timing detectors:

- `encrypted_session_fingerprint_change` — learns a TLS endpoint-pair fingerprint baseline and flags post-baseline fingerprint changes.
- `remote_access_session_anomaly` — learns remote-access targets and flags post-baseline target fan-out from management sources.
- `service_disappearance_replacement` — flags an OT endpoint whose baseline service disappears while a different service appears.
- `polling_cadence_disruption` — flags material post-baseline shifts in an established polling interval.
- `controller_communication_jitter` — flags materially increased timing variance in controller communications.

Observed traffic remains evidence only. It does not create trusted fingerprints, remote-access authorization, expected services, or timing policy. Advanced overrides are compiled only through `backend_bryan.adapters.detection_context_adapter`.

Focused coverage lives in `backend_bryan/tests/test_wave3_detection_modules.py` and `backend_bryan.regression.wave3_detector_acceptance_runner`. Dataset 07, Dataset 10, and Dataset 14 exercise the full 75-module registry. A raw-PCAP Wave 3 dataset can be added after this normalized acceptance baseline is validated on Windows.
