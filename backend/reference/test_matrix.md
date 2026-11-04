# Regression test matrix

The standard Windows gate is `run_regression_tests.bat`. It currently has 22 stages.

| Dataset / gate | Primary purpose | Key protected behavior |
| --- | --- | --- |
| Backend unit/regression tests | Core code contracts | adapters, API, jobs, report pipeline, runtime, all 75 modules |
| Dataset 01 | Mixed OT baseline PCAP | trusted infra, OT/IT identity, communication-pair semantics |
| Dataset 02 | Legacy/high-risk PCAP | rogue inventory and observed-only asset separation |
| Dataset 03 | Outbound/IPv6/QUIC/ICMP PCAP | outbound volume, HTTP upload, ICMP timing, IPv6, QUIC, new-service baseline |
| Dataset 04 | Control/discovery semantics | Modbus, S7, CIP, SNMP SET, BACnet; observed traffic != authorization |
| Dataset 05 | Parser robustness | malformed/partial Zeek rows, weird.log, VLAN/double-tag, parse diagnostics |
| Dataset 06 | Threshold boundaries | exact/below/over thresholds and inclusive time windows |
| Dataset 07 | Temporal/state isolation | out-of-order input, duplicates, singleton reset, no cross-run contamination |
| Dataset 08 | Policy precedence | longest-prefix identity, scoped trust/allowlists, advanced override precedence |
| Dataset 09 | Determinism | canonical ordering and semantically byte-identical reports outside volatile fields |
| Dataset 10 | Performance/scale | 12k connections, 3k assets, 7.5k findings, large contexts, all-75 scale pass |
| Dataset 11 | Failure/cancellation | exception isolation, cleanup, cancellation, retry freshness, stale-job isolation |
| Dataset 12 | Input/security hardening | filenames, size/depth limits, non-finite JSON, invalid network values |
| Dataset 13 | UI workflow resilience | common report normalizer, cancellation UI contract, one-pass Zeek evidence reuse, Home/reset, responsive/report actions |
| Dataset 14 | Mixed OT acceptance | 75-module full-path acceptance with authorized + unauthorized OT activity |
| New detector acceptance | Wave 1 | 75-module registry plus focused normalized semantics for five Wave 1 modules |
| Wave 2 detector acceptance | Wave 2 | Focused normalized semantics for five Wave 2 modules |
| Wave 3 detector acceptance | Wave 3 | Focused normalized semantics for five behavioral/timing modules |
| Dataset 15 | Raw-PCAP Wave 1 acceptance | ARP, DHCP, Modbus role/peer/burst behavior proven from packet capture through Zeek |
| Dataset 16 | Raw-PCAP Wave 2 acceptance | DNS/NTP drift, ARP sweep, multicast drift, and TCP reset surge proven from packet capture through Zeek |
| Dataset 17 | Raw-PCAP Wave 3 acceptance | TLS fingerprint drift, remote-access target expansion, service replacement, polling cadence disruption, and controller jitter proven from packet capture through Zeek |
| Dataset 18 (operator-run) | Real-site validation/tuning | representative site PCAP, matching Detection Context, finding review, missed-detection worksheet, coverage summary; not part of automatic gate |
| Frontend TS/TSX validation | Build-time UI safety | transpiles all frontend TypeScript/TSX |
| Report compatibility contract | Report ingestion | v1, unversioned legacy, sparse v2, future-version rejection |
| Findings explainability contract | Operator trust | evidence vs policy separation, confidence/basis, guidance sections |

## Stable live-PCAP expectations

The live PCAP runner currently freezes these stable finding totals:

| Dataset | Expected findings |
| --- | ---: |
| 01 Mixed OT baseline | 4 |
| 02 Legacy high-risk | 19 |
| 03 Outbound/IPv6/QUIC/ICMP | 12 |

These totals are useful regression signals, but semantic assertions in the manifests are more important than the totals themselves.

## Synthetic semantic-suite expectations

- Dataset 04: 6 expected control/discovery findings.
- Dataset 05: 4 weird-protocol findings + 3 VLAN/double-tag findings; all 75 modules complete on degraded input.
- Dataset 06: 16 threshold/boundary cases.
- Dataset 07: 11 temporal/state-isolation cases.
- Dataset 08: 12 policy-precedence/conflict cases.
- Dataset 09: 11 determinism/reproducibility cases.
- Dataset 10: 10 performance/scale cases.
- Dataset 11: 8 failure-recovery/cancellation cases.
- Dataset 12: 9 input-security cases.
- Dataset 13: 13 UI-workflow resilience cases, including one-pass Zeek evidence-token reuse.
- One-pass Zeek evidence reuse: lifecycle/binding hardening plus a real repeated-analysis test that reuses one extracted Zeek directory across three Detection Contexts, requires context-dependent detector outcomes, fingerprints every retained evidence file before/after each analysis, and asserts the Zeek invocation count remains one.
- Dataset 14: 10 mixed-OT acceptance assertions with all 75 modules completing.
- Dataset 15: raw-PCAP/Zeek acceptance for all five Wave 1 detectors; requires a live Zeek runtime.
- Dataset 16: raw-PCAP/Zeek acceptance for all five Wave 2 detectors; requires a live Zeek runtime.
- Dataset 17: raw-PCAP/Zeek acceptance for all five Wave 3 detectors; requires a live Zeek runtime.
- Dataset 18: operator-run real-site validation harness; intentionally has no frozen finding count and is not part of the automatic gate.

## What should trigger a new dataset

Add a new dataset only when one of these occurs:

- a real capture exposes a behavior not represented here;
- production-backend incorporation changes a contract boundary;
- a detector bug requires a permanent regression fixture;
- a new detector family or protocol is added;
- an operational scale profile materially exceeds Dataset 10.

| Finding calibration coverage | Triage consistency | all 75 modules classified; explicit policy/control violations outrank derived baseline drift; evidence strength constrains confidence |
