# eleVADR canonical regression harness

This directory freezes the three live PCAP scenarios plus normalized semantic/robustness fixtures used while hardening the Detection Context and 75-module analysis path.

`python -m backend_bryan.regression.runner --mode live` runs each PCAP through the same `analyze_pcap_to_report()` path used by the reference PCAP API: Zeek, Detection Context compilation, all selected detectors, and canonical report construction.

`python -m backend_bryan.regression.runner --mode fixture` validates the manifests against the last known-good reference reports without requiring Zeek or Docker. This is useful for testing manifest/check logic itself; it is not a substitute for a live PCAP run.

Each manifest checks the overall finding count, all 60 original modules completing with zero detector errors, important module-level finding counts, host classification totals, and selected semantic assertions. The manifests intentionally focus on stable behavioral expectations rather than timestamps, generated report IDs, or Zeek UIDs.

From the repository root on Windows, run `run_regression_tests.bat`. The current 22-stage gate executes the backend unit suite, the three frozen legacy live PCAP regressions, Datasets 04-17, focused Wave 1/Wave 2/Wave 3 detector acceptance, frontend TS/TSX transpilation validation, the report compatibility contract, and the findings explainability UX contract check. A working Zeek runtime is required for the live PCAP stage; the normal runtime preference remains `ELEVADR_ZEEK_COMMAND`, native Zeek, then Docker using `zeek/zeek:9.0.0`. See `../reference/test_matrix.md` for the handoff coverage map.

## Windows notes

`run_regression_tests.bat` adds `frontend\node_modules` to `NODE_PATH` before running pytest so Node helpers spawned by Python can resolve the frontend-local TypeScript installation. The PCAP pipeline tests invoke their fake Zeek fixture through the active Python interpreter rather than executing a POSIX shebang file directly, which keeps those tests portable on Windows.

## Findings explainability regression coverage

`frontend/src/tests/FindingsExplainability.test.tsx` covers the finding-details explainability behavior: observed evidence remains distinct from authoritative Detection Context policy, the five explainability sections render, older reports degrade gracefully when confidence/context metadata is absent, and the findings table preserves confidence/detection-basis display and selection behavior.

`validate_findings_explainability.cjs` is a lightweight gate that runs without a browser test runner and protects the critical UI/policy-separation contract during the standard regression command. The TS/TSX validator also transpiles the Vitest regression file so type/syntax regressions are caught by the same gate.

## Report compatibility gate

The frontend now routes both directly selected JSON reports and PCAP-generated reports through `frontend/src/app/utils/reportCompatibility.ts` before the report enters the viewer. The compatibility layer accepts canonical v2 reports, legacy v1 reports, and unversioned legacy reports with selected camelCase aliases. Missing optional/derived panels receive empty structural defaults; findings, devices, policy, and provenance are never invented. Unsupported future major versions are rejected instead of guessed.

`backend_bryan/reference/elevadr_report_v2.schema.json` documents the canonical v2 top-level/module contract for backend handoff. `validate_report_compatibility.cjs` executes the actual TypeScript normalizer against frozen fixtures during the standard gate.

## Dataset 04

Dataset 04 is a normalized protocol-log semantic fixture rather than a synthetic PCAP. It deliberately supplies explicit Modbus, S7comm, EtherNet/IP/CIP, SNMP SET, and BACnet discovery evidence while authorizing a different management source. This protects the core rule that observed control traffic does not create authorization. The fixture also checks SNMP credential redaction and BACnet burst/non-BAS discovery behavior. It complements, rather than replaces, the three live PCAP/Zeek datasets.


## Dataset 05

Dataset 05 exercises malformed/partial Zeek evidence without depending on a synthetic PCAP. Its fixture contains short and over-wide ASCII rows, invalid numeric values, malformed and non-object JSON-lines entries, a whole log missing its `#fields` header, partial Modbus records, explicit VLAN mismatch/double-tag evidence, and representative `weird.log` anomalies.

The vendored Zeek parser now isolates a malformed log instead of aborting the full directory load, skips malformed JSON-lines records while retaining valid neighboring records, accepts short/extra-value ASCII rows, and records data-quality details under `AnalysisContext.metadata["zeek_parse_diagnostics"]`. These diagnostics are observational metadata only and never create allowlists, segment permissions, or control authorization.

`python -m backend_bryan.regression.dataset05_runner` verifies parser diagnostics, expected `weird_protocol_violations` and `vlan_tag_mismatch_double_tag` findings, partial ICS-record retention, and that all 75 detector modules complete without exception on the degraded input.


## Dataset 06

Dataset 06 is a deterministic threshold/boundary semantic suite. It exercises exact-threshold, one-below, one-above/window-overrun, zero-byte, sparse-baseline, timestamp-window, and unusually large integer cases without requiring Zeek. The suite currently covers `large_outbound_http_uploads`, `unusual_outbound_data_volume`, `icmp_data_channel`, `brute_force_authentication`, and `high_fan_in_out`.

`python -m backend_bryan.regression.dataset06_runner` verifies that inclusive thresholds fire exactly at the configured boundary, values just below do not, 60-second windows remain inclusive at exactly 60 seconds but not beyond it, zero-byte outbound flows do not create findings, sparse outbound baselines use the absolute floor, and unusually large byte counts remain safe and produce the expected severity.


## Dataset 07

Dataset 07 hardens temporal and cross-run behavior for the singleton detector registry. It verifies out-of-order timestamp handling, duplicate-row behavior where unique timestamps are the intended unit, exact baseline-boundary ties, directional communication-matrix semantics, repeated-run determinism, and state isolation between analyses.

`python -m backend_bryan.regression.dataset07_runner` currently exercises beaconing, brute-force windows, new-service emergence, new OT conversation pairs, OT asset gone-silent cadence, and selected threshold/baseline detectors. It also runs a registry-wide isolation check across all 75 detector instances: an empty analysis result is captured, a trigger-rich context is processed, then the empty analysis is repeated and must match exactly. A final guard confirms detectors do not mutate the shared `AnalysisContext`, so one module cannot alter another module's evidence or policy view.


## Dataset 08

Dataset 08 hardens Detection Context precedence when authoritative inputs disagree. It covers overlapping CIDRs and longest-prefix identity, explicit detector policy versus segment/asset identity, observed communications versus explicit control authorization, service-scoped trusted infrastructure, detector-scoped segment exceptions, destination-scoped external approvals, generic allowed-host scope, advanced module override precedence, and Zeek-observed assets remaining non-authoritative.

`python -m backend_bryan.regression.dataset08_runner` verifies 12 policy-precedence/conflict cases. The suite protects the core rule that observations never create authorization while also making explicit which authoritative policy layer wins when first-class Detection Context values and advanced per-detector overrides conflict.

## Dataset 09: report determinism / reproducibility

`python -m backend_bryan.regression.dataset09_runner` verifies that canonical v2 report content is reproducible when connection rows, detector results, detector findings, detector errors, Zeek log-type maps, or Detection Context mapping keys arrive in different orders. The report builder now applies deterministic ordering to those derived report structures while preserving the Detection Context's semantically ordered lists. The regression comparison excludes only the intentionally volatile `report_id` and `analysis_provenance.generated_at` fields. Combined permutations must otherwise produce byte-identical normalized report content.

### Dataset 10 - Performance and scale behavior

`dataset10_runner.py` provides a deliberately synthetic scale gate. It is a regression tripwire, not a micro-benchmark: timing and memory ceilings are intentionally generous so normal workstation variance does not create flaky failures. It verifies large connection volumes, large authoritative asset inventories, oversized communication/context collections, thousands of findings, deterministic scaled report output, Detection Context compilation, and an all-70-detector benign scale pass. The workload preserves the same policy rule as the rest of eleVADR: observed communication at scale never becomes control authorization.

## Dataset 11: failure recovery / cancellation

`dataset11_runner.py` protects partial-analysis and job-lifecycle behavior. It verifies per-detector exception isolation, stale job isolation, cooperative PCAP/context-discovery cancellation, Zeek-runtime failure reporting, temporary-file cleanup, absence of partial report publication on failure/cancel, and fresh state on retry. The reference server now accepts `DELETE` on a job URL to request cooperative cancellation.

## Dataset 12: input / security hardening

`dataset12_runner.py` exercises hostile/path-like upload filenames, malformed and oversized `Content-Length`, non-finite JSON numbers, deeply nested request objects, invalid CIDRs/IPs/ports, and oversized Detection Context collections. The isolated reference server normalizes uploaded filenames before provenance use and enforces developer-server request-size ceilings before reading request bodies.

## Dataset 13: UI workflow resilience

`dataset13_runner.py` protects the PCAP/JSON workflow contract at the frontend boundary: both report sources use the same compatibility normalizer, failed/canceled PCAP jobs cannot publish a report, job cancellation is exposed in the analysis progress UI, Detection Context create/delete stays in the PCAP chooser, Home is the explicit report-reset action, legacy-report normalization remains centralized, responsive breakpoints remain present, and Share/Print/Export remain report-scoped actions.

## Dataset 14: mixed OT acceptance

`dataset14_runner.py` is the synthetic acceptance scenario for the complete 75-detector request path. It combines IT/OT Purdue segments, authoritative and observed-only assets, trusted DNS/NTP infrastructure, approved external egress, an explicitly authorized Modbus write, an observed-but-unauthorized neighboring Modbus write, S7/CIP/SNMP/BACnet anomalies, and weird-protocol evidence. All 75 modules must complete with zero detector errors while authorization and observation remain distinct.

## Additional detector acceptance

`python -m backend_bryan.regression.new_detector_acceptance_runner` verifies the current 75-module registry and focused semantics for the five post-baseline detectors: ARP/IP-MAC identity change, unexpected DHCP server, OT protocol role reversal, PLC/RTU peer change, and engineering-workstation control bursts. The original live PCAP datasets 01-03 remain frozen at the original 60-detector selection for historical comparability.


## Dataset 15: raw-PCAP validation for the five added detectors

`python -m backend_bryan.regression.dataset15_runner` runs `15_new_detector_raw_pcap.pcap` through the same PCAP -> Zeek -> Detection Context -> detector -> canonical-report path used by the reference API. The fixture includes ARP identity change, a rogue DHCP transaction, five authorized Modbus write-single-register operations from an engineering workstation, a post-baseline PLC role reversal, and a post-baseline new controller peer.

The Zeek runtime loads `backend_bryan/runtime/elevadr_runtime.zeek`, which explicitly enables the built-in ARP packet analyzer and writes an `arp.log` stream consumed by the ARP/IP-MAC detector. Dataset 15 asserts that `conn.log`, `modbus.log`, `dhcp.log`, and `arp.log` are all produced from the raw PCAP and that each of the five added detectors produces the expected semantic finding. The fixture builder is `dataset15_fixture_builder.py` and uses only the Python standard library so the PCAP can be reproduced without Scapy.


## Dataset 16: raw-PCAP validation for Wave 2 detectors

`python -m backend_bryan.regression.dataset16_runner` runs `16_wave2_raw_pcap.pcap` through the normal PCAP -> Zeek -> Detection Context -> detector -> canonical-report path. The fixture contains trusted and untrusted DNS/NTP exchanges, a 20-target ARP sweep, three separate OT multicast flows to an unapproved group, and ten responder-reset TCP connection attempts inside a 60-second window.

Dataset 16 requires Zeek to produce `conn.log`, `dns.log`, `ntp.log`, and the eleVADR `arp.log`. It verifies all five Wave 2 detectors from raw packet evidence. The dataset also protects a live-integration fix in `tcp_reset_abort_surge`: the detector consumes the parser's native `zeek_state` field as well as normalized test aliases. Observed resolver/time-source/multicast traffic remains evidence only and never creates trusted infrastructure or allowed multicast policy.


## Dataset 17: raw-PCAP validation for Wave 3 detectors

`python -m backend_bryan.regression.dataset17_runner` runs `17_wave3_raw_pcap.pcap` through the normal PCAP -> Zeek -> Detection Context -> detector -> canonical-report path. The fixture contains three baseline TLS sessions followed by an SNI/fingerprint change, an authorized management source that expands from one RDP target to two new targets, an OT service replacement, a polling cadence shift from 10-second to 30-second intervals, and a controller communication series whose post-baseline timing variance increases sharply.

Dataset 17 requires Zeek to produce `conn.log` and `ssl.log` from the raw packet capture. It verifies all five Wave 3 detectors from packet evidence while keeping learned TLS fingerprints, newly observed remote-access targets, service identity, polling cadence, and timing jitter observational only. None of those observations are promoted into trusted policy or authorization.

## Dataset 18: real-site validation and analyst tuning harness

Dataset 18 is intentionally **not** part of the automatic regression gate because it is driven by a representative site PCAP and a matching analyst-authored Detection Context rather than a synthetic fixture. Run it with `run_real_site_validation.bat <pcap> <context.json> [output-dir]` or `python -m backend_bryan.regression.dataset18_real_site_runner --pcap ... --context ...`.

The harness runs the normal PCAP -> Zeek -> Detection Context -> 75-detector -> canonical report path, then writes `canonical_report.json`, `coverage_summary.json`, `finding_review.csv`, `missed_detection_review.csv`, and review instructions. The finding worksheet deliberately leaves analyst disposition and tuning action blank. Observed traffic never becomes authorization merely because it appears in the capture. Analysts should record independently known legitimate expectations in the Detection Context only after validation.

After analyst review, `--summarize-review finding_review.csv` creates `analyst_review_summary.json` with counts and candidate modules for false-positive/noise investigation. Tuning candidates are review inputs, not automatic policy changes.

## Raw-PCAP corpus rehearsal without a site capture

When a sanitized operational PCAP is not yet available, use the checked-in raw-PCAP corpus as the packet-to-Zeek rehearsal pack rather than creating a synthetic Dataset 18.

Run the fast integrity/reproducibility check without Zeek:

```bash
python -m backend_bryan.regression.synthetic_pcap_corpus
```

This verifies all six checked-in raw-PCAP fixtures (Datasets 01-03 and 15-17), their matching Detection Context files, frozen SHA-256 identities, basic PCAP structure, and deterministic rebuilds for generated Datasets 15-17.

Run the complete raw-PCAP corpus through the live Zeek path with:

```bat
run_synthetic_pcap_validation.bat
```

or on Linux/macOS:

```bash
./run_synthetic_pcap_validation.sh
```

The live command executes the frozen Datasets 01-03 regression pack plus Datasets 15-17. It is a development rehearsal only; it does not replace Dataset 18 operational validation. When a sanitized real-site capture becomes available, keep using `run_real_site_validation.*` and the operator review worksheets instead of tuning policy from synthetic observations.

## Dataset 19: four-hour site-like OT false-positive tripwire

`python -m backend_bryan.regression.dataset19_runner` runs a deterministic four-hour raw PCAP through the normal PCAP -> Zeek -> Detection Context -> 75-detector -> canonical-report path. Unlike Datasets 15-17, Dataset 19 is designed primarily to stay quiet during legitimate operations. It includes 60-second Modbus polling, internal DNS and NTP, approved multicast telemetry, routine ARP refreshes, DHCP lease renewal, repeated scheduled RDP maintenance to a stable target, and one explicitly authorized maintenance write.

Two deliberate anomalies are injected late in the capture: an unauthorized Modbus write from a known contractor workstation and DHCP server responses from that same untrusted host. The manifest in `fixtures/19_site_like_multi_hour_ot_manifest.json` names the expected detector modules. The live runner fails when an expected anomaly is missed or when any module outside the reviewed anomaly allowlist produces a finding, making Dataset 19 a full-registry false-positive regression tripwire.

The fixture is generated by `dataset19_fixture_builder.py` using only the Python standard library and existing deterministic packet helpers. It contains 2,253 packets spanning just over 14,400 seconds. Its SHA-256 identity and byte-for-byte deterministic rebuild are checked by both `test_dataset19_regressions.py` and the synthetic PCAP corpus verifier.
