# Release-readiness and handoff checklist

This document summarizes the state of the isolated `backend_bryan` implementation before production-backend incorporation.

## Status

The Detection Context + PCAP workflow has reached a mature synthetic-regression baseline. The implementation has coverage for request/response contracts, Zeek parsing, policy compilation, all 75 detectors, report construction, report compatibility, frontend workflow contracts, cancellation/failure behavior, deterministic output, and scale behavior.

The remaining work is primarily **production incorporation and operationalization**, not continued synthetic-dataset expansion.

## Executable release preflight

Release-critical assumptions are now enforced by `python -m backend_bryan.integration.release_preflight` and run as stage 1 of the full regression gate. The preflight fails on detector/snapshot drift, incomplete calibration coverage, API schema/version drift, Zeek image drift, local launcher/API port drift, missing release artifacts, or a malformed Dataset 19 tripwire manifest.

The local reference server also exposes `GET /health` with detector count, request/response contract versions, resolved Zeek runtime status, and retained-evidence TTL for operator diagnostics.

### Hardened release invariants

- The runtime, Windows launcher, Docker preparation script, and backend Dockerfile use the same pinned Zeek image: `zeek/zeek:9.0.0`.
- The Windows local launcher and frontend Detection Context/PCAP endpoints use port `8765` consistently.
- The detector registry snapshot is generated from and synchronized with all 75 current modules.
- Dataset 19 remains the release false-positive tripwire: normal simulated site behavior must remain quiet while the deliberate unauthorized Modbus write and rogue DHCP behavior remain detectable.

## Production incorporation checklist

### Backend ownership

- [ ] Port `adapters/detection_context_adapter.py` into a production-backend-owned package.
- [ ] Port the request validation semantics from `integration/api_contract.py`.
- [ ] Port the orchestration semantics from `integration/analysis_service.py` and `integration/pcap_analysis.py`.
- [ ] Preserve per-detector failure isolation.
- [ ] Preserve cooperative cancellation semantics or map them to the production job framework.
- [ ] Preserve canonical report construction semantics from `integration/report_builder.py`.
- [ ] Decide whether the vendored detector package remains vendored or is replaced by a production dependency; keep the 75-module registry contract synchronized.

### Security and policy invariants

- [ ] Preserve the rule that Zeek observations never create authorization.
- [ ] Keep Authorized Control Actions path/function scoped.
- [ ] Keep trusted infrastructure service scoped rather than host-wide.
- [ ] Keep external-destination approvals detector/scope appropriate.
- [ ] Keep advanced module overrides explicit and backend-owned.
- [ ] Reject unknown/future contract versions.
- [ ] Keep request-size, nesting-depth, network-value, and filename validation at the production request boundary.

### API and jobs

- [ ] Map `POST /api/v1/detection-analysis` semantics to the production API.
- [ ] Map PCAP analysis/context-discovery job status and cancellation to the production job framework.
- [ ] Ensure stale/unknown job IDs cannot mutate active jobs.
- [ ] Ensure failed/canceled runs never publish a partial report as a completed result.
- [ ] Ensure temporary upload/Zeek artifacts are cleaned on completion, failure, and cancellation.

### Frontend compatibility

- [ ] Preserve the existing request envelope and version strings or deliberately version them.
- [ ] Keep generated PCAP reports on the same frontend normalization/viewing path as selected JSON reports.
- [ ] Keep report compatibility normalization centralized in the frontend.
- [ ] Preserve graceful loading of v1/unversioned legacy reports and rejection of unsupported future major versions.

### CI acceptance

Before production merge, the backend maintainer should port or invoke equivalent checks for:

- [ ] all 75 detector modules;
- [ ] Datasets 04â€“14 semantic suites;
- [ ] live PCAP Datasets 01â€“03 with Zeek;
- [ ] frontend/backend request contract;
- [ ] canonical report compatibility;
- [ ] findings explainability contract;
- [ ] deterministic report output;
- [ ] failure/cancellation cleanup and retry isolation.

## Development runtime

The reference runtime resolves Zeek in this order:

1. `ELEVADR_ZEEK_COMMAND`
2. native `zeek` on `PATH`
3. Docker fallback using `zeek/zeek:9.0.0`

The reference HTTP server is for local integration testing only and is not a production server implementation.

## Definition of ready for backend handoff

The handoff is ready when the production backend can accept the versioned Detection Context analysis request, compile policy server-side, execute the detector registry, return the canonical report/analysis response, support PCAP jobs and cancellation, and pass the same semantic invariants represented in the regression suite.

## Definition of ready for field validation

After production incorporation, the next meaningful dataset should be based on a sanitized operational capture. It should be added only when it exercises behavior not already represented by Datasets 01â€“17.

## Additional detector waves (75-module baseline)

The release-ready detector registry now includes five additional modules beyond the original 60-detector baseline:

- `arp_ip_mac_identity_change`
- `unexpected_dhcp_server`
- `ot_protocol_role_reversal`
- `plc_rtu_peer_change`
- `engineering_workstation_control_burst`

The original three live PCAP regression captures remain intentionally frozen as a legacy 60-detector baseline so their historical semantic counts remain comparable. Dataset 14, registry-wide state/scale checks, the Wave 1/Wave 2/Wave 3 acceptance stages, and raw-PCAP Datasets 15â€“17 exercise the current 75-module registry.
