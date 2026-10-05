# eleVADR backend_bryan handoff area

This directory contains the **isolated backend implementation of the simplified Detection Context architecture**. It is intentionally separate from the production backend so the backend maintainer can review and incorporate it later.

## Ownership boundary

- `eleVADR/frontend/` — Detection Context UI, Zeek scanner, profile schema/migration, validation, readiness, and request serialization.
- `eleVADR/backend_bryan/` — authoritative Detection Context v3 -> `AnalysisContext.metadata` compiler, request-boundary reference code, detector integration tests, examples, and handoff documentation.
- `eleVADR/backend/` — production backend owned by the backend maintainer. **Nothing here modifies or imports it.**
- `backend_bryan/vendor/elevadr_modules/` — bundled standalone detector package used for local test/runtime dependency; no system-wide install is required.

## Simplified runtime contract

```text
Frontend Detection Context v3
        |
        | DetectionAnalysisRequest
        | elevadr.detection-context.analysis.v1
        v
Backend request validator
        v
Authoritative Python adapter
        v
AnalysisContext.metadata
        v
75 detector modules
        v
Findings / report JSON
```

The frontend no longer contains an authoritative detector metadata compiler. It sends one normalized v3 profile. Detector aliases and policy namespaces are backend-owned.

## Important files

- `adapters/detection_context_adapter.py` — the **single authoritative reference compiler** from Detection Context v3 to detector metadata.
- `integration/analysis_request.py` — validates the versioned frontend request, compiles metadata, builds `AnalysisContext`, and provides reference module execution.
- `integration/analysis_context_integration_example.py` — example file-based backend incorporation path.
- `integration/build_frontend_analysis_request.cjs` — contract test helper that executes the real frontend request builder.
- `integration/verify_detector_package.py` — runs a versioned analysis request through the standalone detector registry.
- `tests/test_detection_context_adapter.py` — backend adapter behavior/regression tests.
- `tests/test_analysis_request_contract.py` — request envelope and authoritative compiler tests.
- `tests/test_frontend_backend_contract.py` — verifies real frontend requests cross the simplified boundary and remain backend-compilable.
- `tests/test_all_detector_modules.py` — detector package contract test.
- `tests/test_real_data_e2e.py` — known-finding and Detection Context suppression tests using real Zeek row payloads.
- `examples/input_profile.json` — representative Detection Context v3 profile.
- `examples/analysis_request.json` — representative versioned frontend/backend request.
- `examples/compiled_metadata.json` — backend-compiled metadata for reference.
- `reference/frontend_backend_contract.md` — canonical ownership and request contract.
- `reference/architecture.md` — simplified architecture diagram.
- `reference/module_policy_mapping.md` — backend-owned detector policy namespace mapping.
- `reference/metadata_contract.md` — backend mapping rules and security-sensitive non-mappings.
- `reference/contract_profiles/` — representative v3 contract fixtures.
- `reference/e2e/` — real-data request fixtures with deterministic finding expectations.
- `reference/real_data_analysis.md` — browser scan → API → detector → findings workflow.

## Critical security rule

**Observed traffic is not authorization.**

Scanner-derived communications remain observations. They never create `allowed_paths`, `allowed_pairs`, S7 write authorization, Modbus/DNP3 write authorization, or CIP write authorization. Those policies originate only from explicit profile policy fields or explicit Advanced Module Overrides.

## Run isolated tests

From the directory containing `eleVADR/`:

```bash
PYTHONPATH=eleVADR python -m unittest discover -s eleVADR/backend_bryan/tests -v
```

## Run the real 65-detector request contract

The runtime detector package is bundled under `backend_bryan/vendor/elevadr_modules`, so no external install is required. From `eleVADR/` run:

```bash
python -m backend_bryan.integration.verify_detector_package \
  backend_bryan/examples/analysis_request.json
```

A successful run reports a registry count of 65 with zero failures.

## Backend maintainer incorporation path

1. Review `reference/frontend_backend_contract.md`.
2. Move/adapt `integration/analysis_request.py` and `adapters/detection_context_adapter.py` into backend-owned packages.
3. Expose an API/job boundary that accepts `elevadr.detection-context.analysis.v1`.
4. Construct `AnalysisContext` only after backend compilation.
5. Return normal findings/report JSON to the frontend.
6. Port the tests into the backend CI suite.
7. Keep the observed-traffic-is-not-authorization regressions permanently.

## Compatibility target

- Analysis request: **elevadr.detection-context.analysis.v1**
- Detection Context schema: **v3**
- Detector registry snapshot: **75 modules**
- Reference detector package: bundled `backend_bryan/vendor/elevadr_modules/` from `elevadr-analysis-modules.zip`

## Formal API handoff contract

The isolated handoff now includes a complete request/response service boundary:

- `integration/api_contract.py` — version constants, request validation, log validation, structured contract errors.
- `integration/analysis_service.py` — transport-neutral orchestration with per-module failure isolation.
- `integration/http_reference_server.py` — optional stdlib demo server for `POST /api/v1/detection-analysis`; not production server code.
- `reference/api_contract/` — JSON Schema documentation for request and response.
- `reference/golden/` — completed, partial, and invalid request/response golden fixtures.
- `reference/backend_integration_handoff.md` — incorporation checklist for the backend maintainer.

The frontend counterpart is `analysisClient.ts`, which provides one typed `submitDetectionAnalysis()` boundary without importing backend code.

## Local frontend testing

See `reference/local_frontend_testing.md` for the opt-in Vite + reference API workflow.

## PCAP vertical slice

The reference backend exposes one-pass PCAP analysis for local end-to-end development. `POST /api/v1/pcap-context-discovery` uploads the PCAP, runs the comprehensive Zeek profile once, retains the resulting logs, and returns observed Detection Context suggestions plus an opaque evidence token and PCAP SHA-256. `POST /api/v1/pcap-analysis` normally receives that identity plus the reviewed Detection Context, verifies token lifetime/PCAP binding/runtime-policy compatibility, then reuses the retained Zeek logs without rerunning Zeek. Active analyses hold read leases so concurrent jobs cannot lose evidence to expiry cleanup. The 75-detector registry returns canonical eleVADR v2 JSON through the same frontend report loader used for directly selected JSON reports.

PCAP endpoints resolve Zeek in this order: `ELEVADR_ZEEK_COMMAND`, native `zeek` on PATH, then Docker using the pinned official image `zeek/zeek:9.0.0`. This keeps Windows development reproducible without requiring an unofficial native Zeek build.

## Final handoff documents

- `../HANDOFF.md` — repository-level handoff entry point.
- `reference/release_readiness.md` — production incorporation checklist.
- `reference/test_matrix.md` — Datasets 01–14 and gate coverage map.
- `reference/known_limitations.md` — explicit non-goals and remaining validation gaps.
- `reference/architecture.md` — current end-to-end architecture and policy/evidence boundary.

### Finding calibration

Built-in findings are normalized by a versioned 75-module severity/confidence calibration policy before report serialization. Explicit policy/control violations are prioritized above derived baseline drift, while evidence strength constrains confidence. Each finding retains an auditable `metadata.calibration` record. See `reference/finding_calibration.md`.
