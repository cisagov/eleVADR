# Backend handoff file manifest

Use this as a review map when incorporating the isolated implementation into the production backend.

| Area | Reference files | Production use |
| --- | --- | --- |
| Detection Context compiler | `adapters/detection_context_adapter.py` | Port semantics; production backend remains authoritative |
| Analysis contract | `integration/api_contract.py`, `reference/api_contract/` | Port validation/version behavior and schema documentation |
| Detector orchestration | `integration/analysis_service.py`, `integration/detector_runtime.py` | Port module selection, execution, and failure isolation |
| PCAP jobs | `integration/pcap_analysis.py`, `integration/context_discovery.py` | Map lifecycle/cancellation/cleanup to production jobs |
| Zeek runtime | `runtime/zeek_runtime.py` | Adapt runtime selection to deployment model |
| Canonical report | `integration/report_builder.py`, `reference/elevadr_report_v2.schema.json` | Preserve canonical v2 semantics/determinism |
| Detector runtime snapshot | `vendor/elevadr_modules/` | Replace or package deliberately; preserve tested module contract |
| Regression suite | `tests/`, `regression/` | Port into CI or invoke equivalently |
| Frontend boundary | `../frontend/src/app/components/DetectionConfiguration/analysisClient.ts` | Preserve versioned request/response semantics |
| Report compatibility | `../frontend/src/app/utils/reportCompatibility.ts` | Keep one common selected-JSON/generated-PCAP normalization path |

## Files that are reference-only

- `integration/http_reference_server.py` — local development/demo server, not production web-server code.
- `start_elevadr.bat`, `stop_elevadr.bat` — local workstation launch helpers.
- synthetic regression runners/fixtures — CI/reference assets rather than runtime production dependencies.

## Production backend protection

The `backend_bryan` implementation does not import or modify `eleVADR/backend/`. Preserve that separation during review until the backend maintainer deliberately ports the selected semantics into production-owned code.

- `reference/one_pass_zeek_evidence.md` — one-pass PCAP/Zeek evidence reuse contract, lifecycle, and provenance.
