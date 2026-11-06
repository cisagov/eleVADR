# Backend API contract

## Core components

1. `adapters/detection_context_adapter.py` — authoritative v3 profile -> detector metadata compiler.
2. `integration/api_contract.py` — semantic request validation and structured contract errors.
3. `integration/analysis_service.py` — transport-neutral orchestration and per-module failure isolation.
4. `reference/api_contract/*.schema.json` — request/response documentation schemas.

`integration/http_reference_server.py` is the stdlib HTTP server that implements this contract. See `reference/known_limitations.md` for what it does and does not provide (e.g. it is not a hardened, horizontally-scaled web service).

## Request flow

```text
POST /api/v1/detection-analysis
        |
        v
request/auth/upload validation
        |
        v
Detection Context v3 adapter
        |
        v
AnalysisContext(metadata=..., Zeek logs=...)
        |
        v
selected detector modules
        |
        v
DetectionAnalysisResponse v1
```

## Invariants to preserve

- Backend is the only authoritative profile -> detector metadata compiler.
- Zeek logs/observations never become authorization.
- Generic communication observations never become `allowed_pairs` or `allowed_paths`.
- Explicit Authorized Control Actions are required for protocol write authorization.
- Per-module failures should be isolated and surfaced as structured errors.
- Unknown contract versions should fail closed.

## What the frontend expects

The frontend client stub is `frontend/src/app/components/DetectionConfiguration/analysisClient.ts`.
It expects a JSON response conforming to `elevadr.detection-context.analysis-response.v1`. The endpoint is resolved from `VITE_DETECTION_ANALYSIS_URL` when configured and otherwise defaults to `/api/v1/detection-analysis`. See `reference/local_frontend_testing.md` for the Windows/Vite development workflow.

## Test command

With the standalone detector package on `PYTHONPATH`:

```bash
PYTHONPATH=eleVADR:/path/to/zeek_modules \
python -m unittest discover -s eleVADR/backend/tests -v
```

The integration suite intentionally tests all 75 detector modules and the request/response boundary without importing or modifying `eleVADR/backend/`.
