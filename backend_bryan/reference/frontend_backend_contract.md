# Frontend -> backend Detection Context analysis contract

## Goal

There is one request boundary, one authoritative policy compiler, and one response boundary.

```text
Frontend Detection Context UI
        |
        | DetectionAnalysisRequest v1
        | profile = site context/policy
        | logs    = optional analysis evidence
        v
Backend request validation
        |
        v
Authoritative profile adapter
        |
        v
AnalysisContext(metadata + Zeek logs)
        |
        v
selected detector modules
        |
        | DetectionAnalysisResponse v1
        v
Frontend/report consumer
```

## Ownership

### Frontend owns

- profile creation/editing
- schema v1/v2 -> v3 migration
- UI validation
- Zeek observation collection
- readiness guidance
- serialization of a normalized v3 profile into the versioned request
- typed submission/parsing through `analysisClient.ts`

### Backend owns

- every detector metadata alias
- every detector policy namespace
- conversion of frontend profile fields to detector fields
- module-specific allow/ignore routing
- `AnalysisContext.metadata`
- detector execution
- isolation and reporting of module failures

## Request

Contract version: `elevadr.detection-context.analysis.v1`

```json
{
  "contractVersion": "elevadr.detection-context.analysis.v1",
  "profile": { "schemaVersion": 3 },
  "logs": {
    "connections": [],
    "dns": [],
    "s7comm": []
  }
}
```

`logs` is optional. This allows the same profile artifact to be exported independently from analysis evidence. In production the backend may source logs through another upload/job mechanism, as long as the semantic distinction is retained.

## Response

Contract version: `elevadr.detection-context.analysis-response.v1`

```json
{
  "contractVersion": "elevadr.detection-context.analysis-response.v1",
  "status": "completed",
  "summary": {
    "requestedModules": 65,
    "completedModules": 65,
    "failedModules": 0,
    "findingCount": 0
  },
  "moduleResults": [],
  "errors": []
}
```

`partial` means at least one selected module completed and at least one module failed or was unavailable. `failed` means the request could not produce module results.

## Security invariant

Observed traffic is not authorization. Scanner observations and request `logs` may provide evidence to detectors but never create backend policy. Only explicit policy fields inside the v3 profile may create allowlists or control-write authorization.

## Compatibility rule

Changing a request or response envelope incompatibly requires a new corresponding contract version. Changing Detection Context requires a new `schemaVersion`. Detector metadata changes stay backend-internal unless the user-facing profile contract itself changes.
