# Detection analysis API contract

This directory is the framework-neutral integration contract for the future production backend.

## Endpoint shape

Reference route: `POST /api/v1/detection-analysis`

The route name is a recommendation, not a requirement. The JSON contracts are the stable part.

### Request

- Contract: `elevadr.detection-context.analysis.v1`
- `profile`: required normalized Detection Context v3 profile.
- `logs`: optional normalized Zeek rows keyed by AnalysisContext log name.

`profile` is policy/context. `logs` are analysis evidence. The backend must never infer authorization from `logs`.

### Response

- Contract: `elevadr.detection-context.analysis-response.v1`
- `status`: `completed`, `partial`, or `failed`.
- `summary`: requested/completed/failed module counts and total finding count.
- `moduleResults`: normal serialized detector ModuleResult objects.
- `errors`: structured request/module errors.

A single detector exception produces `partial` when other detectors succeeded. This prevents one module from erasing otherwise valid analysis output.

## HTTP guidance

Suggested behavior:

- `200` for `completed` or `partial` analysis responses.
- `400` for malformed/unsupported request contracts.
- Authentication/authorization and upload-size limits belong to the production backend and are intentionally not prototyped here.

## Versioning

Changing the request envelope incompatibly requires a new request `contractVersion`. Changing the response envelope incompatibly requires a new response contract version. Detector metadata changes remain backend-internal and do not require a frontend contract change unless the user-facing Detection Context schema changes.


## Finding provenance

Findings returned by the reference analysis service include a `provenance` object identifying supporting Zeek log types, parsed record indexes, and retained field/value pairs. The same object is mirrored at `metadata.zeek_provenance` for metadata-oriented consumers. See `../finding_provenance.md`.
