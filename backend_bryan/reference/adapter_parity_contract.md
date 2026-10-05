# Detection Context Adapter Parity Contract

This document defines the compatibility gate between the frontend Detection Context v3 adapter and the isolated `backend_bryan` Python reference adapter.

## Ownership boundary

- `eleVADR/frontend/` owns the Detection Context UI, v3 profile model, scanner, readiness UX, and the TypeScript metadata compiler used by frontend-side tooling.
- `eleVADR/backend_bryan/` contains prototype/reference backend integration work only.
- `eleVADR/backend/` is not imported, modified, or required by these parity tests.

The Python adapter is a handoff/reference implementation. A backend maintainer may later incorporate or rewrite it in the production backend after review.

## Canonical input

The canonical input is a valid Detection Context profile with `schemaVersion: 3`, using the frontend field names defined in `frontend/src/app/components/DetectionConfiguration/types.ts`.

The parity fixtures live in `backend_bryan/reference/parity_profiles/` and cover:

1. minimal/empty context;
2. scanner-observed facts with no authorization;
3. IPv4-only capture policy and segment aliases;
4. explicit IPv6 allowance and an unknown Purdue value;
5. trusted DNS/NTP/DHCP/management infrastructure;
6. explicit ignored hosts, segment exceptions, and approved external destinations;
7. authorized Modbus, DNP3, S7comm, and EtherNet/IP/CIP control actions;
8. advanced module overrides;
9. a comprehensive mixed profile.

## Required parity

For every reference fixture, the TypeScript and Python adapters must produce structurally equal JSON metadata. Dictionary/object key ordering is irrelevant; list ordering is considered meaningful and must remain stable.

The parity gate is intentionally stricter than merely checking that all detector modules execute. It catches:

- wrong aliases such as `purdueLevel` vs `purdue_level`;
- wrong policy namespace names;
- booleans or numbers converted to strings;
- missing or extra policy blocks;
- allowlist deduplication drift;
- accidental changes in protocol-specific authorization shape;
- advanced override precedence changes.

## Security-sensitive invariants

Parity alone is not enough because both adapters could drift in the same unsafe direction. The test suite therefore asserts these invariants independently:

- scanner-observed communication is retained under `detection_context_observations` and never promoted to write authorization;
- observed DHCP does not imply DHCP authorization;
- generic Communications do not create `allowed_segment_pairs`;
- high-risk write authorization comes only from `authorizedControlActions`;
- trusted DNS/NTP/DHCP/management entries map only to semantically matching detector policies;
- unknown/unsupported Advanced Module Override namespaces are not blindly injected into metadata;
- explicit advanced overrides take precedence over compiled first-class policy where a supported namespace exists.

## Running the parity gate

From the directory containing `eleVADR/`:

```bash
PYTHONPATH=eleVADR python -m unittest backend_bryan.tests.test_adapter_parity -v
```

The frontend compiler helper requires Node.js and the `typescript` package. In a normal eleVADR frontend checkout, install frontend dependencies first if needed.

To compile one fixture through the real TypeScript adapter directly:

```bash
node eleVADR/backend_bryan/integration/compile_frontend_metadata.cjs \
  eleVADR/backend_bryan/reference/parity_profiles/comprehensive.json
```

## Change rule

Any future change to either adapter should update or add a fixture first. A mapping change is complete only when:

1. frontend and Python outputs match for every fixture;
2. semantic invariant tests pass;
3. the standalone 60-module detector contract test still passes.
