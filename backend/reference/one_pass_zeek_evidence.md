# One-pass Zeek evidence reuse

## Goal

A selected PCAP should normally be processed by Zeek once. Detection Context discovery and detector execution consume the same immutable Zeek evidence.

## Interactive contract

### 1. Extract evidence / discover context

`POST /api/v1/pcap-context-discovery` receives the PCAP. The reference backend:

1. runs the comprehensive eleVADR Zeek runtime profile once;
2. retains the generated Zeek log directory;
3. parses those logs to produce observed-only Detection Context suggestions;
4. returns an opaque `evidenceToken` with the discovery result.

The token references server-side evidence only. It is not a filesystem path and the frontend cannot choose the evidence directory.

### 2. Review policy

The user may create, load, or edit a Detection Context. Policy edits do not mutate the retained Zeek logs and do not trigger a new Zeek extraction.

### 3. Analyze

`POST /api/v1/pcap-analysis` normally receives multipart fields:

- `profile`: normalized Detection Context v3 JSON;
- `evidenceToken`: token returned by context discovery;
- `sourceFilename`: original PCAP display name;
- `evidencePcapSha256`: PCAP SHA-256 returned with the discovery result.

The frontend does not re-upload the PCAP in this path. Before accepting reuse, the backend verifies that the token is still live, the original filename and PCAP SHA-256 match the retained record, the evidence directory still exists, and the current Zeek runtime/policy signature matches the extraction signature. The backend then loads the retained logs, compiles the reviewed policy, runs the selected detector modules, and builds the canonical report.

For compatibility, the endpoint still accepts `file` + `profile` when no evidence token is available. That direct path performs a fresh Zeek extraction.

## Invalidation

A new evidence extraction is required when:

- a different PCAP is selected;
- retained evidence expires or the reference server restarts;
- the Zeek extraction runtime/policy changes and a new workflow is started.

Detection Context edits alone do not invalidate evidence.

## Reference-server retention

The local server retains evidence for two hours by default. Override with `ELEVADR_EVIDENCE_TTL_SECONDS`. Evidence lives under a managed cache root (`ELEVADR_EVIDENCE_CACHE_ROOT` may override it). Active analysis jobs hold read leases so expiry cleanup cannot remove logs mid-analysis; multiple analyses may safely reuse the same immutable evidence concurrently. Expired evidence is removed after the final lease releases. On reference-server startup, orphaned evidence directories from the previous process are deleted because process-local tokens are intentionally not valid across restarts. Cached evidence is also deleted on clean shutdown. Production storage, access control, quotas, and job persistence belong to the production backend.

## Provenance

Reports produced from the reuse path record:

- `zeek_evidence_reused: true`;
- PCAP SHA-256;
- Zeek runtime-policy SHA-256;
- evidence creation time;
- the ephemeral evidence ID used for the local job.

The hashes make it possible to demonstrate that context discovery and detector analysis were based on the same extraction inputs/configuration.

## Security/policy boundary

Zeek evidence is observation. It can prepopulate or suggest context, but it never creates authorization. Trusted infrastructure, approved egress, allowed segment paths, Purdue assignments, and Authorized Control Actions remain human-reviewed policy.

## Lifecycle hardening

The reference implementation regression suite covers expired and stale tokens, token tampering, wrong-PCAP filename/hash binding, concurrent readers, restart-orphan cleanup, missing evidence directories, repeated analysis with different Detection Contexts, and Zeek runtime/policy signature changes. The repeated-analysis coverage performs one real retained-evidence extraction and then applies multiple distinct Detection Contexts to the same Zeek directory; detector outcomes are allowed to change with policy, while a SHA-256 fingerprint of every retained evidence file must remain byte-for-byte identical and the Zeek extraction count must remain exactly one. Detection Context changes do not alter or broaden the retained evidence identity.
