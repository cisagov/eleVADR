# Known limitations and non-goals

These are deliberate boundaries of the current handoff checkpoint.

## Reference backend is not the production backend

`backend_bryan` is an isolated implementation and integration reference. `integration/http_reference_server.py` is a local development server, not a hardened production web service. Production concerns such as organizational authentication/authorization, centralized audit logging, deployment topology, enterprise observability, and production job persistence must be supplied by the production backend.

## Synthetic coverage is mature, not exhaustive

Datasets 01–19 provide broad coverage, including Dataset 19 as a four-hour site-like false-positive tripwire. Datasets 01–03 and Datasets 15–17 are raw PCAP/Zeek regression captures; Datasets 04–14 are deterministic semantic/robustness fixtures. Datasets 15–17 are intentionally synthetic packet data, so they validate packet-to-Zeek plumbing for the fifteen added detectors but do not replace field validation against sanitized operational captures.

## Zeek version is pinned for development reproducibility

The Docker fallback is `zeek/zeek:9.0.0`. A production Zeek upgrade should be treated as a compatibility event and validated against the live PCAP regression pack because log schemas and analyzer behavior can change.


## Retained Zeek evidence is local and temporary

The reference server keeps one-pass Zeek evidence in a local temporary cache keyed by an opaque token. The default lifetime is two hours and the cache is lost when the reference server exits. This is suitable for local development; a production backend should provide its own durable/job-scoped evidence lifecycle, access controls, cleanup policy, and storage quotas. Detection Context edits do not invalidate evidence, but changing the PCAP or the Zeek extraction configuration requires a new extraction.

## Detector registry is a snapshot

The vendored detector package currently contains exactly 75 modules. Adding/removing/changing detectors requires updating the registry snapshot, contract expectations, and affected regression fixtures. The handoff does not provide an automatic upstream detector synchronization mechanism.

## Performance checks are regression ceilings, not capacity guarantees

Dataset 10 uses intentionally generous timing/memory ceilings to detect major regressions. It is not a formal load test, concurrency benchmark, or production sizing study. Production capacity must be measured in the target deployment environment with representative capture sizes and concurrent-job counts.

## Cancellation is cooperative

The reference job APIs implement cooperative cancellation. Production infrastructure may need stronger process/container termination semantics for long-running Zeek or detector work, while still preserving cleanup and no-partial-report guarantees.

## Frontend gate is not a full cross-browser E2E suite

The standard gate transpiles TS/TSX and runs focused contract-style checks for report compatibility, explainability, and workflow resilience. It does not replace browser automation across all supported browsers, accessibility tooling, or visual-regression testing.

## Report compatibility is intentionally bounded

The frontend compatibility layer supports current v2, legacy v1, and selected unversioned legacy shapes. Unsupported future major versions fail closed. It intentionally does not guess arbitrary historical or future schemas.

## Detection Context suggestions remain suggestions

Zeek discovery can suggest assets, communication pairs, services, roles, and Purdue-related context, but observed traffic must not silently authorize control actions, external destinations, DHCP/IPv6 policy, or segment paths. Human-reviewed authoritative context remains required.

## Next real-world dataset is reserved for operational validation

Do not add another synthetic dataset solely to increase coverage count. Dataset 19 is the final synthetic site-like scenario in the current release candidate. The next dataset should represent a sanitized real capture or a production-integration issue that exposes genuinely new behavior.
