# PCAP to eleVADR Report Workflow

The interactive PCAP workflow performs **one comprehensive Zeek extraction per selected PCAP** and reuses those logs for both Detection Context discovery and detector analysis. JSON and generated PCAP reports still converge on the same frontend report normalizer/viewer.

## Runtime flow

1. User selects `.pcap` or `.pcapng`.
2. The frontend uploads the capture to `POST /api/v1/pcap-context-discovery`.
3. `backend_bryan` runs the comprehensive eleVADR Zeek profile once and retains the generated Zeek evidence directory.
4. The same parsed evidence is used to build observed-only Detection Context suggestions. The discovery result includes an opaque `evidenceToken`.
5. The user chooses/creates/reviews the Detection Context. These policy edits do **not** invalidate the retained evidence.
6. The frontend posts the normalized profile plus `evidenceToken` and the discovery-returned PCAP SHA-256 to `POST /api/v1/pcap-analysis`; it does not re-upload the PCAP in the normal path.
7. The backend verifies the token lifetime, original PCAP filename/SHA-256 binding, retained evidence directory, and Zeek runtime/policy signature, then reparses the retained logs, applies Detection Context policy, runs the selected 75-detector registry, and builds canonical eleVADR v2 JSON. **Zeek is not run a second time.**
8. The frontend loads the generated JSON through the exact same compatibility normalizer/report state used by a directly selected JSON report.

The analysis endpoint remains backward-compatible: callers that do not have an evidence token may still submit a PCAP and profile, in which case the backend performs a fresh Zeek extraction.

## Evidence lifetime and invalidation

The local reference server keeps retained evidence in a managed server-side cache for two hours by default (`ELEVADR_EVIDENCE_TTL_SECONDS` can override this). A new PCAP selection creates new evidence. Detection Context changes do not. Active detector jobs lease immutable evidence so concurrent analyses cannot race with expiry cleanup. Restarting the reference server removes orphaned evidence from the prior process; cache expiry, a missing evidence directory, a PCAP identity mismatch, or a changed Zeek runtime/policy requires extraction again.

Each retained record captures the PCAP SHA-256 and Zeek runtime-policy SHA-256 for audit/provenance. The final report records `zeek_evidence_reused: true` when the one-pass path was used.

## Zeek runtime

The resolver in `backend_bryan/runtime/zeek_runtime.py` uses:

1. `ELEVADR_ZEEK_COMMAND` when explicitly configured.
2. Native `zeek` on `PATH`.
3. Docker with pinned `zeek/zeek:9.0.0`.

The first extraction enables the full eleVADR runtime policy (including ARP and other analyzers needed by the detector set), so later detector analysis does not need a policy-dependent second Zeek pass.

## Policy/evidence boundary

Retained Zeek evidence is immutable observation. Detection Context policy is applied only after evidence extraction. Observed communication, DHCP, services, assets, Purdue suggestions, or control traffic never create authorization by themselves.

## Progress behavior

Initial PCAP selection reports upload, Docker/runtime readiness, Zeek execution, log parsing, and Detection Context construction. After context review, analysis progress starts with **Reusing previously extracted Zeek evidence**, then policy compilation, detector execution, report construction, and report loading.
