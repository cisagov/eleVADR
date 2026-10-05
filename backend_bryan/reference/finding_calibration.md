# Finding severity and confidence calibration

Every built-in eleVADR detector is assigned to exactly one calibration family. Calibration runs after a detector creates findings and before finding-level Zeek provenance is attached. It does not decide whether a detector fires and does not change detector thresholds, Detection Context policy, or underlying Zeek evidence.

The current calibration policy is version `1.0` and covers all 75 registered detector modules.

## Core rules

- **Explicit policy/control violations outrank behavioral drift.** When a policy-sensitive control or infrastructure detector explicitly identifies activity as unauthorized, unapproved, forbidden, outside an allowed path, or outside trusted infrastructure, severity is at least `high`. When that violation is backed by a native Zeek protocol/service record, confidence is `high`.
- **Derived baseline drift remains contextual.** Findings from baseline-drift modules that are based on derived or heuristic evidence are capped at `medium` severity and `medium` confidence unless the finding also represents an explicit policy violation.
- **Evidence strength calibrates confidence.** Port-only and heuristic evidence cannot claim `high` confidence. Native `protocol_log` or `zeek_service` evidence cannot remain `low` confidence.
- **Direct control actions remain actionable.** A directly observed control action backed by protocol/service evidence is never triaged below `medium` severity, even when no explicit allow/deny policy is configured.
- **Critical is never invented by calibration.** A detector must make its own stronger assertion before a finding can remain `critical`.

## Audit metadata

Each calibrated finding records its decision under `finding.metadata.calibration`:

```json
{
  "version": "1.0",
  "family": "control_policy",
  "original_severity": "medium",
  "severity": "high",
  "original_confidence": "medium",
  "confidence": "high",
  "explicit_policy_violation": true,
  "adjusted": true,
  "reasons": [
    "explicit policy/control violation floors severity at high",
    "direct evidence of explicit policy violation floors confidence at high"
  ]
}
```

The calibrated top-level `severity` and `confidence` remain the values consumed by report sorting, filtering, and finding presentation. The original detector values remain available in the calibration record for auditability.

## Registry coverage

The calibration test fails if the built-in detector registry and calibration profile map diverge. Extension/test modules outside the built-in registry are left unchanged and marked `unclassified` when mutable finding metadata is available; they do not cause the analysis service to fail.
