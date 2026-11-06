from __future__ import annotations

from collections import defaultdict
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata

DEFAULT_PROTOCOLS = {"modbus", "dnp3", "s7comm", "s7", "enip", "ethernetip", "cip"}
MAX_EVIDENCE = 10


class OtProtocolRoleReversalModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="ot_protocol_role_reversal",
        name="OT Protocol Role Reversal",
        description="Detects hosts that are established as OT protocol responders during the baseline and later begin originating that protocol toward peers.",
        category="security_analysis",
        required_logs=("conn",),
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        policy = _policy(context.metadata)
        baseline_seconds = _as_float(policy.get("baseline_seconds")) or 300.0
        min_responder_events = _as_int(policy.get("minimum_baseline_responder_events")) or 2
        protocols = {str(x).lower() for x in policy.get("protocols", DEFAULT_PROTOCOLS)}
        rows = [_normalized(row) for row in context.connections]
        rows = [row for row in rows if row and row["service"] in protocols]
        if not rows:
            return ModuleResult(self.metadata.id, [], {"candidate_connections": 0, "findings": 0}, {"inspected_logs": ["conn"]}, [])

        times = [row["timestamp"] for row in rows if row["timestamp"] is not None]
        if not times:
            return ModuleResult(self.metadata.id, [], {"candidate_connections": len(rows), "findings": 0}, {"inspected_logs": ["conn"]}, ["No usable timestamps were available for baseline analysis."])
        capture_start = min(times)
        baseline_end = capture_start + baseline_seconds

        responder_counts: dict[tuple[str, str], int] = defaultdict(int)
        baseline_originators: set[tuple[str, str]] = set()
        for row in rows:
            if row["timestamp"] is None or row["timestamp"] > baseline_end:
                continue
            responder_counts[(row["destination_ip"], row["service"])] += 1
            baseline_originators.add((row["source_ip"], row["service"]))

        reversals: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        for row in rows:
            if row["timestamp"] is None or row["timestamp"] <= baseline_end:
                continue
            key = (row["source_ip"], row["service"])
            if responder_counts.get(key, 0) >= min_responder_events and key not in baseline_originators:
                reversals[key].append(row)

        findings: list[Finding] = []
        for (host, service), events in sorted(reversals.items()):
            peers = sorted({row["destination_ip"] for row in events})
            findings.append(Finding(
                title="OT protocol endpoint changed from responder to originator",
                severity="high",
                summary=f"{host} was established as a {service} responder during the baseline and later originated {service} traffic.",
                confidence="high",
                detection_basis="derived",
                devices=[host, *peers[:5]],
                services=[service],
                ports=sorted({p for row in events if (p := row["destination_port"]) is not None}),
                connection_pairs=[{"source": row["source_ip"], "destination": row["destination_ip"], "port": row["destination_port"], "service": service} for row in events[:MAX_EVIDENCE]],
                flows=[row["raw"] for row in events[:MAX_EVIDENCE]],
                timestamps=[row["timestamp"] for row in events[:MAX_EVIDENCE]],
                tags=["ot", "role-reversal", "behavior-change"],
                metadata={
                    "baseline_start": capture_start,
                    "baseline_end": baseline_end,
                    "baseline_responder_events": responder_counts[(host, service)],
                    "post_baseline_originator_events": len(events),
                },
            ))

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={"candidate_connections": len(rows), "role_reversals": len(reversals), "findings": len(findings)},
            evidence={
                "inspected_logs": ["conn"],
                "baseline_start": capture_start,
                "baseline_end": baseline_end,
                "notes": [
                    "The detector learns protocol direction only from the current capture baseline; observed traffic does not create policy authorization.",
                    "At least the configured number of baseline responder observations are required before a reversal is reported.",
                ],
            },
            warnings=[],
        )


def _normalized(row: dict[str, Any]) -> dict[str, Any] | None:
    source = str(_first(row, "source_ip", "id.orig_h") or "").strip()
    dest = str(_first(row, "destination_ip", "id.resp_h") or "").strip()
    if not source or not dest:
        return None
    service = str(_first(row, "service", "protocol_name") or "").strip().lower()
    if not service:
        port = _as_int(_first(row, "destination_port", "id.resp_p"))
        service = {502: "modbus", 20000: "dnp3", 102: "s7comm", 44818: "enip"}.get(port, "")
    return {
        "source_ip": source,
        "destination_ip": dest,
        "destination_port": _as_int(_first(row, "destination_port", "id.resp_p")),
        "service": service,
        "timestamp": _as_float(_first(row, "timestamp", "ts")),
        "raw": row,
    }


def _policy(metadata: dict[str, Any]) -> dict[str, Any]:
    value = metadata.get("ot_role_reversal_policy")
    return dict(value) if isinstance(value, dict) else {}


def _first(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if row.get(key) not in (None, ""):
            return row[key]
    return None


def _as_float(value: Any) -> float | None:
    try: return float(value) if value not in (None, "") else None
    except (TypeError, ValueError): return None


def _as_int(value: Any) -> int | None:
    try: return int(value) if value not in (None, "") else None
    except (TypeError, ValueError): return None
