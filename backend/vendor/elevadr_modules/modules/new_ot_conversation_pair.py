from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import ipaddress
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata


DEFAULT_BASELINE_SECONDS = 300.0
DEFAULT_MIN_POST_BASELINE_OCCURRENCES = 1
MAX_EVIDENCE_ROWS = 20
ICS_ROLE_TOKENS = {
    "ics", "ot", "scada", "plc", "rtu", "hmi", "bas", "bms", "historian",
    "dcs", "controller", "control", "control system", "industrial", "process",
    "engineering workstation", "engineering",
}


@dataclass(frozen=True, slots=True)
class _Segment:
    name: str
    role: str
    network: ipaddress._BaseNetwork


@dataclass(frozen=True, slots=True)
class _Identity:
    ip: str
    role: str
    source: str
    name: str


@dataclass(slots=True)
class _Event:
    timestamp: float
    source: str
    destination: str
    row: dict[str, Any]
    ot_identities: list[_Identity]

    @property
    def pair(self) -> tuple[str, str]:
        return (self.source, self.destination)


class NewOtConversationPairModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="new_ot_conversation_pair",
        name="New OT Conversation Pair (Comm-Matrix Drift)",
        description=(
            "Builds a directed source-to-destination communication matrix during an OT baseline period and identifies "
            "new talker relationships that first appear after the baseline."
        ),
        category="security_analysis",
        required_logs=("conn",),
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        policy = _policy(context.metadata)
        segments = _load_segments(context.metadata)
        inventory = _load_inventory(context.metadata)
        explicit_ot = _string_set(policy.get("ot_hosts"))
        ignored_hosts = _string_set(policy.get("ignored_hosts"))
        allowed_pairs = _pair_set(policy.get("allowed_pairs"))

        classification_available = bool(segments or inventory or explicit_ot)
        timestamps = [
            ts for row in context.connections
            if (ts := _as_float(_first(row, "timestamp", "ts"))) is not None
        ]
        if not context.connections or not timestamps:
            return _empty_result(
                self.metadata.id, policy, segments, context,
                "conn.log with timestamps is required for communication-matrix analysis.",
            )
        if not classification_available:
            return _empty_result(
                self.metadata.id, policy, segments, context,
                "No OT/control-system classification was supplied; private addressing alone is not used to infer OT identity.",
                skipped_unclassified=len(context.connections),
            )

        capture_start = min(timestamps)
        capture_end = max(timestamps)
        baseline_end = capture_start + policy["baseline_seconds"]

        events: list[_Event] = []
        skipped_unclassified = 0
        skipped_allowlisted = 0
        for row in context.connections:
            ts = _as_float(_first(row, "timestamp", "ts"))
            source = _ip(_first(row, "source_ip", "id.orig_h"))
            destination = _ip(_first(row, "destination_ip", "id.resp_h"))
            if ts is None or not source or not destination or source == destination:
                continue

            src_identity = _ot_identity(source, segments, inventory, explicit_ot)
            dst_identity = _ot_identity(destination, segments, inventory, explicit_ot)
            ot_identities = [identity for identity in (src_identity, dst_identity) if identity is not None]
            if not ot_identities:
                skipped_unclassified += 1
                continue
            if source in ignored_hosts or destination in ignored_hosts:
                skipped_allowlisted += 1
                continue
            if (source, destination) in allowed_pairs:
                skipped_allowlisted += 1
                continue

            events.append(
                _Event(
                    timestamp=ts,
                    source=source,
                    destination=destination,
                    row=row,
                    ot_identities=ot_identities,
                )
            )

        if capture_end <= baseline_end:
            return ModuleResult(
                module_id=self.metadata.id,
                findings=[],
                metrics={
                    "connections_evaluated": len(context.connections),
                    "ot_involving_connections": len(events),
                    "baseline_directed_pairs": len({event.pair for event in events}),
                    "new_post_baseline_pairs_observed": 0,
                    "new_ot_conversation_pair_findings": 0,
                    "suppressed_below_occurrence_threshold": 0,
                    "skipped_unclassified": skipped_unclassified,
                    "skipped_allowlisted": skipped_allowlisted,
                },
                evidence={
                    "inspected_logs": ["conn"],
                    "capture_start": capture_start,
                    "capture_end": capture_end,
                    "baseline_end": baseline_end,
                    "segments_loaded": len(segments),
                    "asset_inventory_records": len(context.metadata.get("asset_inventory", []) or []),
                    "thresholds": policy,
                    "notes": [
                        "The capture does not extend beyond the configured baseline window, so matrix drift cannot yet be evaluated.",
                        "Current OT-involving observations are still classified and counted so short captures do not appear to contain zero OT traffic.",
                    ],
                },
                warnings=[],
            )

        baseline_pairs = {event.pair for event in events if event.timestamp <= baseline_end}
        post_by_pair: dict[tuple[str, str], list[_Event]] = defaultdict(list)
        for event in events:
            if event.timestamp > baseline_end and event.pair not in baseline_pairs:
                post_by_pair[event.pair].append(event)

        findings: list[Finding] = []
        suppressed_below_threshold = 0
        for pair, pair_events in sorted(post_by_pair.items()):
            if len(pair_events) < policy["min_post_baseline_occurrences"]:
                suppressed_below_threshold += 1
                continue
            findings.append(_finding(pair, pair_events, baseline_end, capture_end))

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "connections_evaluated": len(context.connections),
                "ot_involving_connections": len(events),
                "baseline_directed_pairs": len(baseline_pairs),
                "new_post_baseline_pairs_observed": len(post_by_pair),
                "new_ot_conversation_pair_findings": len(findings),
                "suppressed_below_occurrence_threshold": suppressed_below_threshold,
                "skipped_unclassified": skipped_unclassified,
                "skipped_allowlisted": skipped_allowlisted,
            },
            evidence={
                "inspected_logs": ["conn"],
                "capture_start": capture_start,
                "capture_end": capture_end,
                "baseline_end": baseline_end,
                "segments_loaded": len(segments),
                "asset_inventory_records": len(context.metadata.get("asset_inventory", []) or []),
                "thresholds": policy,
                "notes": [
                    "The communication matrix is directional: source->destination is distinct from destination->source.",
                    "Only pairs involving at least one explicitly identified OT/control-system endpoint are evaluated.",
                    "A new service or port on an already-known host pair is not matrix drift; use the new-service-emergence detector for that condition.",
                    "The detector can only compare against relationships present during the supplied baseline window; an incomplete baseline may make legitimate but infrequent pairs look new.",
                ],
            },
            warnings=[],
        )


def _finding(pair: tuple[str, str], events: list[_Event], baseline_end: float, capture_end: float) -> Finding:
    source, destination = pair
    ordered = sorted(events, key=lambda item: item.timestamp)
    first = ordered[0]
    identities = {identity.ip: identity for event in ordered for identity in event.ot_identities}
    services = sorted({service for event in ordered if (service := _normalize_service(event.row.get("service"))) != "unknown"})
    ports = sorted({port for event in ordered if (port := _as_int(_first(event.row, "destination_port", "id.resp_p"))) is not None})
    protocols = sorted({_text(_first(event.row, "protocol", "proto")).lower() for event in ordered if _text(_first(event.row, "protocol", "proto"))})
    confidence = "high" if any(identity.source in {"asset_inventory", "policy"} for identity in identities.values()) else "medium"
    severity = "medium"
    return Finding(
        title=f"New OT conversation pair: {source} -> {destination}",
        severity=severity,
        confidence=confidence,
        detection_basis="derived",
        summary=(
            f"Observed a new directed talker relationship from {source} to {destination} after the OT communication-matrix "
            f"baseline ended. The pair was not observed during the baseline and appeared {len(ordered)} time(s) afterward."
        ),
        devices=[source, destination],
        services=services,
        ports=ports,
        connection_pairs=[{"source": source, "destination": destination}],
        flows=[event.row for event in ordered[:MAX_EVIDENCE_ROWS]],
        timestamps=[event.timestamp for event in ordered[:MAX_EVIDENCE_ROWS]],
        tags=["ot", "baseline", "comm-matrix", "new-conversation", "network-drift"],
        metadata={
            "source": source,
            "destination": destination,
            "first_seen_timestamp": first.timestamp,
            "baseline_end_timestamp": baseline_end,
            "capture_end_timestamp": capture_end,
            "post_baseline_occurrences": len(ordered),
            "protocols": protocols,
            "ot_endpoints": [
                {
                    "ip": identity.ip,
                    "asset_name": identity.name,
                    "asset_role": identity.role,
                    "classification_source": identity.source,
                }
                for identity in identities.values()
            ],
        },
    )


def _empty_result(module_id: str, policy: dict[str, Any], segments: list[_Segment], context: AnalysisContext, note: str, skipped_unclassified: int = 0) -> ModuleResult:
    return ModuleResult(
        module_id=module_id,
        findings=[],
        metrics={
            "connections_evaluated": len(context.connections),
            "ot_involving_connections": 0,
            "baseline_directed_pairs": 0,
            "new_post_baseline_pairs_observed": 0,
            "new_ot_conversation_pair_findings": 0,
            "suppressed_below_occurrence_threshold": 0,
            "skipped_unclassified": skipped_unclassified,
            "skipped_allowlisted": 0,
        },
        evidence={
            "inspected_logs": ["conn"] if context.connections else [],
            "segments_loaded": len(segments),
            "asset_inventory_records": len(context.metadata.get("asset_inventory", []) or []),
            "thresholds": policy,
            "notes": [note],
        },
        warnings=[],
    )


def _policy(metadata: dict[str, Any]) -> dict[str, Any]:
    raw: dict[str, Any] = {}
    for key in ("ot_comm_matrix_policy", "communication_matrix_policy", "comm_matrix_policy"):
        value = metadata.get(key)
        if isinstance(value, dict):
            raw = value
            break
    return {
        **raw,
        "baseline_seconds": _positive_float(raw.get("baseline_seconds"), DEFAULT_BASELINE_SECONDS),
        "min_post_baseline_occurrences": _positive_int(
            raw.get("min_post_baseline_occurrences"), DEFAULT_MIN_POST_BASELINE_OCCURRENCES
        ),
    }


def _load_segments(metadata: dict[str, Any]) -> list[_Segment]:
    result: list[_Segment] = []
    for item in metadata.get("segments", []) or []:
        if not isinstance(item, dict):
            continue
        cidr = item.get("cidr") or item.get("network") or item.get("subnet")
        if not cidr:
            continue
        try:
            network = ipaddress.ip_network(str(cidr), strict=False)
        except ValueError:
            continue
        result.append(_Segment(
            name=_text(item.get("name")) or str(network),
            role=_text(item.get("role") or item.get("type") or item.get("zone")),
            network=network,
        ))
    return result


def _load_inventory(metadata: dict[str, Any]) -> dict[str, _Identity]:
    result: dict[str, _Identity] = {}
    for item in metadata.get("asset_inventory", []) or []:
        if not isinstance(item, dict):
            continue
        ip = _ip(item.get("ip") or item.get("ip_address") or item.get("address"))
        role = _text(item.get("role") or item.get("type") or item.get("asset_type"))
        if not ip or not _is_ot_role(role):
            continue
        result[ip] = _Identity(
            ip=ip,
            role=role,
            source="asset_inventory",
            name=_text(item.get("name") or item.get("hostname") or item.get("device")),
        )
    return result


def _ot_identity(ip: str, segments: list[_Segment], inventory: dict[str, _Identity], explicit: set[str]) -> _Identity | None:
    if ip in explicit:
        return _Identity(ip=ip, role="OT", source="policy", name="")
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None

    # Explicit segment classification is authoritative for zone identity.  Asset
    # labels such as "engineering workstation" are descriptive and must not turn
    # a host in an explicitly IT/non-control segment into an OT endpoint.
    matching = [
        segment for segment in segments
        if addr.version == segment.network.version and addr in segment.network
    ]
    if matching:
        segment = max(matching, key=lambda value: value.network.prefixlen)
        if _is_ot_role(segment.role):
            return _Identity(ip=ip, role=segment.role, source="segment", name=segment.name)
        return None

    if ip in inventory:
        return inventory[ip]
    return None


def _is_ot_role(role: str) -> bool:
    value = role.lower().replace("_", " ").replace("-", " ").strip()
    return any(token == value or token in value for token in ICS_ROLE_TOKENS)


def _pair_set(value: Any) -> set[tuple[str, str]]:
    result: set[tuple[str, str]] = set()
    for item in value or []:
        if isinstance(item, dict):
            source = _ip(item.get("source") or item.get("src"))
            destination = _ip(item.get("destination") or item.get("dst"))
        elif isinstance(item, (list, tuple)) and len(item) >= 2:
            source, destination = _ip(item[0]), _ip(item[1])
        else:
            continue
        if source and destination:
            result.add((source, destination))
    return result


def _string_set(value: Any) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, str):
        value = [value]
    return {_text(item) for item in value if _text(item)}


def _normalize_service(value: Any) -> str:
    text = _text(value).lower()
    return "unknown" if not text or text in {"-", "unknown"} else text


def _first(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = row.get(key)
        if value is not None:
            return value
    return None


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _ip(value: Any) -> str:
    text = _text(value)
    try:
        return str(ipaddress.ip_address(text)) if text else ""
    except ValueError:
        return ""


def _as_float(value: Any) -> float | None:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _as_int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _positive_float(value: Any, default: float) -> float:
    parsed = _as_float(value)
    return parsed if parsed is not None and parsed > 0 else default


def _positive_int(value: Any, default: int) -> int:
    parsed = _as_int(value)
    return parsed if parsed is not None and parsed > 0 else default
