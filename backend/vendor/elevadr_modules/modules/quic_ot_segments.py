from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import ipaddress
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata


MAX_EVIDENCE_FLOWS = 10
OT_ROLE_TOKENS = {"ot", "control", "ics", "scada", "operations", "industrial", "process"}
QUIC_SERVICE_TOKENS = {"quic", "http3", "http/3", "h3"}


@dataclass(slots=True)
class _Segment:
    cidr: str
    name: str
    role: str
    trust_zone: str
    purdue_level: str
    network: ipaddress._BaseNetwork


@dataclass(slots=True)
class _Event:
    row: dict[str, Any]
    source: str
    destination: str
    source_port: int | None
    destination_port: int | None
    timestamp: float | None
    evidence_kind: str
    confidence: str
    detection_basis: str
    source_segment: _Segment | None
    destination_segment: _Segment | None
    external_destination: bool


class QuicOtSegmentsModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="quic_ot_segments",
        name="QUIC in OT Segments",
        description=(
            "Identifies QUIC/HTTP/3 traffic involving configured OT/control segments, with explicit protocol "
            "evidence preferred over lower-confidence UDP/443 heuristics."
        ),
        category="security_analysis",
        required_logs=("conn",),
        default_enabled=True,
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        segments = _load_segments(context.metadata)
        policy = _policy(context.metadata)
        allowed_ips = {str(value).strip() for value in policy.get("allowed_ips", []) if str(value).strip()}
        allowed_segments = {str(value).strip().lower() for value in policy.get("allowed_segments", []) if str(value).strip()}

        conn_by_uid = {
            str(row.get("uid")): row
            for row in context.connections
            if row.get("uid") not in (None, "")
        }

        groups: dict[tuple[str, str, str], list[_Event]] = defaultdict(list)
        seen_uids: set[str] = set()
        explicit_events = 0
        zeek_service_events = 0
        port_heuristic_events = 0
        skipped_no_ot_segment = 0
        skipped_allowlisted = 0

        # Prefer dedicated QUIC telemetry when available.
        for row in context.quic:
            event = _event_from_row(
                row,
                conn_by_uid=conn_by_uid,
                segments=segments,
                evidence_kind="quic_protocol_log",
                confidence="high",
                detection_basis="protocol_log",
            )
            if event is None:
                continue
            if not _involves_ot(event):
                skipped_no_ot_segment += 1
                continue
            if _allowlisted(event, allowed_ips, allowed_segments):
                skipped_allowlisted += 1
                continue
            explicit_events += 1
            uid = _text(row.get("uid"))
            if uid:
                seen_uids.add(uid)
            groups[(event.source, event.destination, event.evidence_kind)].append(event)

        # conn.log service identification is strong application evidence, but lower precedence than quic.log.
        for row in context.connections:
            uid = _text(row.get("uid"))
            if uid and uid in seen_uids:
                continue
            if not _is_udp(row):
                continue
            service_tokens = _service_tokens(row.get("service"))
            if not service_tokens.intersection(QUIC_SERVICE_TOKENS):
                continue
            event = _event_from_row(
                row,
                conn_by_uid=conn_by_uid,
                segments=segments,
                evidence_kind="zeek_quic_service",
                confidence="high",
                detection_basis="zeek_service",
            )
            if event is None:
                continue
            if not _involves_ot(event):
                skipped_no_ot_segment += 1
                continue
            if _allowlisted(event, allowed_ips, allowed_segments):
                skipped_allowlisted += 1
                continue
            zeek_service_events += 1
            groups[(event.source, event.destination, event.evidence_kind)].append(event)
            if uid:
                seen_uids.add(uid)

        # UDP/443 alone is only a heuristic candidate; never call it confirmed QUIC.
        if bool(policy.get("enable_udp443_heuristic", True)):
            for row in context.connections:
                uid = _text(row.get("uid"))
                if uid and uid in seen_uids:
                    continue
                if not _is_udp(row) or _as_int(row.get("destination_port", row.get("id.resp_p"))) != 443:
                    continue
                # Do not reclassify application-identified QUIC as a port-only heuristic, even if
                # the stronger event was allowlisted or lacked a UID.
                if _service_tokens(row.get("service")).intersection(QUIC_SERVICE_TOKENS):
                    continue
                event = _event_from_row(
                    row,
                    conn_by_uid=conn_by_uid,
                    segments=segments,
                    evidence_kind="udp443_heuristic",
                    confidence="low",
                    detection_basis="port",
                )
                if event is None:
                    continue
                if not _involves_ot(event):
                    skipped_no_ot_segment += 1
                    continue
                if _allowlisted(event, allowed_ips, allowed_segments):
                    skipped_allowlisted += 1
                    continue
                port_heuristic_events += 1
                groups[(event.source, event.destination, event.evidence_kind)].append(event)

        findings = [_finding(events) for _, events in sorted(groups.items()) if events]
        affected = sorted({device for finding in findings for device in finding.devices})

        inspected = ["conn"]
        if context.quic:
            inspected.append("quic")

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "quic_ot_findings": len(findings),
                "explicit_quic_events": explicit_events,
                "zeek_quic_service_events": zeek_service_events,
                "udp443_heuristic_events": port_heuristic_events,
                "affected_devices": len(affected),
                "configured_segments": len(segments),
                "skipped_no_ot_segment": skipped_no_ot_segment,
                "skipped_allowlisted": skipped_allowlisted,
            },
            evidence={
                "inspected_logs": inspected,
                "notes": [
                    "A dedicated QUIC protocol log has the strongest precedence, followed by Zeek application-service identification.",
                    "UDP/443 without protocol identification is a low-confidence heuristic and is never labeled confirmed QUIC.",
                    "A finding requires at least one endpoint to map to a configured OT/control segment; private address space alone is not treated as proof of OT membership.",
                    "QUIC/HTTP/3 may be legitimate vendor, browser, cloud, or update traffic. This module reports unexpected protocol use in deterministic OT environments, not malicious activity by itself.",
                    "Approved endpoint IPs or segment names can be suppressed with quic_ot_policy metadata.",
                ],
                "policy": policy,
            },
            warnings=[],
        )


def _finding(events: list[_Event]) -> Finding:
    first = events[0]
    representative = events[:MAX_EVIDENCE_FLOWS]
    confirmed = first.evidence_kind != "udp443_heuristic"
    severity = "medium" if confirmed else "low"
    external = any(event.external_destination for event in events)
    protocol_label = "QUIC/HTTP/3" if confirmed else "possible QUIC (UDP/443)"

    src_seg = first.source_segment
    dst_seg = first.destination_segment
    ot_segments = sorted(
        {
            segment.name
            for event in events
            for segment in (event.source_segment, event.destination_segment)
            if segment is not None and _segment_is_ot(segment)
        }
    )
    services = ["QUIC/HTTP/3"] if confirmed else []
    ports = sorted({event.destination_port for event in events if event.destination_port is not None})
    subnets = sorted(
        {
            segment.cidr
            for event in events
            for segment in (event.source_segment, event.destination_segment)
            if segment is not None
        }
    )

    if confirmed:
        summary = (
            f"Observed {len(events)} {protocol_label} flow(s) from {first.source} to {first.destination} involving "
            f"configured OT/control segment(s) {', '.join(ot_segments)}. QUIC/HTTP/3 is typically nondeterministic "
            "web/cloud transport and may be unexpected in segments intended for deterministic industrial protocols. "
            "Review the endpoint purpose, approved vendor/cloud dependencies, and segmentation policy before treating it as suspicious."
        )
    else:
        summary = (
            f"Observed {len(events)} UDP/443 flow(s) from {first.source} to {first.destination} involving configured "
            f"OT/control segment(s) {', '.join(ot_segments)}. UDP/443 is commonly used by QUIC/HTTP/3, but port alone "
            "does not confirm the application protocol. Validate with packet/protocol telemetry before classifying the traffic as QUIC."
        )

    if external:
        summary += " At least one destination is external to the configured/local network context."

    return Finding(
        title=(
            f"QUIC/HTTP/3 observed in OT: {first.source} -> {first.destination}"
            if confirmed
            else f"Possible QUIC over UDP/443 in OT: {first.source} -> {first.destination}"
        ),
        severity=severity,
        summary=summary,
        confidence=first.confidence,
        detection_basis=first.detection_basis,
        devices=sorted({value for event in events for value in (event.source, event.destination) if value}),
        services=services,
        ports=ports,
        connection_pairs=[
            {
                "source": first.source,
                "destination": first.destination,
                "port": first.destination_port,
                "protocol": "udp",
                "service": "QUIC/HTTP/3" if confirmed else None,
            }
        ],
        flows=[event.row for event in representative],
        subnets=subnets,
        timestamps=[event.timestamp for event in representative if event.timestamp is not None],
        tags=["quic", "http3", "ot", "unexpected-protocol", first.evidence_kind],
        metadata={
            "event_count": len(events),
            "evidence_event_count": len(representative),
            "evidence_truncated": len(events) > len(representative),
            "quic_confirmed": confirmed,
            "evidence_kind": first.evidence_kind,
            "external_destination": external,
            "ot_segments": ot_segments,
            "source_segment": src_seg.name if src_seg else None,
            "destination_segment": dst_seg.name if dst_seg else None,
            "confidence": first.confidence,
            "detection_basis": first.detection_basis,
        },
    )


def _event_from_row(
    row: dict[str, Any],
    *,
    conn_by_uid: dict[str, dict[str, Any]],
    segments: list[_Segment],
    evidence_kind: str,
    confidence: str,
    detection_basis: str,
) -> _Event | None:
    merged = dict(row)
    uid = _text(row.get("uid"))
    conn = conn_by_uid.get(uid) if uid else None
    if conn:
        for key, value in conn.items():
            merged.setdefault(key, value)

    source = _text(merged.get("source_ip", merged.get("id.orig_h")))
    destination = _text(merged.get("destination_ip", merged.get("id.resp_h")))
    if not source or not destination:
        return None
    source_port = _as_int(merged.get("source_port", merged.get("id.orig_p")))
    destination_port = _as_int(merged.get("destination_port", merged.get("id.resp_p")))
    timestamp = _as_float(merged.get("timestamp", merged.get("ts")))
    src_segment = _segment_for_ip(source, segments)
    dst_segment = _segment_for_ip(destination, segments)
    external = _is_external(destination, dst_segment)
    return _Event(
        row=merged,
        source=source,
        destination=destination,
        source_port=source_port,
        destination_port=destination_port,
        timestamp=timestamp,
        evidence_kind=evidence_kind,
        confidence=confidence,
        detection_basis=detection_basis,
        source_segment=src_segment,
        destination_segment=dst_segment,
        external_destination=external,
    )


def _policy(metadata: dict[str, Any]) -> dict[str, Any]:
    raw = metadata.get("quic_ot_policy")
    raw = raw if isinstance(raw, dict) else {}
    return {
        "enable_udp443_heuristic": bool(raw.get("enable_udp443_heuristic", True)),
        "allowed_ips": list(raw.get("allowed_ips", [])) if isinstance(raw.get("allowed_ips", []), list) else [],
        "allowed_segments": list(raw.get("allowed_segments", [])) if isinstance(raw.get("allowed_segments", []), list) else [],
    }


def _load_segments(metadata: dict[str, Any]) -> list[_Segment]:
    raw = metadata.get("segments")
    if not isinstance(raw, list):
        return []
    segments: list[_Segment] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        cidr = _text(item.get("cidr") or item.get("subnet"))
        if not cidr:
            continue
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        name = _text(item.get("name") or item.get("label") or cidr) or cidr
        role = _text(item.get("role") or item.get("segment_role") or item.get("type")) or ""
        trust_zone = _text(item.get("trust_zone") or item.get("zone") or item.get("trustZone")) or ""
        purdue = _text(item.get("purdue_level") or item.get("purdue") or item.get("level") or item.get("purdueLevel")) or ""
        segments.append(_Segment(cidr=cidr, name=name, role=role, trust_zone=trust_zone, purdue_level=purdue, network=network))
    return sorted(segments, key=lambda segment: segment.network.prefixlen, reverse=True)


def _segment_for_ip(value: str, segments: list[_Segment]) -> _Segment | None:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    for segment in segments:
        if address.version == segment.network.version and address in segment.network:
            return segment
    return None


def _segment_is_ot(segment: _Segment) -> bool:
    values = f"{segment.role} {segment.trust_zone} {segment.name}".lower().replace("-", " ").replace("_", " ")
    tokens = set(values.split())
    if tokens.intersection(OT_ROLE_TOKENS):
        return True
    level = segment.purdue_level.strip().lower().replace("level", "").replace("l", "")
    try:
        return float(level) <= 3.0
    except ValueError:
        return False


def _involves_ot(event: _Event) -> bool:
    return any(segment is not None and _segment_is_ot(segment) for segment in (event.source_segment, event.destination_segment))


def _allowlisted(event: _Event, ips: set[str], segments: set[str]) -> bool:
    if event.source in ips or event.destination in ips:
        return True
    for segment in (event.source_segment, event.destination_segment):
        if segment and segment.name.lower() in segments:
            return True
    return False


def _is_external(destination: str, destination_segment: _Segment | None) -> bool:
    if destination_segment is not None:
        return False
    try:
        address = ipaddress.ip_address(destination)
    except ValueError:
        return False
    return not (address.is_private or address.is_loopback or address.is_link_local or address.is_multicast)


def _is_udp(row: dict[str, Any]) -> bool:
    proto = _text(row.get("protocol", row.get("proto")))
    return proto.lower() == "udp" if proto else False


def _service_tokens(value: Any) -> set[str]:
    text = _text(value)
    if not text:
        return set()
    normalized = text.lower().replace(";", ",")
    return {part.strip() for part in normalized.split(",") if part.strip()}


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _as_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def _as_float(value: Any) -> float | None:
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
