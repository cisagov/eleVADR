from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import ipaddress
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata


MAX_EVIDENCE = 10
DEFAULT_WINDOW_SECONDS = 60.0
DEFAULT_MIN_PACKET_COUNT = 120
DEFAULT_MIN_FLOW_COUNT = 20
DEFAULT_MIN_SHARE = 0.25
ROLE_KEYS = ("role", "segment_role", "trust_zone", "security_zone", "zone", "type", "classification")


@dataclass(slots=True)
class _Segment:
    name: str
    cidr: str
    network: ipaddress._BaseNetwork
    vlan_ids: tuple[int, ...]


@dataclass(slots=True)
class _Event:
    row: dict[str, Any]
    segment: _Segment
    timestamp: float
    source: str
    destination: str
    service: str
    kind: str | None
    packets: int | None


class ExcessiveBroadcastMulticastOtModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="excessive_broadcast_multicast_ot",
        name="Excessive Broadcast / Multicast in OT",
        description=(
            "Detects unusually high broadcast or multicast traffic rates from explicitly configured OT segments/VLANs "
            "where point-to-point traffic is expected to dominate. Uses Zeek conn.log packet counts when available "
            "and falls back to flow-event rates when packet counts are unavailable."
        ),
        category="security_analysis",
        required_logs=("conn",),
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        policy = _policy(context.metadata)
        segments = _ot_segments(context.metadata)
        if not segments:
            return ModuleResult(
                module_id=self.metadata.id,
                findings=[],
                metrics={
                    "connections_evaluated": len(context.connections),
                    "ot_connections_evaluated": 0,
                    "broadcast_multicast_connections": 0,
                    "broadcast_connections": 0,
                    "multicast_connections": 0,
                    "broadcast_multicast_findings": 0,
                },
                evidence={
                    "inspected_logs": ["conn"] if context.connections else [],
                    "ot_segment_metadata_loaded": False,
                    "notes": [
                        "OT membership is never inferred from private addressing alone; explicit OT/control segment metadata is required.",
                        "Zeek conn.log is flow-oriented. Packet-rate findings use source packet counters when present; otherwise the detector falls back to flow-event rates and lowers confidence.",
                    ],
                    "policy": _policy_evidence(policy),
                },
                warnings=["No explicitly classified OT/control segments were configured; broadcast/multicast rate analysis was not performed."],
            )

        ignored_services = {_norm(value) for value in _values(policy.get("ignored_services"))}
        ignored_destinations = {str(value).strip() for value in _values(policy.get("ignored_destinations")) if str(value).strip()}
        events: list[_Event] = []
        broadcast_count = 0
        multicast_count = 0

        for row in context.connections:
            source = _text(_first(row, "source_ip", "id.orig_h", "src", "source"))
            segment = _segment_for_ip(source, segments)
            if segment is None:
                continue
            ts = _as_float(_first(row, "timestamp", "ts"))
            if ts is None:
                continue
            destination = _text(_first(row, "destination_ip", "id.resp_h", "dst", "destination"))
            service = _norm(_first(row, "service", "zeek_service", "protocol") or "")
            kind = _traffic_kind(row, destination, segment)
            if kind and (service in ignored_services or destination in ignored_destinations):
                kind = None
            packets = _as_int(_first(row, "source_packets", "orig_pkts"))
            if packets is not None and packets < 0:
                packets = None
            event = _Event(
                row=row,
                segment=segment,
                timestamp=ts,
                source=source,
                destination=destination,
                service=service,
                kind=kind,
                packets=packets,
            )
            events.append(event)
            if kind == "broadcast":
                broadcast_count += 1
            elif kind == "multicast":
                multicast_count += 1

        findings: list[Finding] = []
        for segment in segments:
            segment_events = [event for event in events if event.segment is segment]
            if segment_events:
                finding = _segment_finding(segment, segment_events, policy)
                if finding is not None:
                    findings.append(finding)

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "connections_evaluated": len(context.connections),
                "ot_connections_evaluated": len(events),
                "broadcast_multicast_connections": broadcast_count + multicast_count,
                "broadcast_connections": broadcast_count,
                "multicast_connections": multicast_count,
                "broadcast_multicast_findings": len(findings),
                "affected_ot_segments": len({finding.metadata.get("segment") for finding in findings}),
            },
            evidence={
                "inspected_logs": ["conn"],
                "ot_segment_metadata_loaded": True,
                "notes": [
                    "Broadcast/multicast classification uses destination IP semantics (IPv4 limited/directed broadcast, IPv4/IPv6 multicast) and explicit destination MAC fields when present.",
                    "The denominator is all timestamped conn.log traffic sourced from the same configured OT segment during the selected window.",
                    "A finding requires both a minimum broadcast/multicast volume and a minimum traffic share, preventing a few expected discovery messages from alerting on otherwise point-to-point segments.",
                    "Packet mode is used only when every event in the evaluated OT segment has a usable source packet counter; otherwise flow-event mode is used and confidence is reduced.",
                    "Evidence is capped at 10 representative broadcast/multicast flows while complete counts remain in finding metadata.",
                ],
                "policy": _policy_evidence(policy),
            },
            warnings=[],
        )


def _segment_finding(segment: _Segment, events: list[_Event], policy: dict[str, Any]) -> Finding | None:
    events = sorted(events, key=lambda item: item.timestamp)
    packet_mode = all(event.packets is not None for event in events)
    window_seconds = _float_policy(policy, "window_seconds", DEFAULT_WINDOW_SECONDS)
    min_share = _float_policy(policy, "min_broadcast_multicast_share", DEFAULT_MIN_SHARE)
    min_units = (
        _int_policy(policy, "min_broadcast_multicast_packets", DEFAULT_MIN_PACKET_COUNT)
        if packet_mode
        else _int_policy(policy, "min_broadcast_multicast_flows", DEFAULT_MIN_FLOW_COUNT)
    )

    q: deque[_Event] = deque()
    total_units = 0
    bm_units = 0
    best: tuple[float, int, int, list[_Event]] | None = None

    for event in events:
        units = _units(event, packet_mode)
        q.append(event)
        total_units += units
        if event.kind:
            bm_units += units
        while q and event.timestamp - q[0].timestamp > window_seconds:
            old = q.popleft()
            old_units = _units(old, packet_mode)
            total_units -= old_units
            if old.kind:
                bm_units -= old_units
        share = (bm_units / total_units) if total_units > 0 else 0.0
        if bm_units >= min_units and share >= min_share:
            score = (share, bm_units, total_units, list(q))
            if best is None or (score[0], score[1]) > (best[0], best[1]):
                best = score

    if best is None:
        return None

    share, suspicious_units, all_units, window_events = best
    suspicious = [event for event in window_events if event.kind]
    broadcast_events = [event for event in suspicious if event.kind == "broadcast"]
    multicast_events = [event for event in suspicious if event.kind == "multicast"]
    broadcast_units = sum(_units(event, packet_mode) for event in broadcast_events)
    multicast_units = sum(_units(event, packet_mode) for event in multicast_events)
    unit_label = "packets" if packet_mode else "flows"
    rate = suspicious_units / window_seconds if window_seconds > 0 else 0.0

    severe = suspicious_units >= (min_units * 2) or share >= max(0.50, min_share * 1.5)
    severity = "high" if severe else "medium"
    confidence = "high" if packet_mode else "medium"
    vlan_text = f" (VLAN {', '.join(map(str, segment.vlan_ids))})" if segment.vlan_ids else ""
    summary = (
        f"Observed {suspicious_units} broadcast/multicast {unit_label} from OT segment {segment.name}{vlan_text} "
        f"within {window_seconds:g} seconds ({rate:.2f} {unit_label}/s), representing {share:.1%} of the segment's "
        f"observed outbound {unit_label} in that window. The configured thresholds are at least {min_units} {unit_label} "
        f"and {min_share:.0%} traffic share."
    )

    representative = suspicious[:MAX_EVIDENCE]
    devices = sorted({event.source for event in suspicious if event.source})
    destinations = sorted({event.destination for event in suspicious if event.destination})
    services = sorted({event.service for event in suspicious if event.service})
    timestamps = [event.timestamp for event in representative]
    ports = sorted({port for event in suspicious if (port := _as_int(_first(event.row, "destination_port", "id.resp_p"))) is not None})
    pairs = []
    seen_pairs: set[tuple[str, str]] = set()
    for event in representative:
        pair = (event.source, event.destination)
        if pair in seen_pairs:
            continue
        seen_pairs.add(pair)
        pairs.append({"source": event.source, "destination": event.destination})

    start = window_events[0].timestamp if window_events else None
    end = window_events[-1].timestamp if window_events else None
    metadata = {
        "finding_type": "excessive_broadcast_multicast",
        "segment": segment.name,
        "segment_cidr": segment.cidr,
        "vlan_ids": list(segment.vlan_ids),
        "measurement_mode": "packet" if packet_mode else "flow_event",
        "window_seconds": window_seconds,
        "window_start": start,
        "window_end": end,
        "broadcast_multicast_units": suspicious_units,
        "total_units": all_units,
        "broadcast_units": broadcast_units,
        "multicast_units": multicast_units,
        "broadcast_multicast_share": share,
        "broadcast_multicast_rate_per_second": rate,
        "broadcast_flow_count": len(broadcast_events),
        "multicast_flow_count": len(multicast_events),
        "minimum_units_threshold": min_units,
        "minimum_share_threshold": min_share,
        "destinations": destinations,
        "evidence_count": len(representative),
        "evidence_truncated": len(suspicious) > MAX_EVIDENCE,
    }

    return Finding(
        title=f"Excessive broadcast/multicast in OT segment {segment.name}",
        severity=severity,
        summary=summary,
        confidence=confidence,
        detection_basis="derived",
        devices=devices,
        services=services,
        ports=ports,
        connection_pairs=pairs,
        flows=[event.row for event in representative],
        subnets=[segment.cidr],
        timestamps=timestamps,
        tags=["ot", "broadcast", "multicast", "traffic-rate", "baseline-policy"],
        metadata=metadata,
    )


def _traffic_kind(row: dict[str, Any], destination: str, segment: _Segment) -> str | None:
    if destination:
        try:
            address = ipaddress.ip_address(destination)
        except ValueError:
            address = None
        if address is not None:
            if address.is_multicast:
                return "multicast"
            if isinstance(address, ipaddress.IPv4Address):
                if str(address) == "255.255.255.255":
                    return "broadcast"
                if isinstance(segment.network, ipaddress.IPv4Network) and segment.network.prefixlen <= 30:
                    if address == segment.network.broadcast_address:
                        return "broadcast"

    mac = _text(_first(row, "destination_mac", "dst_mac", "resp_l2_addr", "id.resp_l2_addr"))
    if mac:
        normalized = mac.lower().replace("-", ":")
        if normalized == "ff:ff:ff:ff:ff:ff":
            return "broadcast"
        try:
            first_octet = int(normalized.split(":", 1)[0], 16)
        except (ValueError, IndexError):
            first_octet = 0
        if first_octet & 1:
            return "multicast"
    return None


def _ot_segments(metadata: dict[str, Any]) -> list[_Segment]:
    raw = metadata.get("segments")
    if not isinstance(raw, list):
        return []
    result: list[_Segment] = []
    for item in raw:
        if not isinstance(item, dict) or not _is_ot(item):
            continue
        cidr = _text(item.get("cidr") or item.get("subnet"))
        if not cidr:
            continue
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        name = _text(item.get("name") or item.get("segment") or item.get("label") or cidr)
        vlan_values = item.get("vlan_ids") if item.get("vlan_ids") is not None else item.get("vlan_id")
        if vlan_values is None:
            vlan_values = item.get("vlan")
        vlans = tuple(sorted({value for raw_value in _values(vlan_values) if (value := _as_int(raw_value)) is not None and 0 <= value <= 4095}))
        result.append(_Segment(name=name, cidr=cidr, network=network, vlan_ids=vlans))
    return result


def _segment_for_ip(value: str, segments: list[_Segment]) -> _Segment | None:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    matches = [segment for segment in segments if address in segment.network]
    return max(matches, key=lambda segment: segment.network.prefixlen) if matches else None


def _is_ot(item: dict[str, Any]) -> bool:
    values = [_norm(item.get(key)) for key in ROLE_KEYS if item.get(key) not in (None, "")]
    return any(
        value == "ot"
        or "operational technology" in value
        or "control" in value
        or "ics" in value
        or "scada" in value
        for value in values
    )


def _policy(metadata: dict[str, Any]) -> dict[str, Any]:
    value = metadata.get("broadcast_multicast_ot_policy")
    return value if isinstance(value, dict) else {}


def _policy_evidence(policy: dict[str, Any]) -> dict[str, Any]:
    return {
        "window_seconds": _float_policy(policy, "window_seconds", DEFAULT_WINDOW_SECONDS),
        "min_broadcast_multicast_packets": _int_policy(policy, "min_broadcast_multicast_packets", DEFAULT_MIN_PACKET_COUNT),
        "min_broadcast_multicast_flows": _int_policy(policy, "min_broadcast_multicast_flows", DEFAULT_MIN_FLOW_COUNT),
        "min_broadcast_multicast_share": _float_policy(policy, "min_broadcast_multicast_share", DEFAULT_MIN_SHARE),
        "ignored_services": sorted({_norm(value) for value in _values(policy.get("ignored_services"))}),
        "ignored_destinations": sorted({str(value).strip() for value in _values(policy.get("ignored_destinations")) if str(value).strip()}),
    }


def _units(event: _Event, packet_mode: bool) -> int:
    if packet_mode:
        return max(0, event.packets or 0)
    return 1


def _float_policy(policy: dict[str, Any], key: str, default: float) -> float:
    value = _as_float(policy.get(key))
    return value if value is not None and value > 0 else default


def _int_policy(policy: dict[str, Any], key: str, default: int) -> int:
    value = _as_int(policy.get(key))
    return value if value is not None and value > 0 else default


def _values(value: Any) -> list[Any]:
    if isinstance(value, (list, tuple, set)):
        return list(value)
    if value in (None, "", "-"):
        return []
    return [value]


def _norm(value: Any) -> str:
    return " ".join(str(value or "").strip().lower().replace("_", " ").replace("-", " ").split())


def _text(value: Any) -> str:
    return "" if value in (None, "-") else str(value).strip()


def _first(row: dict[str, Any], *names: str) -> Any:
    for name in names:
        value = row.get(name)
        if value not in (None, "", "-"):
            return value
    return None


def _as_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
