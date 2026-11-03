from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import ipaddress
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata

MAX_EVIDENCE_ROWS = 50
NETBIOS_PORTS = {137, 138, 139}
ESTABLISHED_TCP_STATES = {"SF", "S1", "S2", "S3", "RSTO", "RSTR", "RSTOS0", "RSTRH"}


@dataclass(frozen=True, slots=True)
class _Segment:
    name: str
    role: str
    network: ipaddress._BaseNetwork


class NetbiosSmbv1ExposureModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="netbios_smbv1_exposure",
        name="NetBIOS / SMBv1 Exposure",
        description=(
            "Identifies NetBIOS traffic on ports 137-139 crossing configured network-segment boundaries "
            "or involving public Internet addresses."
        ),
        category="security_analysis",
        required_logs=("conn",),
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        policy = _policy(context.metadata)
        segments = _load_segments(context.metadata)
        allowed_hosts = _string_set(policy.get("allowed_hosts"))
        allowed_pairs = _pair_set(policy.get("allowed_pairs"))
        allowed_segment_pairs = _segment_pair_set(policy.get("allowed_segment_pairs"))
        require_established_external = _bool(policy.get("require_established_external"), True)
        report_cross_segment = _bool(policy.get("report_cross_segment"), True)
        report_external = _bool(policy.get("report_external"), True)

        events: list[dict[str, Any]] = []
        netbios_candidates = 0
        external_attempts_not_reachable = 0
        skipped_allowlisted = 0
        skipped_no_segment_context = 0

        for row in context.connections:
            proto = _text(_first(row, "protocol", "proto")).lower()
            port = _as_int(_first(row, "destination_port", "id.resp_p"))
            if port not in NETBIOS_PORTS or proto not in {"tcp", "udp"}:
                continue
            netbios_candidates += 1
            event = _event_from_conn(row, "netbios", "port")
            decision = _classify_event(
                event, segments, allowed_hosts, allowed_pairs, allowed_segment_pairs,
                report_cross_segment, report_external, require_established_external,
            )
            if decision == "external_unreachable":
                external_attempts_not_reachable += 1
            elif decision == "allowlisted":
                skipped_allowlisted += 1
            elif decision == "no_segment":
                skipped_no_segment_context += 1
            elif decision:
                event["context_type"] = decision
                events.append(event)

        groups: dict[tuple[str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
        for event in events:
            groups[(event["protocol_type"], event["context_type"], event["source"], event["destination"])].append(event)
        findings = [_finding(items) for _key, items in sorted(groups.items())]

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "netbios_candidates": netbios_candidates,
                "netbios_smbv1_findings": len(findings),
                "cross_segment_events": sum(1 for e in events if e["context_type"] == "cross_segment"),
                "external_events": sum(1 for e in events if e["context_type"] == "external"),
                "external_attempts_not_counted_as_reachable": external_attempts_not_reachable,
                "skipped_allowlisted": skipped_allowlisted,
                "skipped_no_segment_context": skipped_no_segment_context,
            },
            evidence={
                "inspected_logs": [name for name in ("conn",) if context.log(name)],
                "segments_loaded": len(segments),
                "policy": policy,
                "notes": [
                    "NetBIOS is identified from TCP/UDP ports 137-139; these legacy services are reported only when they cross a configured segment boundary or involve a public IP.",
                    "Cross-segment detection requires configured segment metadata; private addressing alone does not establish a boundary.",
                    "Unanswered Internet TCP probes are not treated as proof of reachable exposure when require_established_external is enabled.",
                    "SMBv1 detection was removed from this module: it depended on smb_cmd.log, which is off by default in stock Zeek and known to drop commands on busy streams. It is not a reliable basis for a security finding.",
                ],
            },
            warnings=[],
        )


def _classify_event(event, segments, allowed_hosts, allowed_pairs, allowed_segment_pairs, report_cross_segment, report_external, require_established_external):
    source, destination = event["source"], event["destination"]
    if source in allowed_hosts or destination in allowed_hosts or (source, destination) in allowed_pairs:
        return "allowlisted"
    src_public, dst_public = _is_public(source), _is_public(destination)
    if report_external and (src_public or dst_public):
        if require_established_external and event.get("protocol") == "tcp" and not _observed_reachable(event.get("connection") or {}):
            return "external_unreachable"
        return "external"
    if not report_cross_segment:
        return ""
    src_seg, dst_seg = _segment_for(source, segments), _segment_for(destination, segments)
    if not src_seg or not dst_seg:
        return "no_segment"
    if src_seg.name == dst_seg.name:
        return ""
    if _segment_pair_allowed(src_seg.name, dst_seg.name, allowed_segment_pairs):
        return "allowlisted"
    event["source_segment"], event["destination_segment"] = src_seg.name, dst_seg.name
    event["source_role"], event["destination_role"] = src_seg.role, dst_seg.role
    return "cross_segment"


def _finding(items: list[dict[str, Any]]) -> Finding:
    first = items[0]
    context_type = first["context_type"]
    external = context_type == "external"
    severity = "high" if external else "medium"
    title = "NetBIOS exposed to public network" if external else "NetBIOS crossing network-segment boundary"
    summary = f"Observed {len(items)} NetBIOS flow(s) on ports 137-139 {'involving a public Internet address' if external else 'crossing configured network segments'}. Review whether legacy NetBIOS is required across this trust boundary."
    confidence, basis = "medium", "port"
    tags = ["netbios", "legacy-protocol"]
    devices = sorted({x for e in items for x in (e["source"], e["destination"]) if x})
    ports = sorted({e.get("port") for e in items if isinstance(e.get("port"), int)})
    pairs = []
    for e in items[:MAX_EVIDENCE_ROWS]:
        pairs.append({"source": e["source"], "destination": e["destination"], "protocol": e.get("protocol"), "destination_port": e.get("port")})
    return Finding(
        title=title,
        severity=severity,
        summary=summary,
        confidence=confidence,
        detection_basis=basis,
        devices=devices,
        services=["NetBIOS"],
        ports=ports,
        connection_pairs=pairs,
        timestamps=[e["timestamp"] for e in items[:MAX_EVIDENCE_ROWS] if e.get("timestamp") not in (None, "")],
        tags=tags + (["external"] if external else ["cross-segment"]),
        metadata={
            "protocol_type": first["protocol_type"],
            "context_type": context_type,
            "event_count": len(items),
            "source_segment": first.get("source_segment"),
            "destination_segment": first.get("destination_segment"),
        },
    )


def _event_from_conn(row, protocol_type, basis):
    return {
        "protocol_type": protocol_type,
        "basis": basis,
        "source": _ip(_first(row, "source_ip", "id.orig_h")) or "",
        "destination": _ip(_first(row, "destination_ip", "id.resp_h")) or "",
        "port": _as_int(_first(row, "destination_port", "id.resp_p")),
        "protocol": _text(_first(row, "protocol", "proto")).lower(),
        "timestamp": _first(row, "timestamp", "ts"),
        "connection": row,
    }


def _policy(metadata):
    value = metadata.get("netbios_smbv1_policy", {}) if isinstance(metadata, dict) else {}
    return value if isinstance(value, dict) else {}


def _load_segments(metadata) -> list[_Segment]:
    values = metadata.get("segments", []) if isinstance(metadata, dict) else []
    result = []
    if not isinstance(values, list):
        return result
    for item in values:
        if not isinstance(item, dict):
            continue
        cidr = item.get("cidr") or item.get("network")
        try:
            network = ipaddress.ip_network(str(cidr), strict=False)
        except (ValueError, TypeError):
            continue
        result.append(_Segment(_text(item.get("name")) or str(network), _text(item.get("role")), network))
    return result


def _segment_for(ip, segments):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    matches = [s for s in segments if addr.version == s.network.version and addr in s.network]
    return max(matches, key=lambda s: s.network.prefixlen) if matches else None


def _segment_pair_set(value):
    result = set()
    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                a, b = _text(item.get("source")), _text(item.get("destination"))
                if a and b:
                    result.add((a, b))
    return result


def _segment_pair_allowed(a, b, pairs):
    return (a, b) in pairs or (b, a) in pairs


def _pair_set(value):
    result = set()
    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                a, b = _text(item.get("source")), _text(item.get("destination"))
                if a and b:
                    result.add((a, b))
    return result


def _string_set(value):
    if not isinstance(value, list):
        return set()
    return {_text(v) for v in value if _text(v)}


def _observed_reachable(row):
    proto = _text(_first(row, "protocol", "proto")).lower()
    if proto != "tcp":
        return True
    state = _text(_first(row, "connection_state", "conn_state")).upper()
    if state in ESTABLISHED_TCP_STATES:
        return True
    return (_as_int(_first(row, "destination_bytes", "resp_bytes")) or 0) > 0 or (_as_int(_first(row, "destination_packets", "resp_pkts")) or 0) > 0


def _is_public(value):
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return addr.is_global


def _ip(value):
    text = _text(value)
    try:
        return str(ipaddress.ip_address(text)) if text else ""
    except ValueError:
        return ""


def _first(row, *names):
    for name in names:
        if row.get(name) not in (None, ""):
            return row.get(name)
    return None


def _text(value):
    return str(value).strip() if value is not None else ""


def _as_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _bool(value, default):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        if value.strip().lower() in {"true", "yes", "1", "on"}:
            return True
        if value.strip().lower() in {"false", "no", "0", "off"}:
            return False
    return default
