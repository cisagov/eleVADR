from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import ipaddress
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata

MAX_EVIDENCE_ROWS = 50
NETBIOS_PORTS = {137, 138, 139}
SMB_LOGS = ("smb", "smb_mapping", "smb_files", "smb_cmd")
SMBV1_FIELDS = ("version", "smb_version", "protocol_version", "dialect", "smb_dialect", "negotiated_dialect")
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
            "Identifies NetBIOS traffic on ports 137-139 or explicitly evidenced SMBv1 traffic crossing "
            "configured network-segment boundaries or involving public Internet addresses."
        ),
        category="security_analysis",
        required_logs=(),
        required_any_logs=("conn", "smb", "smb_mapping", "smb_files", "smb_cmd"),
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

        conn_by_uid = {
            str(row.get("uid")): row for row in context.connections if row.get("uid") not in (None, "")
        }

        events: list[dict[str, Any]] = []
        netbios_candidates = 0
        smbv1_candidates = 0
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

        seen_smb: set[tuple[str, str, str]] = set()
        for log_name in SMB_LOGS:
            for row in context.log(log_name):
                version = _explicit_smbv1(row)
                if not version:
                    continue
                uid = _text(row.get("uid"))
                conn = conn_by_uid.get(uid, {}) if uid else {}
                source = _ip(_first(row, "source_ip", "id.orig_h")) or _ip(_first(conn, "source_ip", "id.orig_h"))
                destination = _ip(_first(row, "destination_ip", "id.resp_h")) or _ip(_first(conn, "destination_ip", "id.resp_h"))
                if not source or not destination:
                    continue
                dedupe = (uid or f"{source}>{destination}", source, destination)
                if dedupe in seen_smb:
                    continue
                seen_smb.add(dedupe)
                smbv1_candidates += 1
                event = _event_from_smb(row, conn, log_name, version)
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
                "smbv1_candidates": smbv1_candidates,
                "netbios_smbv1_findings": len(findings),
                "cross_segment_events": sum(1 for e in events if e["context_type"] == "cross_segment"),
                "external_events": sum(1 for e in events if e["context_type"] == "external"),
                "external_attempts_not_counted_as_reachable": external_attempts_not_reachable,
                "skipped_allowlisted": skipped_allowlisted,
                "skipped_no_segment_context": skipped_no_segment_context,
            },
            evidence={
                "inspected_logs": [name for name in ("conn", *SMB_LOGS) if context.log(name)],
                "segments_loaded": len(segments),
                "policy": policy,
                "notes": [
                    "NetBIOS is identified from TCP/UDP ports 137-139; these legacy services are reported only when they cross a configured segment boundary or involve a public IP.",
                    "TCP/445 alone is never classified as SMBv1. SMBv1 requires an explicit SMB protocol-log version/dialect such as SMB1, SMBv1, CIFS, or NT LM 0.12.",
                    "Cross-segment detection requires configured segment metadata; private addressing alone does not establish a boundary.",
                    "Unanswered Internet TCP probes are not treated as proof of reachable exposure when require_established_external is enabled.",
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
    kind = first["protocol_type"]
    context_type = first["context_type"]
    external = context_type == "external"
    if kind == "smbv1":
        severity = "high" if external else "medium"
        title = "SMBv1 exposed to public network" if external else "SMBv1 crossing network-segment boundary"
        summary = f"Observed {len(items)} explicitly identified SMBv1 session/event(s) {'involving a public Internet address' if external else 'crossing configured network segments'}. SMBv1 is obsolete and should be removed or tightly isolated."
        confidence, basis = "high", "protocol_log"
        tags = ["smb", "smbv1", "legacy-protocol"]
    else:
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
        services=["SMBv1"] if kind == "smbv1" else ["NetBIOS"],
        ports=ports,
        connection_pairs=pairs,
        timestamps=[e["timestamp"] for e in items[:MAX_EVIDENCE_ROWS] if e.get("timestamp") not in (None, "")],
        tags=tags + (["external"] if external else ["cross-segment"]),
        metadata={
            "protocol_type": kind,
            "context_type": context_type,
            "event_count": len(items),
            "source_segment": first.get("source_segment"),
            "destination_segment": first.get("destination_segment"),
            "smbv1_version_evidence": sorted({e.get("version_evidence") for e in items if e.get("version_evidence")}),
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


def _event_from_smb(row, conn, log_name, version):
    source = _ip(_first(row, "source_ip", "id.orig_h")) or _ip(_first(conn, "source_ip", "id.orig_h")) or ""
    destination = _ip(_first(row, "destination_ip", "id.resp_h")) or _ip(_first(conn, "destination_ip", "id.resp_h")) or ""
    port = _as_int(_first(row, "destination_port", "id.resp_p"))
    if port is None:
        port = _as_int(_first(conn, "destination_port", "id.resp_p"))
    return {
        "protocol_type": "smbv1",
        "basis": "protocol_log",
        "source": source,
        "destination": destination,
        "port": port,
        "protocol": _text(_first(row, "protocol", "proto")).lower() or _text(_first(conn, "protocol", "proto")).lower() or "tcp",
        "timestamp": _first(row, "timestamp", "ts") or _first(conn, "timestamp", "ts"),
        "connection": conn,
        "log_name": log_name,
        "version_evidence": version,
    }


def _explicit_smbv1(row: dict[str, Any]) -> str:
    for field in SMBV1_FIELDS:
        if field not in row or row.get(field) in (None, "", "-"):
            continue
        text = _text(row.get(field)).strip().lower()
        compact = text.replace(" ", "").replace("_", "").replace("-", "")
        if compact in {"1", "v1", "smb1", "smbv1", "cifs", "ntlm0.12", "ntlm012"} or "nt lm 0.12" in text:
            return f"{field}={_text(row.get(field))}"
    return ""


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
