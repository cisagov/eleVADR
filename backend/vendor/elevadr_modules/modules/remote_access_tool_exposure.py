from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import ipaddress
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata

MAX_EVIDENCE_ROWS = 50
ESTABLISHED_TCP_STATES = {"SF", "S1", "S2", "S3", "RSTO", "RSTR", "RSTOS0", "RSTRH"}

DEFAULT_TOOL_PORTS: dict[str, set[tuple[str, int]]] = {
    "vnc": {("tcp", 5900), ("tcp", 5901), ("tcp", 5902)},
    "pcanywhere": {("tcp", 5631), ("udp", 5632)},
    "teamviewer": {("tcp", 5938), ("udp", 5938)},
    "anydesk": {("tcp", 7070)},
    "radmin": {("tcp", 4899)},
}

SERVICE_ALIASES = {
    "vnc": "vnc",
    "rfb": "vnc",
    "pcanywhere": "pcanywhere",
    "pc-anywhere": "pcanywhere",
    "teamviewer": "teamviewer",
    "anydesk": "anydesk",
    "radmin": "radmin",
}

OT_ROLE_TOKENS = {"ot", "ics", "scada", "plc", "rtu", "hmi", "dcs", "bas", "bms", "control", "industrial"}


@dataclass(frozen=True, slots=True)
class _Segment:
    name: str
    role: str
    network: ipaddress._BaseNetwork


class RemoteAccessToolExposureModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="remote_access_tool_exposure",
        name="VNC / Remote Access Tool Exposure",
        description=(
            "Identifies VNC, pcAnywhere, TeamViewer, AnyDesk, Radmin, and configured remote-access tools, "
            "with higher priority for traffic involving OT/ICS segments or public Internet peers."
        ),
        category="security_analysis",
        required_logs=("conn",),
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        policy = _policy(context.metadata)
        segments = _load_segments(context.metadata)
        tool_ports = _tool_ports(policy.get("tool_ports"))
        allowed_hosts = _string_set(policy.get("allowed_hosts"))
        allowed_pairs = _pair_set(policy.get("allowed_pairs"))
        ignored_tools = {_normalize_tool(v) for v in _string_set(policy.get("ignored_tools"))}
        ignored_tools.discard("")
        require_established_external = _bool(policy.get("require_established_external"), True)

        groups: dict[tuple[str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
        group_meta: dict[tuple[str, str, str, str], dict[str, Any]] = {}
        candidates = 0
        ot_flows = 0
        external_flows = 0
        generic_flows = 0
        skipped_allowlisted = 0
        external_attempts_not_reachable = 0

        for row in context.connections:
            source = _ip(_first(row, "source_ip", "id.orig_h"))
            destination = _ip(_first(row, "destination_ip", "id.resp_h"))
            if not source or not destination:
                continue
            tool, basis = _tool_identity(row, tool_ports)
            if not tool or tool in ignored_tools:
                continue
            candidates += 1

            if source in allowed_hosts or destination in allowed_hosts or (source, destination) in allowed_pairs:
                skipped_allowlisted += 1
                continue

            source_seg = _segment_for(source, segments)
            dest_seg = _segment_for(destination, segments)
            source_ot = _is_ot_segment(source_seg)
            dest_ot = _is_ot_segment(dest_seg)
            source_public = _is_public(source)
            dest_public = _is_public(destination)
            external = source_public or dest_public
            ot_involved = source_ot or dest_ot

            if external and require_established_external and not _observed_reachable(row):
                external_attempts_not_reachable += 1
                continue

            if external and ot_involved:
                context_type = "internet_ot_remote_access"
                external_flows += 1
                ot_flows += 1
            elif ot_involved:
                context_type = "ot_remote_access"
                ot_flows += 1
            elif external:
                context_type = "internet_remote_access"
                external_flows += 1
            else:
                context_type = "remote_access_observed"
                generic_flows += 1

            key = (context_type, tool, source, destination)
            groups[key].append(row)
            group_meta[key] = {
                "context_type": context_type,
                "tool": tool,
                "basis": basis,
                "source_segment": source_seg.name if source_seg else None,
                "source_role": source_seg.role if source_seg else None,
                "destination_segment": dest_seg.name if dest_seg else None,
                "destination_role": dest_seg.role if dest_seg else None,
            }

        findings = [_finding(rows, group_meta[key]) for key, rows in sorted(groups.items())]

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "remote_access_candidates": candidates,
                "remote_access_findings": len(findings),
                "ot_remote_access_flows": ot_flows,
                "external_remote_access_flows": external_flows,
                "generic_remote_access_flows": generic_flows,
                "external_attempts_not_counted_as_reachable": external_attempts_not_reachable,
                "skipped_allowlisted": skipped_allowlisted,
            },
            evidence={
                "inspected_logs": ["conn"] + (["vnc"] if context.vnc else []),
                "segments_loaded": len(segments),
                "tool_ports": {name: sorted(f"{proto}/{port}" for proto, port in values) for name, values in sorted(tool_ports.items())},
                "policy": policy,
                "notes": [
                    "Port matches are service-consistent evidence, not proof that a specific remote-access product generated the traffic.",
                    "An explicit Zeek service label such as vnc/rfb raises confidence when available.",
                    "Remote-access traffic involving configured OT/ICS segments is prioritized over ordinary enterprise remote-support traffic.",
                    "Internet TCP probes without an established/replied connection are not treated as proof that the remote-access service is reachable when require_established_external is enabled.",
                    "TeamViewer can fall back to other ports such as 443/80; this detector intentionally does not label generic HTTPS/HTTP as TeamViewer without stronger evidence.",
                ],
            },
            warnings=[],
        )


def _finding(rows: list[dict[str, Any]], meta: dict[str, Any]) -> Finding:
    tool = meta["tool"]
    context_type = meta["context_type"]
    ports: set[int] = set()
    services: set[str] = set()
    devices: set[str] = set()
    pairs: list[dict[str, Any]] = []
    timestamps: list[Any] = []
    explicit = meta["basis"] == "zeek_service"

    for row in rows:
        source = _ip(_first(row, "source_ip", "id.orig_h")) or ""
        destination = _ip(_first(row, "destination_ip", "id.resp_h")) or ""
        port = _as_int(_first(row, "destination_port", "id.resp_p"))
        proto = _text(_first(row, "protocol", "proto")).lower()
        service = _text(row.get("service"))
        devices.update(v for v in (source, destination) if v)
        if port is not None:
            ports.add(port)
        if service and service != "-":
            services.update(_service_tokens(service))
        ts = _first(row, "timestamp", "ts")
        if ts not in (None, ""):
            timestamps.append(ts)
        if len(pairs) < MAX_EVIDENCE_ROWS:
            pairs.append({"source": source, "destination": destination, "protocol": proto, "destination_port": port})

    display = {"vnc": "VNC", "pcanywhere": "pcAnywhere", "teamviewer": "TeamViewer", "anydesk": "AnyDesk", "radmin": "Radmin"}.get(tool, tool)
    if context_type == "internet_ot_remote_access":
        severity = "high"
        title = f"{display} remote access observed between Internet and OT"
        summary = f"Observed {len(rows)} {display}-consistent flow(s) between a public Internet peer and a configured OT/ICS segment. Validate whether this remote-access path is approved and appropriately mediated."
    elif context_type == "ot_remote_access":
        severity = "medium"
        title = f"{display} remote access observed involving OT"
        summary = f"Observed {len(rows)} {display}-consistent flow(s) involving a configured OT/ICS segment. Confirm the endpoints are approved engineering/support systems and that remote access is controlled."
    elif context_type == "internet_remote_access":
        severity = "medium"
        title = f"{display} remote access observed with Internet peer"
        summary = f"Observed {len(rows)} {display}-consistent flow(s) involving a public Internet peer. Validate whether the externally reachable/use path is expected."
    else:
        severity = "low"
        title = f"{display} remote access traffic observed"
        summary = f"Observed {len(rows)} flow(s) consistent with {display}. This is retained for remote-access visibility even though no configured OT segment or public peer was involved."

    return Finding(
        title=title,
        severity=severity,
        summary=summary,
        confidence="high" if explicit else "medium",
        detection_basis="zeek_service" if explicit else "port",
        devices=sorted(devices),
        services=sorted(services),
        ports=sorted(ports),
        connection_pairs=pairs,
        timestamps=timestamps[:MAX_EVIDENCE_ROWS],
        tags=["remote-access", tool] + (["ot"] if "ot" in context_type else []) + (["external"] if "internet" in context_type else []),
        metadata={
            "tool": tool,
            "context_type": context_type,
            "flow_count": len(rows),
            "source_segment": meta.get("source_segment"),
            "source_role": meta.get("source_role"),
            "destination_segment": meta.get("destination_segment"),
            "destination_role": meta.get("destination_role"),
        },
    )


def _tool_identity(row: dict[str, Any], tool_ports: dict[str, set[tuple[str, int]]]) -> tuple[str, str]:
    for token in _service_tokens(row.get("service")):
        tool = _normalize_tool(token)
        if tool:
            return tool, "zeek_service"
    proto = _text(_first(row, "protocol", "proto")).lower()
    port = _as_int(_first(row, "destination_port", "id.resp_p"))
    if not proto or port is None:
        return "", ""
    for tool, entries in tool_ports.items():
        if (proto, port) in entries:
            return tool, "port"
    return "", ""


def _tool_ports(value: Any) -> dict[str, set[tuple[str, int]]]:
    result = {name: set(entries) for name, entries in DEFAULT_TOOL_PORTS.items()}
    if not isinstance(value, dict):
        return result
    for name, items in value.items():
        tool = _normalize_tool(name) or _text(name).lower()
        parsed: set[tuple[str, int]] = set()
        if isinstance(items, list):
            for item in items:
                if isinstance(item, int):
                    parsed.add(("tcp", item))
                elif isinstance(item, str) and "/" in item:
                    proto, _, p = item.partition("/")
                    port = _as_int(p)
                    if proto.lower() in {"tcp", "udp"} and port is not None:
                        parsed.add((proto.lower(), port))
                elif isinstance(item, dict):
                    proto = _text(item.get("protocol", "tcp")).lower()
                    port = _as_int(item.get("port"))
                    if proto in {"tcp", "udp"} and port is not None:
                        parsed.add((proto, port))
        if parsed:
            result[tool] = parsed
    return result


def _normalize_tool(value: Any) -> str:
    token = _text(value).lower().replace("_", "-")
    compact = token.replace("-", "").replace(" ", "")
    for alias, tool in SERVICE_ALIASES.items():
        if compact == alias.replace("-", "").replace(" ", ""):
            return tool
    return ""


def _load_segments(metadata: dict[str, Any]) -> list[_Segment]:
    rows = metadata.get("segments", []) if isinstance(metadata, dict) else []
    result: list[_Segment] = []
    if not isinstance(rows, list):
        return result
    for row in rows:
        if not isinstance(row, dict):
            continue
        cidr = _text(row.get("cidr"))
        if not cidr:
            continue
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        result.append(_Segment(_text(row.get("name")) or cidr, _text(row.get("role")), network))
    return result


def _segment_for(ip: str, segments: list[_Segment]) -> _Segment | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for segment in segments:
        if addr in segment.network:
            return segment
    return None


def _is_ot_segment(segment: _Segment | None) -> bool:
    if not segment:
        return False
    text = f"{segment.name} {segment.role}".lower()
    return any(token in text for token in OT_ROLE_TOKENS)


def _is_public(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def _observed_reachable(row: dict[str, Any]) -> bool:
    proto = _text(_first(row, "protocol", "proto")).lower()
    if proto != "tcp":
        resp_bytes = _as_int(_first(row, "destination_bytes", "resp_bytes")) or 0
        return resp_bytes > 0 or (_as_int(_first(row, "destination_packets", "resp_pkts")) or 0) > 0
    state = _text(_first(row, "connection_state", "conn_state")).upper()
    if state in ESTABLISHED_TCP_STATES:
        return True
    return (_as_int(_first(row, "destination_bytes", "resp_bytes")) or 0) > 0


def _service_tokens(value: Any) -> set[str]:
    if value in (None, "", "-"):
        return set()
    text = str(value).replace(",", " ")
    return {part.strip().lower() for part in text.split() if part.strip() and part.strip() != "-"}


def _policy(metadata: dict[str, Any]) -> dict[str, Any]:
    value = metadata.get("remote_access_tool_policy", {}) if isinstance(metadata, dict) else {}
    return value if isinstance(value, dict) else {}


def _pair_set(value: Any) -> set[tuple[str, str]]:
    result: set[tuple[str, str]] = set()
    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                source = _text(item.get("source"))
                destination = _text(item.get("destination"))
                if source and destination:
                    result.add((source, destination))
    return result


def _string_set(value: Any) -> set[str]:
    return {_text(v) for v in value} if isinstance(value, list) else set()


def _bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        if value.strip().lower() in {"true", "1", "yes", "on"}:
            return True
        if value.strip().lower() in {"false", "0", "no", "off"}:
            return False
    return default


def _first(row: dict[str, Any], *names: str) -> Any:
    for name in names:
        if name in row and row[name] not in (None, ""):
            return row[name]
    return None


def _ip(value: Any) -> str | None:
    text = _text(value)
    if not text:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
