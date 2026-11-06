from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import ipaddress
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata


MAX_EVIDENCE_ROWS = 50
OT_ROLE_TOKENS = {
    "ot", "ics", "control", "control system", "scada", "plc", "rtu", "hmi",
    "historian", "engineering", "engineering workstation", "dcs", "bas", "bms",
    "controller", "process", "industrial",
}
IT_ROLE_TOKENS = {
    "it", "enterprise", "corporate", "business", "user", "users", "office",
    "server", "datacenter", "data center", "non-ot", "non ot", "level 4", "l4", "level 5", "l5",
}
DMZ_ROLE_TOKENS = {"dmz", "idmz", "industrial dmz", "industrial-dmz", "demilitarized"}


@dataclass(frozen=True, slots=True)
class _Segment:
    name: str
    role: str
    network: ipaddress._BaseNetwork


@dataclass(frozen=True, slots=True)
class _Identity:
    ip: str
    zone: str
    role: str
    name: str
    source: str
    segment: str | None = None


class ControlSystemEnterpriseNonDmzModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="control_system_enterprise_non_dmz",
        name="Control System to Enterprise IT Communication (Non-DMZ)",
        description=(
            "Identifies direct communication between configured control-system/OT assets and enterprise or "
            "other non-OT networks when neither observed endpoint is an approved control-system DMZ intermediary."
        ),
        category="security_analysis",
        required_logs=("conn",),
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        policy = _policy(context.metadata)
        segments = _load_segments(context.metadata)
        inventory = _load_inventory(context.metadata)
        explicit_ot = _string_set(policy.get("ot_hosts"))
        explicit_it = _string_set(policy.get("enterprise_hosts")) | _string_set(policy.get("non_ot_hosts"))
        explicit_dmz = _string_set(policy.get("dmz_hosts"))
        allowed_pairs = _pair_set(policy.get("allowed_pairs"))
        allowed_segment_pairs = _segment_pair_set(policy.get("allowed_segment_pairs"))
        trusted_service_hosts = _trusted_service_hosts(policy.get("trusted_service_hosts"))
        report_only_communication = _bool(policy.get("require_observed_communication"), True)

        classification_available = bool(segments or inventory or explicit_ot or explicit_it or explicit_dmz)
        if not classification_available:
            return ModuleResult(
                module_id=self.metadata.id,
                findings=[],
                metrics={
                    "control_system_enterprise_non_dmz_findings": 0,
                    "direct_ot_it_flows": 0,
                    "skipped_unclassified": len(context.connections),
                    "skipped_allowlisted": 0,
                    "skipped_noncommunication": 0,
                },
                evidence={
                    "inspected_logs": ["conn"] if context.connections else [],
                    "classification_available": False,
                    "segments_loaded": 0,
                    "asset_inventory_records": 0,
                    "policy": policy,
                    "notes": [
                        "No OT/enterprise/DMZ classification was supplied, so the module did not infer zones from private addressing alone.",
                        "Configure segment roles, asset inventory roles, or control_system_enterprise_policy host lists to enable detection.",
                    ],
                },
                warnings=[],
            )

        groups: dict[tuple[str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
        group_meta: dict[tuple[str, str, str, str], dict[str, Any]] = {}
        skipped_unclassified = 0
        skipped_allowlisted = 0
        skipped_noncommunication = 0
        dmz_endpoint_flows = 0

        for row in context.connections:
            source = _ip(_first(row, "source_ip", "id.orig_h"))
            destination = _ip(_first(row, "destination_ip", "id.resp_h"))
            if not source or not destination:
                skipped_unclassified += 1
                continue

            src = _identity(source, segments, inventory, explicit_ot, explicit_it, explicit_dmz)
            dst = _identity(destination, segments, inventory, explicit_ot, explicit_it, explicit_dmz)
            if src is None or dst is None:
                skipped_unclassified += 1
                continue

            if src.zone == "dmz" or dst.zone == "dmz":
                dmz_endpoint_flows += 1
                continue

            zones = {src.zone, dst.zone}
            if zones != {"ot", "it"}:
                continue

            if report_only_communication and not _observed_communication(row):
                skipped_noncommunication += 1
                continue

            if (source, destination) in allowed_pairs or (destination, source) in allowed_pairs:
                skipped_allowlisted += 1
                continue

            if src.segment and dst.segment and frozenset((src.segment, dst.segment)) in allowed_segment_pairs:
                skipped_allowlisted += 1
                continue

            if _matches_trusted_service_host(row, source, destination, trusted_service_hosts):
                skipped_allowlisted += 1
                continue

            ot = src if src.zone == "ot" else dst
            it = dst if src.zone == "ot" else src
            direction = "ot_to_it" if src.zone == "ot" else "it_to_ot"
            key = (ot.ip, it.ip, ot.segment or "", it.segment or "")
            groups[key].append(row)
            group_meta[key] = {"ot": ot, "it": it, "direction": direction}

        findings = [
            _finding(rows, group_meta[key])
            for key, rows in sorted(groups.items())
        ]

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "control_system_enterprise_non_dmz_findings": len(findings),
                "direct_ot_it_flows": sum(len(rows) for rows in groups.values()),
                "ot_assets_involved": len({meta["ot"].ip for meta in group_meta.values()}),
                "enterprise_assets_involved": len({meta["it"].ip for meta in group_meta.values()}),
                "dmz_endpoint_flows_excluded": dmz_endpoint_flows,
                "skipped_unclassified": skipped_unclassified,
                "skipped_allowlisted": skipped_allowlisted,
                "skipped_noncommunication": skipped_noncommunication,
            },
            evidence={
                "inspected_logs": ["conn"],
                "classification_available": True,
                "segments_loaded": len(segments),
                "asset_inventory_records": len(context.metadata.get("asset_inventory", []) or []),
                "policy": policy,
                "notes": [
                    "A finding requires one endpoint classified as OT/control-system and the other as enterprise/non-OT; private addressing alone is not sufficient classification.",
                    "Flows with a DMZ endpoint are excluded because the observed connection terminates at the DMZ rather than directly at the opposite trust zone.",
                    "Zeek conn.log does not reveal invisible routed hops. A transparent/routed DMZ device that preserves original endpoints cannot be proven or disproven from endpoint telemetry alone.",
                    "Use allowed_pairs or allowed_segment_pairs for approved direct exceptions such as intentionally dual-homed historians or management systems.",
                ],
            },
            warnings=[],
        )


def _finding(rows: list[dict[str, Any]], meta: dict[str, Any]) -> Finding:
    ot: _Identity = meta["ot"]
    it: _Identity = meta["it"]
    directions: set[str] = set()
    services: set[str] = set()
    ports: set[int] = set()
    pairs: list[dict[str, Any]] = []
    flows: list[dict[str, Any]] = []
    timestamps: list[Any] = []

    for row in rows:
        source = _ip(_first(row, "source_ip", "id.orig_h")) or ""
        destination = _ip(_first(row, "destination_ip", "id.resp_h")) or ""
        service = _text(row.get("service"))
        port = _as_int(_first(row, "destination_port", "id.resp_p"))
        protocol = _text(_first(row, "protocol", "proto")).lower()
        direction = "ot_to_it" if source == ot.ip else "it_to_ot"
        directions.add(direction)
        if service:
            services.update(token.strip().lower() for token in service.split(",") if token.strip())
        if port is not None:
            ports.add(port)
        timestamp = _first(row, "timestamp", "ts")
        if timestamp not in (None, ""):
            timestamps.append(timestamp)
        pairs.append({
            "source": source,
            "destination": destination,
            "port": port,
            "protocol": protocol,
            "service": service or None,
            "direction": direction,
        })
        if len(flows) < MAX_EVIDENCE_ROWS:
            flows.append(dict(row))

    classification_sources = {ot.source, it.source}
    confidence = "high" if classification_sources <= {"asset_inventory", "policy"} else "medium"
    severity = "high" if _has_control_or_admin_service(services, ports) else "medium"

    return Finding(
        title=f"Direct control-system to enterprise communication: {ot.ip} <-> {it.ip}",
        severity=severity,
        summary=(
            f"Observed {len(rows)} direct flow(s) between control-system asset {ot.name} ({ot.ip}) and "
            f"enterprise/non-OT host {it.name} ({it.ip}) with neither observed endpoint classified as a control-system DMZ. "
            "Review whether this is an approved architecture exception or a segmentation/DMZ-bypass condition."
        ),
        confidence=confidence,
        detection_basis="derived",
        devices=sorted({ot.ip, it.ip}),
        services=sorted(services),
        ports=sorted(ports),
        connection_pairs=pairs[:MAX_EVIDENCE_ROWS],
        flows=flows,
        subnets=sorted({value for value in (ot.segment, it.segment) if value}),
        timestamps=sorted(timestamps, key=str)[:MAX_EVIDENCE_ROWS],
        tags=["ot", "ics", "enterprise", "segmentation", "dmz-bypass"],
        metadata={
            "finding_type": "direct_ot_enterprise_non_dmz",
            "ot_ip": ot.ip,
            "ot_name": ot.name,
            "ot_role": ot.role,
            "ot_classification_source": ot.source,
            "ot_segment": ot.segment,
            "enterprise_ip": it.ip,
            "enterprise_name": it.name,
            "enterprise_role": it.role,
            "enterprise_classification_source": it.source,
            "enterprise_segment": it.segment,
            "directions": sorted(directions),
            "flow_count": len(rows),
            "evidence_truncated": len(rows) > MAX_EVIDENCE_ROWS,
            "path_limitation": "conn.log shows endpoints, not invisible routed intermediaries",
        },
    )


def _policy(metadata: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(metadata, dict):
        return {}
    for key in ("control_system_enterprise_policy", "ot_enterprise_policy", "non_dmz_ot_it_policy"):
        value = metadata.get(key)
        if isinstance(value, dict):
            return value
    return {}


def _load_segments(metadata: dict[str, Any]) -> list[_Segment]:
    raw = metadata.get("segments") if isinstance(metadata, dict) else None
    if not isinstance(raw, list):
        return []
    out: list[_Segment] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        cidr = _text(item.get("cidr") or item.get("subnet") or item.get("network"))
        role = _text(item.get("role") or item.get("zone") or item.get("type") or item.get("purdue_level"))
        name = _text(item.get("name") or cidr)
        if not cidr or not role:
            continue
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        out.append(_Segment(name=name or cidr, role=role, network=network))
    return out


def _load_inventory(metadata: dict[str, Any]) -> dict[str, _Identity]:
    raw = metadata.get("asset_inventory") if isinstance(metadata, dict) else None
    if not isinstance(raw, list):
        return {}
    out: dict[str, _Identity] = {}
    for item in raw:
        if not isinstance(item, dict):
            continue
        ip = _ip(item.get("ip") or item.get("ip_address") or item.get("address"))
        role = _text(item.get("role") or item.get("type") or item.get("asset_type"))
        if not ip or not role:
            continue
        zone = _zone_from_role(role)
        if zone is None:
            continue
        name = _text(item.get("name") or item.get("hostname") or ip) or ip
        out[ip] = _Identity(ip=ip, zone=zone, role=role, name=name, source="asset_inventory")
    return out


def _identity(
    ip: str,
    segments: list[_Segment],
    inventory: dict[str, _Identity],
    explicit_ot: set[str],
    explicit_it: set[str],
    explicit_dmz: set[str],
) -> _Identity | None:
    if ip in explicit_dmz:
        return _Identity(ip, "dmz", "DMZ", ip, "policy")
    if ip in explicit_ot:
        return _Identity(ip, "ot", "OT", ip, "policy")
    if ip in explicit_it:
        return _Identity(ip, "it", "Enterprise/IT", ip, "policy")
    # For this architecture detector, explicit network-segment classification is
    # more authoritative than descriptive asset roles (for example an engineering
    # workstation that resides in an IT-classified engineering segment).
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        address = None
    if address is not None:
        best: _Segment | None = None
        for segment in segments:
            if address.version == segment.network.version and address in segment.network:
                if best is None or segment.network.prefixlen > best.network.prefixlen:
                    best = segment
        if best is not None:
            zone = _zone_from_role(best.role)
            if zone is not None:
                inv = inventory.get(ip)
                return _Identity(
                    ip, zone, best.role, inv.name if inv else ip, "segment", best.name
                )
    if ip in inventory:
        return inventory[ip]
    return None


def _zone_from_role(role: str) -> str | None:
    normalized = role.strip().lower().replace("_", " ")
    if normalized in DMZ_ROLE_TOKENS or "dmz" in normalized:
        return "dmz"
    if normalized in OT_ROLE_TOKENS or any(token in normalized for token in ("plc", "scada", "control", "industrial", "historian", "hmi", "rtu", "dcs", "bas", "bms")):
        return "ot"
    if normalized in IT_ROLE_TOKENS or any(token in normalized for token in ("enterprise", "corporate", "business", "office", "user", "non-ot", "non ot")):
        return "it"
    return None


def _has_control_or_admin_service(services: set[str], ports: set[int]) -> bool:
    high_services = {"ssh", "telnet", "rdp", "vnc", "smb", "modbus", "dnp3", "s7comm", "enip", "bacnet", "mms"}
    high_ports = {22, 23, 445, 3389, 5900, 502, 20000, 102, 44818, 47808}
    return bool(services & high_services or ports & high_ports)


def _observed_communication(row: dict[str, Any]) -> bool:
    proto = _text(_first(row, "protocol", "proto")).lower()
    if proto != "tcp":
        return True
    state = _text(row.get("conn_state")).upper()
    if state in {"SF", "S1", "S2", "S3", "RSTO", "RSTR", "RSTOS0", "RSTRH"}:
        return True
    orig_bytes = _as_int(row.get("orig_bytes")) or 0
    resp_bytes = _as_int(row.get("resp_bytes")) or 0
    return (orig_bytes + resp_bytes) > 0


def _trusted_service_hosts(value: Any) -> dict[str, tuple[set[str], set[int]]]:
    out: dict[str, tuple[set[str], set[int]]] = {}
    if not isinstance(value, list):
        return out
    for item in value:
        if not isinstance(item, dict):
            continue
        host = _ip(item.get("host") or item.get("ip"))
        if not host:
            continue
        services = {_text(v).lower() for v in item.get("services", []) if _text(v)} if isinstance(item.get("services"), list) else set()
        ports = {_as_int(v) for v in item.get("ports", [])} if isinstance(item.get("ports"), list) else set()
        out[host] = (services, {v for v in ports if v is not None})
    return out


def _matches_trusted_service_host(
    row: dict[str, Any],
    source: str,
    destination: str,
    trusted: dict[str, tuple[set[str], set[int]]],
) -> bool:
    service = _text(row.get("service")).lower()
    port = _as_int(_first(row, "destination_port", "id.resp_p"))
    # Infrastructure is normally the responder, but accept either endpoint for
    # captures where directionality is reversed while still requiring a service/port match.
    for host in (destination, source):
        rule = trusted.get(host)
        if not rule:
            continue
        services, ports = rule
        if (service and service in services) or (port is not None and port in ports):
            return True
    return False


def _pair_set(value: Any) -> set[tuple[str, str]]:
    out: set[tuple[str, str]] = set()
    if not isinstance(value, list):
        return out
    for item in value:
        if isinstance(item, dict):
            source = _ip(item.get("source") or item.get("src"))
            destination = _ip(item.get("destination") or item.get("dst"))
            if source and destination:
                out.add((source, destination))
        elif isinstance(item, (list, tuple)) and len(item) >= 2:
            source, destination = _ip(item[0]), _ip(item[1])
            if source and destination:
                out.add((source, destination))
    return out


def _segment_pair_set(value: Any) -> set[frozenset[str]]:
    out: set[frozenset[str]] = set()
    if not isinstance(value, list):
        return out
    for item in value:
        if isinstance(item, dict):
            source = _text(item.get("source") or item.get("from"))
            destination = _text(item.get("destination") or item.get("to"))
            if source and destination:
                out.add(frozenset((source, destination)))
        elif isinstance(item, (list, tuple)) and len(item) >= 2:
            source, destination = _text(item[0]), _text(item[1])
            if source and destination:
                out.add(frozenset((source, destination)))
    return out


def _string_set(value: Any) -> set[str]:
    if not isinstance(value, (list, tuple, set)):
        return set()
    return {_text(item) for item in value if _text(item)}


def _bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return default


def _first(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = row.get(key)
        if value not in (None, "", "-"):
            return value
    return None


def _text(value: Any) -> str:
    if value in (None, "-"):
        return ""
    return str(value).strip()


def _ip(value: Any) -> str | None:
    text = _text(value)
    if not text:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def _as_int(value: Any) -> int | None:
    if value in (None, "", "-"):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
