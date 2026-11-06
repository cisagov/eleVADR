from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import ipaddress
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata


MAX_EVIDENCE_ROWS = 50
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


class OtOutboundInternetAnyProtocolModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="ot_outbound_internet_any_protocol",
        name="OT Outbound Internet Connection (Any Protocol)",
        description=(
            "Generic egress catch-all for sessions initiated by configured OT/control-system assets "
            "toward globally routable Internet destinations, irrespective of application protocol."
        ),
        category="security_analysis",
        required_logs=("conn",),
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        policy = _policy(context.metadata)
        segments = _load_segments(context.metadata)
        inventory = _load_inventory(context.metadata)
        explicit_ot = _string_set(policy.get("ot_hosts") or policy.get("control_system_hosts"))
        allowed_networks = _networks(policy.get("allowed_external_destinations", []))
        allowed_pairs = _pair_set(policy.get("allowed_pairs", []))
        ignored_services = _string_set(policy.get("ignored_services"))
        ignored_ports = _int_set(policy.get("ignored_ports"))
        require_observed = _bool(policy.get("require_observed_communication"), True)
        min_flows = max(1, _as_int(policy.get("min_flows")) or 1)

        classification_available = bool(segments or inventory or explicit_ot)
        if not classification_available:
            return ModuleResult(
                module_id=self.metadata.id,
                findings=[],
                metrics={
                    "connections_evaluated": len(context.connections),
                    "ot_outbound_public_flows": 0,
                    "ot_hosts_with_internet_egress": 0,
                    "ot_outbound_internet_findings": 0,
                    "skipped_unclassified": len(context.connections),
                    "skipped_allowlisted": 0,
                    "skipped_noncommunication": 0,
                },
                evidence={
                    "inspected_logs": ["conn"] if context.connections else [],
                    "classification_available": False,
                    "segments_loaded": len(segments),
                    "asset_inventory_records": len(context.metadata.get("asset_inventory", []) or []),
                    "notes": [
                        "No OT/control-system classification was supplied, so private addressing alone was not used to infer OT identity.",
                        "Configure OT segments, asset inventory roles, or ot_outbound_internet_policy.ot_hosts to enable detection.",
                    ],
                },
                warnings=[],
            )

        groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        identities: dict[str, _Identity] = {}
        skipped_unclassified = 0
        skipped_allowlisted = 0
        skipped_noncommunication = 0
        skipped_ignored = 0

        for row in context.connections:
            source = _ip(_first(row, "source_ip", "id.orig_h"))
            destination = _ip(_first(row, "destination_ip", "id.resp_h"))
            if not source or not destination:
                continue

            identity = _ot_identity(source, segments, inventory, explicit_ot)
            if identity is None:
                if _is_public(destination):
                    skipped_unclassified += 1
                continue
            if not _is_public(destination):
                continue
            if _ip_in_networks(destination, allowed_networks) or (source, destination) in allowed_pairs:
                skipped_allowlisted += 1
                continue

            service_tokens = _service_tokens(row.get("service"))
            port = _as_int(_first(row, "destination_port", "id.resp_p"))
            if (ignored_services and service_tokens & ignored_services) or (port is not None and port in ignored_ports):
                skipped_ignored += 1
                continue

            if require_observed and not _observed_communication(row):
                skipped_noncommunication += 1
                continue

            groups[source].append(row)
            identities[source] = identity

        findings: list[Finding] = []
        for source, rows in sorted(groups.items()):
            if len(rows) < min_flows:
                continue
            findings.append(_finding(source, rows, identities[source]))

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "connections_evaluated": len(context.connections),
                "ot_outbound_public_flows": sum(len(rows) for rows in groups.values()),
                "ot_hosts_with_internet_egress": len(findings),
                "ot_outbound_internet_findings": len(findings),
                "skipped_unclassified": skipped_unclassified,
                "skipped_allowlisted": skipped_allowlisted,
                "skipped_ignored": skipped_ignored,
                "skipped_noncommunication": skipped_noncommunication,
            },
            evidence={
                "inspected_logs": ["conn"],
                "classification_available": True,
                "segments_loaded": len(segments),
                "asset_inventory_records": len(context.metadata.get("asset_inventory", []) or []),
                "allowed_external_destinations": [str(net) for net in allowed_networks],
                "ignored_services": sorted(ignored_services),
                "ignored_ports": sorted(ignored_ports),
                "min_flows": min_flows,
                "require_observed_communication": require_observed,
                "notes": [
                    "This is a protocol-agnostic OT egress catch-all. It intentionally overlaps more specific DNS, NTP, HTTP, VPN, or ICS-protocol findings when the same connection qualifies.",
                    "Globally routable destinations are identified using Python IP address semantics; private, loopback, link-local, multicast, documentation, and other non-global destinations are excluded.",
                    "OT identity must come from configured segments, asset inventory roles, or explicit policy; private addressing alone is not treated as OT evidence.",
                    "By default, unanswered TCP SYNs and similarly unobserved communication are excluded so a scan attempt is not mislabeled as an established egress session.",
                    "Use allowed_external_destinations, allowed_pairs, ignored_services, or ignored_ports for approved vendor cloud, update, telemetry, or other sanctioned egress.",
                ],
            },
            warnings=[],
        )


def _finding(source: str, rows: list[dict[str, Any]], identity: _Identity) -> Finding:
    destinations: set[str] = set()
    services: set[str] = set()
    ports: set[int] = set()
    timestamps: list[float] = []
    pairs: list[dict[str, Any]] = []
    flows: list[dict[str, Any]] = []

    ordered = sorted(rows, key=lambda row: _as_float(_first(row, "timestamp", "ts")) or -1.0)
    for row in ordered:
        destination = _ip(_first(row, "destination_ip", "id.resp_h")) or ""
        protocol = _text(_first(row, "protocol", "proto")).lower()
        port = _as_int(_first(row, "destination_port", "id.resp_p"))
        tokens = _service_tokens(row.get("service"))
        ts = _as_float(_first(row, "timestamp", "ts"))
        destinations.add(destination)
        services.update(tokens)
        if port is not None:
            ports.add(port)
        if ts is not None:
            timestamps.append(ts)
        if len(pairs) < MAX_EVIDENCE_ROWS:
            pairs.append({"source": source, "destination": destination})
        if len(flows) < MAX_EVIDENCE_ROWS:
            flows.append({
                "timestamp": ts,
                "uid": _text(row.get("uid")),
                "source_ip": source,
                "destination_ip": destination,
                "destination_port": port,
                "protocol": protocol,
                "service": sorted(tokens),
                "conn_state": _text(_first(row, "conn_state", "state")),
                "orig_bytes": _as_int(row.get("orig_bytes")),
                "resp_bytes": _as_int(row.get("resp_bytes")),
            })

    confidence = "high" if identity.source in {"asset_inventory", "policy"} else "medium"
    summary = (
        f"OT/control-system host {source} initiated {len(rows)} observed connection(s) to "
        f"{len(destinations)} globally routable Internet destination(s). This generic egress finding is protocol-agnostic "
        "and is intended to catch outbound OT communication not covered by a more specific detector."
    )

    return Finding(
        title="OT Outbound Internet Connection",
        severity="medium",
        summary=summary,
        confidence=confidence,
        detection_basis="derived",
        devices=sorted({source, *destinations}),
        services=sorted(services),
        ports=sorted(ports),
        connection_pairs=pairs,
        flows=flows,
        timestamps=timestamps[:MAX_EVIDENCE_ROWS],
        tags=["ot", "internet", "egress", "outbound", "generic-catch-all"],
        metadata={
            "source_ip": source,
            "asset_name": identity.name,
            "asset_role": identity.role,
            "classification_source": identity.source,
            "external_destination_count": len(destinations),
            "external_destinations": sorted(destinations),
            "flow_count": len(rows),
            "evidence_truncated": len(rows) > MAX_EVIDENCE_ROWS,
        },
    )


def _policy(metadata: dict[str, Any]) -> dict[str, Any]:
    for key in ("ot_outbound_internet_policy", "ot_egress_policy", "outbound_internet_policy"):
        value = metadata.get(key)
        if isinstance(value, dict):
            return value
    return {}


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


def _is_public(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    # Multicast is globally scoped in Python's ipaddress semantics, but it is
    # not an Internet unicast destination and must not trigger OT egress.
    if address.is_multicast or address.is_unspecified or address.is_loopback or address.is_link_local:
        return False
    return address.is_global


def _observed_communication(row: dict[str, Any]) -> bool:
    protocol = _text(_first(row, "protocol", "proto")).lower()
    if protocol != "tcp":
        return True
    state = _text(_first(row, "conn_state", "state")).upper()
    if state and state not in {"S0", "REJ", "SH", "SHR", "RSTOS0"}:
        return True
    orig_bytes = _as_int(row.get("orig_bytes")) or 0
    resp_bytes = _as_int(row.get("resp_bytes")) or 0
    return orig_bytes > 0 or resp_bytes > 0


def _networks(value: Any) -> list[ipaddress._BaseNetwork]:
    values = value if isinstance(value, list) else ([value] if value else [])
    result: list[ipaddress._BaseNetwork] = []
    for item in values:
        try:
            if "/" in str(item):
                result.append(ipaddress.ip_network(str(item), strict=False))
            else:
                addr = ipaddress.ip_address(str(item))
                result.append(ipaddress.ip_network(f"{addr}/{addr.max_prefixlen}", strict=False))
        except ValueError:
            continue
    return result


def _ip_in_networks(value: str, networks: list[ipaddress._BaseNetwork]) -> bool:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(addr.version == network.version and addr in network for network in networks)


def _pair_set(value: Any) -> set[tuple[str, str]]:
    result: set[tuple[str, str]] = set()
    if not isinstance(value, list):
        return result
    for item in value:
        if isinstance(item, dict):
            source = _ip(item.get("source") or item.get("src"))
            destination = _ip(item.get("destination") or item.get("dst"))
            if source and destination:
                result.add((source, destination))
    return result


def _string_set(value: Any) -> set[str]:
    if value is None:
        return set()
    values = value if isinstance(value, (list, tuple, set)) else [value]
    return {_text(item).lower() if not _ip(item) else _ip(item) for item in values if _text(item)}


def _int_set(value: Any) -> set[int]:
    values = value if isinstance(value, (list, tuple, set)) else ([value] if value is not None else [])
    result: set[int] = set()
    for item in values:
        parsed = _as_int(item)
        if parsed is not None:
            result.add(parsed)
    return result


def _service_tokens(value: Any) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, (list, tuple, set)):
        items = value
    else:
        items = str(value).replace(",", " ").split()
    return {_text(item).lower() for item in items if _text(item) and _text(item) != "-"}


def _first(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in row and row[key] not in (None, "", "-"):
            return row[key]
    return None


def _ip(value: Any) -> str | None:
    if value in (None, "", "-"):
        return None
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _as_int(value: Any) -> int | None:
    try:
        return int(value) if value not in (None, "", "-") else None
    except (TypeError, ValueError):
        return None


def _as_float(value: Any) -> float | None:
    try:
        return float(value) if value not in (None, "", "-") else None
    except (TypeError, ValueError):
        return None


def _bool(value: Any, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}
