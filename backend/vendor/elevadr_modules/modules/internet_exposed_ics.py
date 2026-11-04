from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import ipaddress
import re
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata


MAX_EVIDENCE_ROWS = 50
DEFAULT_ADMIN_PORTS = {
    22, 23, 80, 443, 3389, 5900, 5901, 5985, 5986, 8080, 8443, 9443,
}
DEFAULT_ADMIN_SERVICES = {
    "ssh", "telnet", "http", "https", "ssl", "tls", "rdp", "vnc", "winrm",
}
ICS_ROLE_TOKENS = {
    "ics", "ot", "scada", "plc", "rtu", "hmi", "bas", "bms", "historian",
    "dcs", "controller", "control", "control system", "industrial", "process",
}
DMZ_ROLE_TOKENS = {"dmz", "idmz", "industrial dmz", "industrial-dmz", "demilitarized"}
ESTABLISHED_TCP_STATES = {"SF", "S1", "S2", "S3", "RSTO", "RSTR", "RSTOS0", "RSTRH"}


@dataclass(frozen=True, slots=True)
class _Segment:
    name: str
    role: str
    network: ipaddress._BaseNetwork


@dataclass(frozen=True, slots=True)
class _AssetIdentity:
    ip: str
    role: str
    source: str
    name: str


class InternetExposedIcsModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="internet_exposed_ics",
        name="Internet-Exposed ICS Device / External Admin to PLC/HMI",
        description=(
            "Identifies configured ICS assets communicating directly with public IP addresses and "
            "Internet-originated administrative access to PLC, RTU, HMI, BAS, historian, or other OT assets."
        ),
        category="security_analysis",
        required_logs=("conn",),
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        policy = _policy(context.metadata)
        segments = _load_segments(context.metadata)
        inventory_identities = _load_inventory_identities(context.metadata)
        explicit_ics_hosts = _string_set(policy.get("ics_hosts"))
        explicit_dmz_hosts = _string_set(policy.get("dmz_hosts"))
        allowed_external_networks = _networks(policy.get("allowed_external_destinations", []))
        allowed_pairs = _pair_set(policy.get("allowed_pairs", []))
        admin_ports = _int_set(policy.get("admin_ports"), DEFAULT_ADMIN_PORTS)
        admin_services = _string_set(policy.get("admin_services")) or set(DEFAULT_ADMIN_SERVICES)
        require_established_admin = _bool(policy.get("require_established_admin"), True)

        classification_available = bool(segments or inventory_identities or explicit_ics_hosts)
        if not classification_available:
            return ModuleResult(
                module_id=self.metadata.id,
                findings=[],
                metrics={
                    "internet_exposed_ics_findings": 0,
                    "direct_ics_internet_flows": 0,
                    "external_admin_flows": 0,
                    "skipped_unclassified": len(context.connections),
                    "skipped_allowlisted": 0,
                },
                evidence={
                    "inspected_logs": ["conn"] if context.connections else [],
                    "segments_loaded": len(segments),
                    "asset_inventory_records": len(context.metadata.get("asset_inventory", []) or []),
                    "classification_available": False,
                    "policy": policy,
                    "notes": [
                        "No ICS asset classification was supplied, so the module did not infer ICS identity from private addressing alone.",
                        "Configure OT/ICS segments, asset_inventory.json/csv roles, or internet_exposed_ics_policy.ics_hosts to enable detection.",
                    ],
                },
                warnings=[],
            )

        groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        group_meta: dict[tuple[str, str], dict[str, Any]] = {}
        skipped_allowlisted = 0
        skipped_unclassified = 0
        skipped_noncommunication = 0
        inbound_attempts_not_reachable = 0

        for row in context.connections:
            source = _ip(_first(row, "source_ip", "id.orig_h"))
            destination = _ip(_first(row, "destination_ip", "id.resp_h"))
            if not source or not destination:
                continue

            src_identity = _ics_identity(source, segments, inventory_identities, explicit_ics_hosts, explicit_dmz_hosts)
            dst_identity = _ics_identity(destination, segments, inventory_identities, explicit_ics_hosts, explicit_dmz_hosts)
            src_public = _is_public(source)
            dst_public = _is_public(destination)

            if not ((src_identity and dst_public) or (dst_identity and src_public)):
                if (src_public or dst_public) and not (src_identity or dst_identity):
                    skipped_unclassified += 1
                continue

            ics_identity = src_identity if src_identity else dst_identity
            ics_ip = source if src_identity else destination
            external_ip = destination if src_identity else source
            direction = "ics_to_internet" if src_identity else "internet_to_ics"

            if _ip_in_networks(external_ip, allowed_external_networks):
                skipped_allowlisted += 1
                continue
            if (source, destination) in allowed_pairs:
                skipped_allowlisted += 1
                continue

            if not _observed_communication(row):
                if direction == "internet_to_ics":
                    inbound_attempts_not_reachable += 1
                skipped_noncommunication += 1
                continue

            finding_type = "direct_ics_internet"
            if direction == "internet_to_ics" and _is_admin_flow(row, admin_ports, admin_services):
                if require_established_admin and not _established_or_udp(row):
                    inbound_attempts_not_reachable += 1
                    continue
                finding_type = "external_admin_to_ics"

            key = (finding_type, ics_ip)
            groups[key].append(row)
            group_meta[key] = {
                "ics_ip": ics_ip,
                "ics_role": ics_identity.role,
                "ics_name": ics_identity.name,
                "classification_source": ics_identity.source,
                "direction": direction,
            }

        findings = [
            _finding(
                finding_type=finding_type,
                rows=rows,
                identity=group_meta[(finding_type, ics_ip)],
                admin_ports=admin_ports,
                admin_services=admin_services,
            )
            for (finding_type, ics_ip), rows in sorted(groups.items())
        ]

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "internet_exposed_ics_findings": len(findings),
                "direct_ics_internet_flows": sum(
                    len(rows) for (kind, _), rows in groups.items() if kind == "direct_ics_internet"
                ),
                "external_admin_flows": sum(
                    len(rows) for (kind, _), rows in groups.items() if kind == "external_admin_to_ics"
                ),
                "ics_assets_with_findings": len({meta["ics_ip"] for meta in group_meta.values()}),
                "skipped_allowlisted": skipped_allowlisted,
                "skipped_unclassified": skipped_unclassified,
                "skipped_noncommunication": skipped_noncommunication,
                "inbound_attempts_not_counted_as_reachable": inbound_attempts_not_reachable,
            },
            evidence={
                "inspected_logs": ["conn"],
                "segments_loaded": len(segments),
                "asset_inventory_records": len(context.metadata.get("asset_inventory", []) or []),
                "classification_available": True,
                "admin_ports": sorted(admin_ports),
                "admin_services": sorted(admin_services),
                "policy": policy,
                "notes": [
                    "A direct exposure finding requires a configured/classified ICS endpoint and a globally routable peer; private addressing alone is not treated as proof of ICS identity.",
                    "Internet-originated administrative access is elevated when the public peer reaches a configured ICS endpoint on a management service/port and the flow shows communication rather than only an unanswered TCP SYN.",
                    "If a configured DMZ host terminates the Internet-facing connection, that DMZ endpoint is not treated as the ICS device. Zeek conn.log cannot prove the physical routed path when middleboxes preserve the original endpoints.",
                    "An observed public IP peer does not by itself prove that the ICS asset is generally reachable from the Internet; NAT, firewall policy, VPNs, proxies, and capture placement must be considered.",
                ],
            },
            warnings=[],
        )


def _finding(
    *,
    finding_type: str,
    rows: list[dict[str, Any]],
    identity: dict[str, Any],
    admin_ports: set[int],
    admin_services: set[str],
) -> Finding:
    devices: set[str] = set()
    services: set[str] = set()
    ports: set[int] = set()
    external_peers: set[str] = set()
    directions: set[str] = set()
    connection_pairs: list[dict[str, Any]] = []
    seen_pairs: set[tuple[str, str, int | None, str]] = set()
    timestamps: list[Any] = []

    ics_ip = identity["ics_ip"]
    for row in rows:
        source = _ip(_first(row, "source_ip", "id.orig_h")) or ""
        destination = _ip(_first(row, "destination_ip", "id.resp_h")) or ""
        protocol = _text(_first(row, "protocol", "proto")).lower()
        port = _as_int(_first(row, "destination_port", "id.resp_p"))
        service_tokens = _service_tokens(row.get("service"))
        devices.update(value for value in (source, destination) if value)
        services.update(service_tokens)
        if port is not None:
            ports.add(port)
        external = destination if source == ics_ip else source
        if _is_public(external):
            external_peers.add(external)
        directions.add("ics_to_internet" if source == ics_ip else "internet_to_ics")
        ts = _first(row, "timestamp", "ts")
        if ts not in (None, ""):
            timestamps.append(ts)
        pair = (source, destination, port, protocol)
        if pair not in seen_pairs and len(connection_pairs) < MAX_EVIDENCE_ROWS:
            seen_pairs.add(pair)
            connection_pairs.append(
                {"source": source, "destination": destination, "port": port, "protocol": protocol}
            )

    classification_source = identity["classification_source"]
    confidence = "high" if classification_source in {"policy", "asset_inventory"} else "medium"

    if finding_type == "external_admin_to_ics":
        title = "Internet-originated administrative access to ICS asset observed"
        severity = "high"
        summary = (
            f"Observed {len(rows)} Internet-originated management flow(s) to ICS asset {ics_ip} "
            f"({identity['ics_role'] or 'ICS/OT'}). The traffic matched configured administrative "
            "services/ports and showed communication beyond an unanswered connection attempt. "
            "This is direct endpoint evidence, not proof that the service is universally reachable from the Internet."
        )
        tags = ["ics", "ot", "internet-exposure", "external-admin", "remote-management"]
    else:
        inbound = "internet_to_ics" in directions
        title = "ICS asset communicating directly with Internet-routable peer"
        severity = "high" if inbound else "medium"
        summary = (
            f"Observed {len(rows)} direct flow(s) between ICS asset {ics_ip} "
            f"({identity['ics_role'] or 'ICS/OT'}) and {len(external_peers)} globally routable peer(s). "
            "The ICS asset and public peer are the observed connection endpoints; capture data does not prove the physical routed path or absence of transparent middleboxes."
        )
        tags = ["ics", "ot", "internet-exposure", "direct-internet"]

    return Finding(
        title=title,
        severity=severity,
        summary=summary,
        confidence=confidence,
        detection_basis="derived",
        devices=sorted(devices),
        services=sorted(services),
        ports=sorted(ports),
        connection_pairs=connection_pairs,
        flows=rows[:MAX_EVIDENCE_ROWS],
        timestamps=timestamps[:MAX_EVIDENCE_ROWS],
        tags=tags,
        metadata={
            "finding_type": finding_type,
            "ics_ip": ics_ip,
            "ics_name": identity["ics_name"],
            "ics_role": identity["ics_role"],
            "classification_source": classification_source,
            "external_peers": sorted(external_peers),
            "directions": sorted(directions),
            "flow_count": len(rows),
            "admin_ports": sorted(admin_ports),
            "admin_services": sorted(admin_services),
            "evidence_truncated": len(rows) > MAX_EVIDENCE_ROWS,
        },
    )


def _policy(metadata: dict[str, Any]) -> dict[str, Any]:
    raw = metadata.get("internet_exposed_ics_policy", {}) if isinstance(metadata, dict) else {}
    return raw if isinstance(raw, dict) else {}


def _load_segments(metadata: dict[str, Any]) -> list[_Segment]:
    raw = metadata.get("segments") if isinstance(metadata, dict) else None
    if not isinstance(raw, list):
        return []
    result: list[_Segment] = []
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
        result.append(
            _Segment(
                name=_text(item.get("name")) or str(network),
                role=_text(item.get("role") or item.get("type") or item.get("zone")),
                network=network,
            )
        )
    return result


def _load_inventory_identities(metadata: dict[str, Any]) -> dict[str, _AssetIdentity]:
    raw = metadata.get("asset_inventory") if isinstance(metadata, dict) else None
    if not isinstance(raw, list):
        return {}
    identities: dict[str, _AssetIdentity] = {}
    for item in raw:
        if not isinstance(item, dict):
            continue
        role_text = " ".join(
            _text(item.get(key)) for key in ("role", "type", "asset_type", "category", "function", "class", "name")
            if _text(item.get(key))
        )
        if not _contains_role(role_text, ICS_ROLE_TOKENS) or _contains_role(role_text, DMZ_ROLE_TOKENS):
            continue
        name = _text(item.get("name") or item.get("hostname") or item.get("asset"))
        role = _text(item.get("role") or item.get("type") or item.get("asset_type")) or role_text
        for value in _values(item, "ips", "ip_addresses", "ip", "address", "addresses"):
            normalized = _ip(value)
            if normalized:
                identities[normalized] = _AssetIdentity(normalized, role, "asset_inventory", name)
    return identities


def _ics_identity(
    ip: str,
    segments: list[_Segment],
    inventory: dict[str, _AssetIdentity],
    explicit_ics_hosts: set[str],
    explicit_dmz_hosts: set[str],
) -> _AssetIdentity | None:
    if ip in explicit_dmz_hosts:
        return None
    if ip in explicit_ics_hosts:
        return _AssetIdentity(ip, "ICS/OT", "policy", ip)
    if ip in inventory:
        return inventory[ip]
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for segment in segments:
        if address not in segment.network:
            continue
        descriptor = f"{segment.name} {segment.role}"
        if _contains_role(descriptor, DMZ_ROLE_TOKENS):
            return None
        if _contains_role(descriptor, ICS_ROLE_TOKENS):
            return _AssetIdentity(ip, segment.role or segment.name, "segment", segment.name)
    return None


def _contains_role(text: str, tokens: set[str]) -> bool:
    normalized = re.sub(r"[_/]+", " ", _text(text).lower())
    words = set(re.findall(r"[a-z0-9]+", normalized))
    for token in tokens:
        token_norm = token.lower()
        if " " in token_norm or "-" in token_norm:
            if token_norm.replace("-", " ") in normalized.replace("-", " "):
                return True
        elif token_norm in words:
            return True
    return False


def _is_admin_flow(row: dict[str, Any], admin_ports: set[int], admin_services: set[str]) -> bool:
    port = _as_int(_first(row, "destination_port", "id.resp_p"))
    services = _service_tokens(row.get("service"))
    return (port in admin_ports if port is not None else False) or bool(services & admin_services)


def _observed_communication(row: dict[str, Any]) -> bool:
    protocol = _text(_first(row, "protocol", "proto")).lower()
    if protocol == "udp":
        return True
    if protocol != "tcp":
        return True
    if _established_or_udp(row):
        return True
    return (_as_int(row.get("orig_bytes")) or 0) > 0 or (_as_int(row.get("resp_bytes")) or 0) > 0


def _established_or_udp(row: dict[str, Any]) -> bool:
    protocol = _text(_first(row, "protocol", "proto")).lower()
    if protocol == "udp":
        return True
    state = _text(row.get("conn_state")).upper()
    return state in ESTABLISHED_TCP_STATES


def _is_public(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.is_global and not address.is_multicast


def _networks(value: Any) -> list[ipaddress._BaseNetwork]:
    values = value if isinstance(value, (list, tuple, set)) else [value]
    result: list[ipaddress._BaseNetwork] = []
    for item in values:
        text = _text(item)
        if not text:
            continue
        try:
            result.append(ipaddress.ip_network(text, strict=False))
        except ValueError:
            try:
                address = ipaddress.ip_address(text)
            except ValueError:
                continue
            result.append(ipaddress.ip_network(f"{address}/{address.max_prefixlen}", strict=False))
    return result


def _ip_in_networks(value: str, networks: list[ipaddress._BaseNetwork]) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(address.version == network.version and address in network for network in networks)


def _pair_set(value: Any) -> set[tuple[str, str]]:
    result: set[tuple[str, str]] = set()
    if not isinstance(value, list):
        return result
    for item in value:
        if not isinstance(item, dict):
            continue
        source = _ip(item.get("source"))
        destination = _ip(item.get("destination"))
        if source and destination:
            result.add((source, destination))
    return result


def _values(item: dict[str, Any], *keys: str) -> list[Any]:
    values: list[Any] = []
    for key in keys:
        value = item.get(key)
        if isinstance(value, (list, tuple, set)):
            values.extend(value)
        elif value not in (None, ""):
            values.append(value)
    return values


def _string_set(value: Any) -> set[str]:
    if not isinstance(value, (list, tuple, set)):
        return set()
    return {_text(item).lower() for item in value if _text(item)}


def _int_set(value: Any, default: set[int]) -> set[int]:
    if not isinstance(value, (list, tuple, set)):
        return set(default)
    result = {_as_int(item) for item in value}
    return {item for item in result if item is not None}


def _service_tokens(value: Any) -> set[str]:
    text = _text(value).lower()
    if not text or text == "-":
        return set()
    return {token for token in re.split(r"[\s,;/|]+", text) if token and token != "-"}


def _bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        if value.strip().lower() in {"true", "t", "1", "yes", "y"}:
            return True
        if value.strip().lower() in {"false", "f", "0", "no", "n"}:
            return False
    return default


def _ip(value: Any) -> str | None:
    try:
        return str(ipaddress.ip_address(_text(value)))
    except ValueError:
        return None


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _first(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in row and row[key] not in (None, ""):
            return row[key]
    return None
