from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import ipaddress
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata


MAX_EVIDENCE_ROWS = 50
ESTABLISHED_TCP_STATES = {"SF", "S1", "S2", "S3", "RSTO", "RSTR", "RSTOS0", "RSTRH"}

# Conservative defaults: server/listener ports, not auxiliary discovery/browser ports.
DEFAULT_DATABASE_PORTS: dict[str, set[int]] = {
    "mysql": {3306, 33060},
    "mssql": {1433},
    "postgresql": {5432},
    "mongodb": {27017, 27018, 27019},
    "redis": {6379},
    "memcached": {11211},
    "elasticsearch": {9200, 9300},
}

SERVICE_ALIASES: dict[str, str] = {
    "mysql": "mysql",
    "mysqlx": "mysql",
    "mssql": "mssql",
    "ms-sql-s": "mssql",
    "sqlserver": "mssql",
    "postgres": "postgresql",
    "postgresql": "postgresql",
    "pgsql": "postgresql",
    "mongodb": "mongodb",
    "mongo": "mongodb",
    "redis": "redis",
    "memcached": "memcached",
    "memcache": "memcached",
    "elasticsearch": "elasticsearch",
    "elastic": "elasticsearch",
}


@dataclass(frozen=True, slots=True)
class _Segment:
    name: str
    role: str
    network: ipaddress._BaseNetwork


class DatabaseServiceExposedModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="database_service_exposed",
        name="Database Service Exposed",
        description=(
            "Identifies database services reachable across configured network-segment boundaries or "
            "from public Internet addresses, including MySQL, SQL Server, PostgreSQL, MongoDB, Redis, "
            "Memcached, and Elasticsearch."
        ),
        category="security_analysis",
        required_logs=("conn",),
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        policy = _policy(context.metadata)
        segments = _load_segments(context.metadata)
        database_ports = _database_ports(policy.get("database_ports"))
        allowed_hosts = _string_set(policy.get("allowed_hosts"))
        allowed_pairs = _pair_set(policy.get("allowed_pairs"))
        allowed_cross_segment_pairs = _segment_pair_set(policy.get("allowed_segment_pairs"))
        allowed_public_networks = _networks(policy.get("allowed_public_sources", []))
        ignored_databases = {_normalize_database_name(v) for v in _string_set(policy.get("ignored_databases"))}
        ignored_databases.discard("")
        require_established_external = _bool(policy.get("require_established_external"), True)
        report_cross_segment = _bool(policy.get("report_cross_segment"), True)
        report_external = _bool(policy.get("report_external"), True)

        groups: dict[tuple[str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
        group_meta: dict[tuple[str, str, str, str], dict[str, Any]] = {}

        database_candidates = 0
        cross_segment_flows = 0
        external_flows = 0
        skipped_allowlisted = 0
        skipped_same_segment = 0
        skipped_no_segment_context = 0
        external_attempts_not_reachable = 0

        for row in context.connections:
            source = _ip(_first(row, "source_ip", "id.orig_h"))
            destination = _ip(_first(row, "destination_ip", "id.resp_h"))
            if not source or not destination:
                continue

            database, basis = _database_identity(row, database_ports)
            if not database or database in ignored_databases:
                continue
            database_candidates += 1

            if source in allowed_hosts or destination in allowed_hosts or (source, destination) in allowed_pairs:
                skipped_allowlisted += 1
                continue

            src_public = _is_public(source)
            dst_public = _is_public(destination)

            # The responder is treated as the database server because Zeek conn.log's
            # id.orig_h is the connection initiator and id.resp_h is the responder.
            server = destination
            client = source

            if report_external and src_public and not dst_public:
                if _ip_in_networks(source, allowed_public_networks):
                    skipped_allowlisted += 1
                    continue
                if require_established_external and not _observed_reachable(row):
                    external_attempts_not_reachable += 1
                    continue
                key = ("external_database_access", database, server, client)
                groups[key].append(row)
                group_meta[key] = {
                    "finding_type": "external_database_access",
                    "database": database,
                    "server": server,
                    "client": client,
                    "source_segment": _segment_name(source, segments),
                    "destination_segment": _segment_name(destination, segments),
                    "basis": basis,
                }
                external_flows += 1
                continue

            if not report_cross_segment or src_public or dst_public:
                continue

            src_segment = _segment_for(source, segments)
            dst_segment = _segment_for(destination, segments)
            if not src_segment or not dst_segment:
                skipped_no_segment_context += 1
                continue
            if src_segment.name == dst_segment.name:
                skipped_same_segment += 1
                continue
            if _segment_pair_allowed(src_segment.name, dst_segment.name, allowed_cross_segment_pairs):
                skipped_allowlisted += 1
                continue

            key = ("cross_segment_database_access", database, server, src_segment.name)
            groups[key].append(row)
            group_meta[key] = {
                "finding_type": "cross_segment_database_access",
                "database": database,
                "server": server,
                "client": client,
                "source_segment": src_segment.name,
                "source_role": src_segment.role,
                "destination_segment": dst_segment.name,
                "destination_role": dst_segment.role,
                "basis": basis,
            }
            cross_segment_flows += 1

        findings = [
            _finding(rows=rows, meta=group_meta[key], database_ports=database_ports)
            for key, rows in sorted(groups.items())
        ]

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "database_candidates": database_candidates,
                "database_exposure_findings": len(findings),
                "cross_segment_database_flows": cross_segment_flows,
                "external_database_flows": external_flows,
                "external_attempts_not_counted_as_reachable": external_attempts_not_reachable,
                "skipped_allowlisted": skipped_allowlisted,
                "skipped_same_segment": skipped_same_segment,
                "skipped_no_segment_context": skipped_no_segment_context,
            },
            evidence={
                "inspected_logs": ["conn"] if context.connections else [],
                "segments_loaded": len(segments),
                "database_ports": {name: sorted(ports) for name, ports in sorted(database_ports.items())},
                "policy": policy,
                "notes": [
                    "The conn.log responder is treated as the database server; this module reports observed reachability/communication, not a vulnerability scan result.",
                    "Cross-segment detection requires configured segment metadata and does not infer a boundary from private addressing alone.",
                    "Internet-originated TCP probes that do not show an established/replied connection are not treated as proof that the database service is reachable when require_established_external is enabled.",
                    "Port evidence is service-consistent rather than payload confirmation. An explicit database service label, when available, raises confidence.",
                    "SQL Server Browser UDP/1434 is intentionally excluded from the default server-port set because it is auxiliary discovery traffic rather than the database listener itself.",
                ],
            },
            warnings=[],
        )


def _finding(*, rows: list[dict[str, Any]], meta: dict[str, Any], database_ports: dict[str, set[int]]) -> Finding:
    finding_type = meta["finding_type"]
    database = meta["database"]
    server = meta["server"]
    clients: set[str] = set()
    ports: set[int] = set()
    services: set[str] = set()
    devices: set[str] = {server}
    timestamps: list[Any] = []
    connection_pairs: list[dict[str, Any]] = []
    seen_pairs: set[tuple[str, str, int | None, str]] = set()
    explicit_service = False

    for row in rows:
        source = _ip(_first(row, "source_ip", "id.orig_h")) or ""
        destination = _ip(_first(row, "destination_ip", "id.resp_h")) or ""
        port = _as_int(_first(row, "destination_port", "id.resp_p"))
        protocol = _text(_first(row, "protocol", "proto")).lower()
        row_services = _service_tokens(row.get("service"))
        services.update(row_services)
        explicit_service = explicit_service or any(_normalize_database_name(token) == database for token in row_services)
        if source:
            clients.add(source)
            devices.add(source)
        if destination:
            devices.add(destination)
        if port is not None:
            ports.add(port)
        timestamp = _first(row, "timestamp", "ts")
        if timestamp not in (None, ""):
            timestamps.append(timestamp)
        pair_key = (source, destination, port, protocol)
        if pair_key not in seen_pairs and len(connection_pairs) < MAX_EVIDENCE_ROWS:
            seen_pairs.add(pair_key)
            connection_pairs.append({
                "source": source,
                "destination": destination,
                "destination_port": port,
                "protocol": protocol,
                "service": sorted(row_services),
            })

    if explicit_service:
        confidence = "high"
        detection_basis = "zeek_service"
    else:
        confidence = "medium"
        detection_basis = "port"

    if finding_type == "external_database_access":
        severity = "high"
        title = f"{_display_database(database)} database service reachable from Internet"
        summary = (
            f"Observed {len(rows)} connection(s) from public Internet address(es) to {_display_database(database)} "
            f"service on {server}. Direct Internet reachability of database listeners should be validated against "
            "firewall, DMZ, VPN, and administrative-access policy."
        )
        tags = ["database", "external-exposure", database]
    else:
        severity = "medium"
        title = f"{_display_database(database)} database service reachable across network segments"
        summary = (
            f"Observed {len(rows)} connection(s) from segment {meta.get('source_segment') or 'unknown'} to "
            f"{_display_database(database)} service on {server} in segment {meta.get('destination_segment') or 'unknown'}. "
            "Validate that the cross-segment database path is expected and appropriately restricted."
        )
        tags = ["database", "cross-segment", database]

    return Finding(
        title=title,
        severity=severity,
        summary=summary,
        confidence=confidence,
        detection_basis=detection_basis,
        devices=sorted(devices),
        services=sorted(services) or [database],
        ports=sorted(ports or database_ports.get(database, set())),
        connection_pairs=connection_pairs,
        flows=rows[:MAX_EVIDENCE_ROWS],
        timestamps=timestamps[:MAX_EVIDENCE_ROWS],
        tags=tags,
        metadata={
            **meta,
            "flow_count": len(rows),
            "clients": sorted(clients),
            "ports": sorted(ports),
            "explicit_service_label": explicit_service,
        },
    )


def _database_identity(row: dict[str, Any], database_ports: dict[str, set[int]]) -> tuple[str, str]:
    for token in _service_tokens(row.get("service")):
        database = _normalize_database_name(token)
        if database:
            return database, "zeek_service"

    protocol = _text(_first(row, "protocol", "proto")).lower()
    if protocol not in {"tcp", "udp"}:
        return "", ""
    port = _as_int(_first(row, "destination_port", "id.resp_p"))
    if port is None:
        return "", ""
    for database, ports in database_ports.items():
        if port in ports:
            return database, "port"
    return "", ""


def _database_ports(value: Any) -> dict[str, set[int]]:
    result = {name: set(ports) for name, ports in DEFAULT_DATABASE_PORTS.items()}
    if not isinstance(value, dict):
        return result
    for raw_name, raw_ports in value.items():
        name = _normalize_database_name(raw_name) or _text(raw_name).lower().strip()
        if not name:
            continue
        result[name] = _int_set(raw_ports)
    return result


def _normalize_database_name(value: Any) -> str:
    token = _text(value).lower().strip().replace("_", "-")
    return SERVICE_ALIASES.get(token, "")


def _display_database(name: str) -> str:
    return {
        "mysql": "MySQL",
        "mssql": "Microsoft SQL Server",
        "postgresql": "PostgreSQL",
        "mongodb": "MongoDB",
        "redis": "Redis",
        "memcached": "Memcached",
        "elasticsearch": "Elasticsearch",
    }.get(name, name)


def _policy(metadata: dict[str, Any]) -> dict[str, Any]:
    value = metadata.get("database_exposure_policy", {})
    return value if isinstance(value, dict) else {}


def _load_segments(metadata: dict[str, Any]) -> list[_Segment]:
    segments: list[_Segment] = []
    raw_segments = metadata.get("segments", [])
    if not isinstance(raw_segments, list):
        return segments
    for item in raw_segments:
        if not isinstance(item, dict):
            continue
        cidr = _text(item.get("cidr") or item.get("network")).strip()
        if not cidr:
            continue
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        segments.append(_Segment(
            name=_text(item.get("name") or cidr).strip() or cidr,
            role=_text(item.get("role")).strip(),
            network=network,
        ))
    return segments


def _segment_for(address: str, segments: list[_Segment]) -> _Segment | None:
    try:
        ip_obj = ipaddress.ip_address(address)
    except ValueError:
        return None
    matches = [segment for segment in segments if ip_obj.version == segment.network.version and ip_obj in segment.network]
    if not matches:
        return None
    return max(matches, key=lambda segment: segment.network.prefixlen)


def _segment_name(address: str, segments: list[_Segment]) -> str:
    segment = _segment_for(address, segments)
    return segment.name if segment else ""


def _is_public(address: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(address)
    except ValueError:
        return False
    return ip_obj.is_global


def _observed_reachable(row: dict[str, Any]) -> bool:
    protocol = _text(_first(row, "protocol", "proto")).lower()
    if protocol != "tcp":
        # UDP has no handshake. Require evidence of response bytes/packets when available;
        # otherwise the Zeek flow itself is the best available observation.
        resp_bytes = _as_int(_first(row, "response_bytes", "resp_bytes"))
        resp_pkts = _as_int(_first(row, "response_packets", "resp_pkts"))
        if resp_bytes is not None or resp_pkts is not None:
            return (resp_bytes or 0) > 0 or (resp_pkts or 0) > 0
        return True
    state = _text(_first(row, "connection_state", "conn_state")).upper()
    if state:
        return state in ESTABLISHED_TCP_STATES
    resp_bytes = _as_int(_first(row, "response_bytes", "resp_bytes"))
    resp_pkts = _as_int(_first(row, "response_packets", "resp_pkts"))
    return (resp_bytes or 0) > 0 or (resp_pkts or 0) > 0


def _segment_pair_allowed(source: str, destination: str, pairs: set[tuple[str, str]]) -> bool:
    return (source, destination) in pairs or (destination, source) in pairs


def _pair_set(value: Any) -> set[tuple[str, str]]:
    result: set[tuple[str, str]] = set()
    if not isinstance(value, list):
        return result
    for item in value:
        if isinstance(item, dict):
            source = _text(item.get("source")).strip()
            destination = _text(item.get("destination")).strip()
            if source and destination:
                result.add((source, destination))
        elif isinstance(item, (list, tuple)) and len(item) >= 2:
            source, destination = _text(item[0]).strip(), _text(item[1]).strip()
            if source and destination:
                result.add((source, destination))
    return result


def _segment_pair_set(value: Any) -> set[tuple[str, str]]:
    return _pair_set(value)


def _networks(value: Any) -> list[ipaddress._BaseNetwork]:
    values = value if isinstance(value, list) else [value]
    networks: list[ipaddress._BaseNetwork] = []
    for item in values:
        text = _text(item).strip()
        if not text:
            continue
        try:
            networks.append(ipaddress.ip_network(text, strict=False))
        except ValueError:
            try:
                ip_obj = ipaddress.ip_address(text)
            except ValueError:
                continue
            networks.append(ipaddress.ip_network(f"{ip_obj}/{ip_obj.max_prefixlen}", strict=False))
    return networks


def _ip_in_networks(address: str, networks: list[ipaddress._BaseNetwork]) -> bool:
    try:
        ip_obj = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(ip_obj.version == network.version and ip_obj in network for network in networks)


def _service_tokens(value: Any) -> set[str]:
    if isinstance(value, (list, tuple, set)):
        raw = [str(item) for item in value]
    else:
        raw = _text(value).replace(",", ";").split(";")
    return {token.strip().lower() for token in raw if token.strip() and token.strip() != "-"}


def _string_set(value: Any) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, (list, tuple, set)):
        return {_text(item).strip() for item in value if _text(item).strip()}
    text = _text(value).strip()
    return {text} if text else set()


def _int_set(value: Any) -> set[int]:
    values = value if isinstance(value, (list, tuple, set)) else [value]
    result: set[int] = set()
    for item in values:
        number = _as_int(item)
        if number is not None and 0 <= number <= 65535:
            result.add(number)
    return result


def _bool(value: Any, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes", "1", "on"}:
            return True
        if lowered in {"false", "no", "0", "off"}:
            return False
    return bool(value)


def _ip(value: Any) -> str:
    text = _text(value).strip()
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return ""


def _as_int(value: Any) -> int | None:
    if value in (None, "", "-"):
        return None
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def _first(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in row and row[key] not in (None, "", "-"):
            return row[key]
    return None


def _text(value: Any) -> str:
    return "" if value is None else str(value)
