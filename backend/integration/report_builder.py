"""Build the canonical eleVADR v2 JSON report from detector analysis output.

This is isolated reference code for eventual backend incorporation.  The generated
object intentionally matches the same report shape accepted by the existing
frontend JSON loader, so PCAP and JSON workflows converge immediately after
analysis.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import json
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Any, Iterable, Mapping
from uuid import uuid4




def _stable_json_value(value: Any) -> Any:
    """Normalize mapping key order without changing semantically ordered lists."""
    if isinstance(value, Mapping):
        return {str(key): _stable_json_value(value[key]) for key in sorted(value, key=lambda item: str(item))}
    if isinstance(value, list):
        return [_stable_json_value(item) for item in value]
    if isinstance(value, tuple):
        return [_stable_json_value(item) for item in value]
    return value


def _stable_json_key(value: Any) -> str:
    """Return a deterministic comparison key for JSON-like values."""
    return json.dumps(_stable_json_value(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _connection_sort_key(row: Mapping[str, Any]) -> tuple[Any, ...]:
    timestamp = _float(row.get("timestamp"))
    return (
        timestamp if timestamp is not None else float("inf"),
        _text(row.get("uid")),
        _text(row.get("source_ip")),
        _int(row.get("source_port")),
        _text(row.get("destination_ip")),
        _int(row.get("destination_port")),
        _text(row.get("protocol")),
        _text(row.get("service")),
        _stable_json_key(row),
    )


def _stable_module_results(rows: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    stable: list[dict[str, Any]] = []
    for raw in rows:
        row = dict(raw)
        findings = row.get("findings")
        if isinstance(findings, list):
            row["findings"] = sorted((dict(item) if isinstance(item, Mapping) else item for item in findings), key=_stable_json_key)
        stable.append(row)
    return sorted(stable, key=lambda row: (_text(row.get("module_id")), _stable_json_key(row)))

def _text(value: Any, default: str = "") -> str:
    return str(value) if value not in (None, "") else default


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _public(ip: str) -> bool:
    try:
        obj = ip_address(ip)
        return not (obj.is_private or obj.is_loopback or obj.is_link_local or obj.is_multicast)
    except ValueError:
        return False


def _service_name(row: Mapping[str, Any]) -> str:
    service = _text(row.get("service"))
    if service and service != "-":
        return service
    port = _int(row.get("destination_port"))
    proto = _text(row.get("protocol"), "tcp")
    return f"{proto}/{port}" if port else proto or "unknown"


def _asset_index(profile: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for raw in profile.get("assets", []) if isinstance(profile.get("assets"), list) else []:
        if not isinstance(raw, Mapping):
            continue
        ip = _text(raw.get("ip"))
        if ip:
            result[ip] = dict(raw)
    return result


def _segment_role_index(profile: Mapping[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw in profile.get("segments", []) if isinstance(profile.get("segments"), list) else []:
        if not isinstance(raw, Mapping):
            continue
        name = _text(raw.get("name"))
        role = _text(raw.get("role")).lower()
        if name and role:
            result[name] = role
    return result


def _is_ot_asset(asset: Mapping[str, Any] | None, segment_roles: Mapping[str, str]) -> bool:
    if not asset:
        return False
    # Segment policy is authoritative for report-zone classification when present.
    # Asset labels such as "engineering workstation" are descriptive and should not
    # override an explicitly IT-classified segment.
    segment_name = _text(asset.get("segment"))
    segment_role = _text(segment_roles.get(segment_name)).lower() if segment_name else ""
    if segment_role:
        if segment_role in {"ot", "ics", "control", "control system"} or any(token in segment_role for token in ("industrial", "control", "scada")):
            return True
        if segment_role in {"it", "enterprise", "non-ot", "non ot"} or any(token in segment_role for token in ("enterprise", "corporate", "office", "business")):
            return False

    role = _text(asset.get("role")).lower()
    asset_type = _text(asset.get("assetType")).lower()
    return (
        role == "ot"
        or role.startswith("ot ")
        or any(token in role for token in ("plc", "rtu", "scada", "controller", "control system"))
        or any(token in asset_type for token in ("plc", "hmi", "rtu", "controller", "ics", "ot"))
    )


def _device(ip: str, asset: Mapping[str, Any] | None, incoming: Iterable[str], outgoing: Iterable[str], segment_roles: Mapping[str, str]) -> dict[str, Any]:
    return {
        "manufacturer": None,
        "mac": ((asset or {}).get("macAddresses") or [None])[0],
        "ip_addresses": [ip],
        "ipv4_ips": [ip] if ":" not in ip else [],
        "ipv6_ips": [ip] if ":" in ip else [],
        "subnets": [asset.get("segment")] if asset and asset.get("segment") else [],
        "ipv4_subnets": [asset.get("segment")] if asset and asset.get("segment") and ":" not in ip else [],
        "ipv6_subnets": [asset.get("segment")] if asset and asset.get("segment") and ":" in ip else [],
        "incoming_services": sorted(set(incoming)),
        "sent_services": sorted(set(outgoing)),
        "is_ot": _is_ot_asset(asset, segment_roles),
        "is_edge": _public(ip),
    }


def build_elevadr_report(
    *,
    source_filename: str,
    profile: Mapping[str, Any],
    context: Any,
    module_results: list[dict[str, Any]],
    module_errors: list[dict[str, Any]] | None = None,
    zeek_log_types: Mapping[str, int] | None = None,
    zeek_runtime: str | None = None,
    detector_modules_requested: int | None = None,
) -> dict[str, Any]:
    connections = sorted(list(getattr(context, "connections", []) or []), key=_connection_sort_key)
    module_results = _stable_module_results(module_results)
    module_errors = sorted((dict(row) for row in (module_errors or [])), key=lambda row: (_text(row.get("moduleId")), _text(row.get("code")), _text(row.get("message")), _stable_json_key(row)))
    asset_by_ip = _asset_index(profile)
    segment_roles = _segment_role_index(profile)

    service_counts: Counter[tuple[str, int]] = Counter()
    state_counts: Counter[str] = Counter()
    host_incoming: defaultdict[str, list[str]] = defaultdict(list)
    host_outgoing: defaultdict[str, list[str]] = defaultdict(list)
    hosts: set[str] = set(asset_by_ip)
    report_connections: list[dict[str, Any]] = []
    outbound_counts: Counter[tuple[str, str, int, str]] = Counter()
    cross_counts: Counter[tuple[str, str, int, str]] = Counter()

    for row in connections:
        src = _text(row.get("source_ip"))
        dst = _text(row.get("destination_ip"))
        sport = _int(row.get("source_port")) or None
        dport = _int(row.get("destination_port")) or None
        service = _service_name(row)
        proto = _text(row.get("protocol")) or None
        state = _text(row.get("zeek_state")) or None
        if src:
            hosts.add(src)
            host_outgoing[src].append(service)
        if dst:
            hosts.add(dst)
            host_incoming[dst].append(service)
        if dport:
            service_counts[(service, dport)] += 1
        if state:
            state_counts[state] += 1
        success = state in {"SF", "S1", "S2", "S3", "OTH"}
        report_connections.append({
            "src_endpoint.ip": src or None,
            "src_endpoint.port": sport,
            "dst_endpoint.ip": dst or None,
            "dst_endpoint.port": dport,
            "service.name": service,
            "connection_info.protocol_name": proto,
            "connection_info.direction_name": "outbound" if src and dst and not _public(src) and _public(dst) else None,
            "duration": _float(row.get("duration")),
            "orig_bytes": _int(row.get("source_bytes")) if row.get("source_bytes") is not None else None,
            "resp_bytes": _int(row.get("destination_bytes")) if row.get("destination_bytes") is not None else None,
            "state": state,
            "history": row.get("history"),
            "success": success,
        })
        if src and dst and not _public(src) and _public(dst):
            outbound_counts[(src, dst, dport or 0, service)] += 1
        src_asset = asset_by_ip.get(src)
        dst_asset = asset_by_ip.get(dst)
        if src and dst and (_is_ot_asset(src_asset, segment_roles) or _is_ot_asset(dst_asset, segment_roles)):
            src_seg = _text((src_asset or {}).get("segment"))
            dst_seg = _text((dst_asset or {}).get("segment"))
            if src_seg and dst_seg and src_seg != dst_seg:
                cross_counts[(src, dst, dport or 0, service)] += 1

    module_findings: list[dict[str, Any]] = []
    risk_services: defaultdict[str, set[str]] = defaultdict(set)
    for module_result in module_results:
        module_id = _text(module_result.get("module_id"), "unknown")
        findings = module_result.get("findings", [])
        if not isinstance(findings, list):
            continue
        for raw in findings:
            if not isinstance(raw, Mapping):
                continue
            finding = dict(raw)
            finding["module_id"] = module_id
            module_findings.append(finding)
            severity = _text(finding.get("severity"), "informational")
            services = finding.get("services", [])
            if isinstance(services, list):
                for service in services:
                    if service:
                        risk_services[severity].add(str(service))

    known_services = [
        {"name": name, "port": port, "count": count}
        for (name, port), count in sorted(service_counts.items(), key=lambda item: (-item[1], item[0][0]))
    ]
    risky_service_names = {service for values in risk_services.values() for service in values}
    ot_service_names = {"modbus", "dnp3", "s7comm", "enip", "bacnet", "mms", "iec61850"}
    observed_service_names = {name for name, _port in service_counts}

    ot_devices: list[dict[str, Any]] = []
    it_devices: list[dict[str, Any]] = []
    edge_devices: list[dict[str, Any]] = []
    for ip in sorted(hosts):
        asset = asset_by_ip.get(ip)
        device = _device(ip, asset, host_incoming[ip], host_outgoing[ip], segment_roles)
        if device["is_edge"]:
            edge_devices.append(device)
        elif device["is_ot"]:
            ot_devices.append(device)
        else:
            it_devices.append(device)

    cross_lines = [
        {"src_endpoint.ip": src, "dst_endpoint.ip": dst, "dst_endpoint.port": port, "service.name": service, "count": count}
        for (src, dst, port, service), count in sorted(cross_counts.items())
    ]
    suspicious = [
        {"src_endpoint.ip": src, "dst_endpoint.ip": dst, "dst_endpoint.port": port, "service.name": service, "count": count}
        for (src, dst, port, service), count in sorted(outbound_counts.items())
    ]

    successful = sum(1 for row in report_connections if row["success"])
    unsuccessful = len(report_connections) - successful
    report_id = f"elevadr-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid4().hex[:8]}"

    return {
        "report_version": "2.0.0",
        "report_id": report_id,
        "executive_summary": {
            "analysis_summary": f"Analyzed {source_filename} with {len(module_results)} detector modules and produced {len(module_findings)} detector finding(s).",
            "device_summary": f"Observed {len(hosts)} host(s), including {len(ot_devices)} OT-classified host(s).",
            "service_summary": f"Observed {len(observed_service_names)} distinct service name(s) across {len(connections)} connection record(s).",
        },
        "modules": {
            "service_panel": {
                "num_known_services": len(observed_service_names),
                "num_ot_services": len(observed_service_names & ot_service_names),
                "num_risky_services": len(risky_service_names),
                "num_unknown_services": sum(1 for name in observed_service_names if name.startswith(("tcp/", "udp/", "unknown"))),
            },
            "device_panel": {
                "hosts": len(hosts),
                "ot_hosts": len(ot_devices),
                "it_hosts": len(it_devices),
                "edge_hosts": len(edge_devices),
                "ot_cross_segment": len(cross_lines),
            },
            "service_risk_breakdown_panel": {
                "risk_category_counts": {key: len(risk_services[key]) for key in sorted(risk_services)},
                "risk_category_services": {key: sorted(risk_services[key]) for key in sorted(risk_services)},
            },
            "service_count_panel": {
                "service_count": sum(service_counts.values()),
                "service_connections_count": {"known_services": known_services, "unknown_services": {}},
            },
            "connection_success_panel": {
                "summary": {"successful_count": successful, "unsuccessful_count": unsuccessful, "by_state": {key: state_counts[key] for key in sorted(state_counts)}},
                "connections": report_connections,
            },
            "suspicious_outbound_connections_panel": suspicious,
            "ot_cross_segment_lines_panel": {
                "lines": cross_lines,
                "subnet_pair_counts": [],
                "dst_subnet_counts": [],
                "ot_device_counts": [],
            },
            "ot_devices": ot_devices,
            "it_devices": it_devices,
            "edge_devices": edge_devices,
            "ot_services": [
                {
                    "service.name": service,
                    "service.description": "Observed OT/ICS service",
                    "service.information_categories": "control",
                    "service.risk_categories": "detector_observed" if service in risky_service_names else "",
                }
                for service in sorted(observed_service_names & ot_service_names)
            ],
        },
        "arch_insights": {
            "detector_results": module_results,
            "detector_findings": module_findings,
            "detector_errors": module_errors,
            "analysis_provenance": {
                "source_type": "pcap",
                "source_filename": source_filename,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "detection_context_profile_id": profile.get("id", ""),
                "detection_context_profile_name": profile.get("name", ""),
                "detection_context_schema_version": profile.get("schemaVersion"),
                "modules_requested": list(profile.get("selectedModules", [])) if isinstance(profile.get("selectedModules"), list) else [],
                "detector_modules_requested": detector_modules_requested if detector_modules_requested is not None else len(module_results),
                "detector_modules_completed": len(module_results),
                "detector_modules_failed": len(module_errors or []),
                "zeek_runtime": zeek_runtime or "unknown",
                "zeek_log_types": {key: (zeek_log_types or {})[key] for key in sorted(zeek_log_types or {})},
            },
            "detection_context_snapshot": _stable_json_value(profile),
        },
    }
