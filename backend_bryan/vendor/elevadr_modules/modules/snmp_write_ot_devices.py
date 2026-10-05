from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import ipaddress
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata

MAX_EVIDENCE = 10
OT_ROLE_TOKENS = {"ot", "ics", "control", "scada", "industrial", "process", "plc", "hmi", "rtu", "dcs", "bas", "bms"}
MANAGED_ROLE_TOKENS = OT_ROLE_TOKENS | {"switch", "router", "firewall", "network", "controller", "historian", "engineering"}


@dataclass(slots=True)
class _Segment:
    name: str
    role: str
    network: ipaddress._BaseNetwork


@dataclass(slots=True)
class _Event:
    row: dict[str, Any]
    source: str
    destination: str
    version: str
    community: str
    set_count: int
    signal: str
    timestamp: Any


class SnmpWriteOtDevicesModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="snmp_write_ot_devices",
        name="SNMP Write / Set to OT Devices",
        description=(
            "Detects SNMP SET operations or use of explicitly configured writable SNMPv1/v2c communities "
            "against OT devices, controllers, or managed network infrastructure beyond ordinary read-only polling."
        ),
        category="security_analysis",
        required_logs=("snmp",),
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        policy = _policy(context.metadata)
        segments = _segments(context.metadata)
        inventory_roles = _inventory_roles(context.metadata)
        explicit_targets = _string_set(policy.get("target_hosts") or policy.get("managed_hosts"))
        writable_communities = _string_set(policy.get("writable_communities"))
        allowed_managers = _string_set(policy.get("allowed_managers"))
        allowed_pairs = _pair_set(policy.get("allowed_pairs"))
        report_writable = _as_bool(policy.get("report_writable_community_access"), True)
        min_sets = max(1, _as_int(policy.get("min_set_operations")) or 1)

        groups: dict[tuple[str, str, str], list[_Event]] = defaultdict(list)
        candidates = 0
        set_events = 0
        writable_access_events = 0
        skipped_non_target = 0
        skipped_allowed = 0
        skipped_read_only = 0

        for row in context.snmp:
            source = _text(_first(row, "source_ip", "id.orig_h", "src"))
            destination = _text(_first(row, "destination_ip", "id.resp_h", "dst"))
            if not source or not destination:
                continue
            if not _is_target(destination, segments, inventory_roles, explicit_targets):
                skipped_non_target += 1
                continue
            candidates += 1
            if source in allowed_managers or (source, destination) in allowed_pairs:
                skipped_allowed += 1
                continue

            version = _version(_first(row, "version", "snmp_version"))
            community = _text(_first(row, "community", "community_string"))
            set_count = _set_count(row)
            signal = ""
            if set_count >= min_sets:
                signal = "set_operation"
                set_events += 1
            elif report_writable and version in {"v1", "v2c"} and community and community in writable_communities:
                signal = "writable_community_access"
                writable_access_events += 1
            else:
                skipped_read_only += 1
                continue

            event = _Event(
                row=row,
                source=source,
                destination=destination,
                version=version,
                community=community,
                set_count=set_count,
                signal=signal,
                timestamp=_first(row, "timestamp", "ts"),
            )
            groups[(signal, source, destination)].append(event)

        findings = [_finding(signal, source, destination, rows, inventory_roles, segments) for (signal, source, destination), rows in sorted(groups.items())]

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "snmp_events_evaluated": len(context.snmp),
                "targeted_managed_device_events": candidates,
                "snmp_set_events": set_events,
                "writable_community_access_events": writable_access_events,
                "snmp_write_findings": len(findings),
                "skipped_non_target": skipped_non_target,
                "skipped_allowed": skipped_allowed,
                "skipped_read_only_or_unproven_writable": skipped_read_only,
            },
            evidence={
                "inspected_logs": ["snmp"] if context.snmp else [],
                "segments_loaded": len(segments),
                "inventory_entries_loaded": len(inventory_roles),
                "explicit_target_count": len(explicit_targets),
                "writable_community_rules_loaded": len(writable_communities),
                "notes": [
                    "Explicit SNMP SET request evidence is the primary signal; ordinary GET/GETNEXT/GETBULK polling does not trigger this module.",
                    "SNMPv1/v2c use alone does not prove a community is writable. Community-based findings require the community to be explicitly listed in policy as writable.",
                    "Community strings are treated as credentials and are redacted from finding evidence and metadata.",
                    "Targets must be explicitly identified by OT segment, asset-inventory role, or target_hosts/managed_hosts policy; private addressing alone is not sufficient.",
                    "Allowed managers and source-destination pairs can suppress approved SNMP configuration workflows.",
                ],
            },
            warnings=[],
        )


def _finding(signal: str, source: str, destination: str, rows: list[_Event], inventory_roles: dict[str, str], segments: list[_Segment]) -> Finding:
    total_sets = sum(event.set_count for event in rows)
    versions = sorted({event.version for event in rows if event.version})
    target_role = inventory_roles.get(destination, "")
    segment = _segment_for(destination, segments)
    if signal == "set_operation":
        severity = "high"
        title = "SNMP SET operation directed at OT/managed device"
        summary = (
            f"Observed {total_sets or len(rows)} SNMP SET operation(s) from {source} to managed target {destination}. "
            "SNMP SET can change device configuration or control state and should be limited to approved management stations and workflows."
        )
    else:
        severity = "medium"
        title = "Writable SNMPv1/v2c community used against OT/managed device"
        summary = (
            f"Observed {len(rows)} SNMPv1/v2c access event(s) from {source} to {destination} using a community explicitly marked writable by policy. "
            "The captured event does not itself prove a SET occurred, but the credential is configured as write-capable and should be tightly controlled."
        )

    evidence = [_redact(event.row) for event in rows[:MAX_EVIDENCE]]
    return Finding(
        title=title,
        severity=severity,
        summary=summary,
        confidence="high",
        detection_basis="protocol_log",
        devices=sorted({source, destination}),
        services=["SNMP"],
        ports=[161],
        connection_pairs=[{"source": source, "destination": destination, "protocol": "udp", "destination_port": 161}],
        flows=evidence,
        subnets=[str(segment.network)] if segment else [],
        timestamps=[event.timestamp for event in rows[:MAX_EVIDENCE] if event.timestamp is not None],
        tags=["snmp", "ot", "write", signal],
        metadata={
            "signal": signal,
            "event_count": len(rows),
            "set_operation_count": total_sets,
            "versions": versions,
            "target_role": target_role or (segment.role if segment else ""),
            "target_segment": segment.name if segment else "",
            "community_present": any(bool(event.community) for event in rows),
            "community_redacted": True,
            "evidence_event_count": len(evidence),
            "evidence_truncated": len(rows) > MAX_EVIDENCE,
        },
    )


def _redact(row: dict[str, Any]) -> dict[str, Any]:
    result = dict(row)
    for key in ("community", "community_string"):
        if key in result and result[key] not in (None, ""):
            result[key] = "[REDACTED]"
    return result


def _set_count(row: dict[str, Any]) -> int:
    for key in ("set_requests", "set_request_count", "set_count", "sets"):
        value = _as_int(row.get(key))
        if value is not None and value > 0:
            return value
    for key in ("pdu_type", "operation", "request_type", "request", "command"):
        text = _text(row.get(key)).lower().replace("-", "_").replace(" ", "_")
        if text in {"set", "set_request", "setrequest", "snmp_set"} or "set_request" in text:
            return 1
    return 0


def _is_target(ip: str, segments: list[_Segment], inventory_roles: dict[str, str], explicit: set[str]) -> bool:
    if ip in explicit:
        return True
    role = inventory_roles.get(ip, "").lower()
    if any(token in role for token in MANAGED_ROLE_TOKENS):
        return True
    segment = _segment_for(ip, segments)
    return bool(segment and any(token in segment.role.lower() for token in OT_ROLE_TOKENS))


def _segments(metadata: dict[str, Any]) -> list[_Segment]:
    result: list[_Segment] = []
    for item in metadata.get("segments", []) if isinstance(metadata, dict) else []:
        if not isinstance(item, dict):
            continue
        cidr = item.get("cidr") or item.get("subnet") or item.get("network")
        if not cidr:
            continue
        try:
            network = ipaddress.ip_network(str(cidr), strict=False)
        except ValueError:
            continue
        result.append(_Segment(_text(item.get("name")), _text(item.get("role") or item.get("type")), network))
    return result


def _segment_for(ip: str, segments: list[_Segment]) -> _Segment | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return next((segment for segment in segments if addr in segment.network), None)


def _inventory_roles(metadata: dict[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in metadata.get("asset_inventory", []) if isinstance(metadata, dict) else []:
        if not isinstance(item, dict):
            continue
        ip = _text(_first(item, "ip", "ip_address", "address", "host"))
        role = _text(_first(item, "role", "type", "asset_type", "device_type", "function"))
        if ip:
            result[ip] = role
    return result


def _policy(metadata: dict[str, Any]) -> dict[str, Any]:
    value = metadata.get("snmp_write_policy") if isinstance(metadata, dict) else None
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
    if isinstance(value, (list, tuple, set)):
        return {_text(item) for item in value if _text(item)}
    return set()


def _version(value: Any) -> str:
    text = _text(value).lower().replace("snmp", "").strip()
    if text in {"0", "1", "v1"}:
        return "v1"
    if text in {"2", "2c", "v2", "v2c"}:
        return "v2c"
    if text in {"3", "v3"}:
        return "v3"
    return text


def _as_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        if value.lower() in {"true", "yes", "1", "on"}:
            return True
        if value.lower() in {"false", "no", "0", "off"}:
            return False
    return default


def _as_int(value: Any) -> int | None:
    try:
        return int(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _first(mapping: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = mapping.get(key)
        if value not in (None, ""):
            return value
    return None


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()
