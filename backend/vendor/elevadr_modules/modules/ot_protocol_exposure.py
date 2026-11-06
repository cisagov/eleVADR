from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
import ipaddress
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata


MAX_EVIDENCE_ROWS = 25


@dataclass(frozen=True, slots=True)
class ProtocolRule:
    id: str
    name: str
    ports: tuple[int, ...]
    transports: tuple[str, ...]
    service_aliases: tuple[str, ...]
    protocol_logs: tuple[str, ...] = ()
    severity: str = "high"


PROTOCOL_RULES: tuple[ProtocolRule, ...] = (
    ProtocolRule(
        id="modbus",
        name="Modbus/TCP",
        ports=(502,),
        transports=("tcp",),
        service_aliases=("modbus", "modbus_tcp", "modbus/tcp"),
        protocol_logs=("modbus",),
        severity="high",
    ),
    ProtocolRule(
        id="dnp3",
        name="DNP3",
        ports=(20000,),
        transports=("tcp", "udp"),
        service_aliases=("dnp3",),
        protocol_logs=("dnp3",),
        severity="high",
    ),
    ProtocolRule(
        id="enip",
        name="EtherNet/IP",
        ports=(44818, 2222),
        transports=("tcp", "udp"),
        service_aliases=("enip", "ethernet/ip", "ethernetip", "cip"),
        protocol_logs=("enip",),
        severity="high",
    ),
    ProtocolRule(
        id="bacnet",
        name="BACnet/IP",
        ports=tuple(range(47808, 47824)),
        transports=("udp",),
        service_aliases=("bacnet", "bacnet-ip", "bacnet_ip"),
        protocol_logs=("bacnet",),
        severity="high",
    ),
)

# TCP/102 is shared by ISO-on-TCP applications. Without application-level
# confirmation it is not defensible to decide between S7comm and IEC 61850 MMS.
PORT_102_RULE = ProtocolRule(
    id="iso_on_tcp_ot",
    name="ISO-on-TCP (possible S7comm / IEC 61850 MMS)",
    ports=(102,),
    transports=("tcp",),
    service_aliases=(),
    severity="medium",
)

SERVICE_ONLY_RULES: tuple[ProtocolRule, ...] = (
    ProtocolRule(
        id="s7comm",
        name="S7comm",
        ports=(102,),
        transports=("tcp",),
        service_aliases=("s7", "s7comm", "s7comm-plus", "s7comm_plus"),
        protocol_logs=("s7comm",),
        severity="high",
    ),
    ProtocolRule(
        id="iec61850_mms",
        name="IEC 61850 MMS",
        ports=(102,),
        transports=("tcp",),
        service_aliases=("mms", "iec61850", "iec-61850", "iec61850-mms"),
        protocol_logs=("mms", "iec61850"),
        severity="high",
    ),
)

CONTROL_ROLES = {
    "control",
    "control_system",
    "control-system",
    "control system",
    "ot_control",
    "ics_control",
    "ics",
    "ot",
}
NON_CONTROL_ROLES = {
    "non_control",
    "non-control",
    "non control",
    "it",
    "enterprise",
    "corporate",
    "business",
    "user",
    "dmz",
    "guest",
}


@dataclass(slots=True)
class _ObservedFlow:
    row: dict[str, Any]
    rule: ProtocolRule
    source: str
    destination: str
    source_port: int | None
    destination_port: int | None
    transport: str
    timestamp: float | str | None
    detection_basis: str
    protocol_confirmed: bool
    source_segment: dict[str, str] | None
    destination_segment: dict[str, str] | None


class OtProtocolExposureModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="ot_protocol_exposure",
        name="OT Protocol Exposure",
        description=(
            "Identifies industrial control protocols observed outside configured control-system "
            "network segments, including Modbus, DNP3, EtherNet/IP, BACnet, IEC 61850 MMS, and S7comm."
        ),
        category="security_analysis",
        required_logs=("conn",),
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        if not context.connections:
            return ModuleResult(
                module_id=self.metadata.id,
                findings=[],
                metrics={
                    "ot_protocol_exposure_findings": 0,
                    "ot_protocol_flows_observed": 0,
                    "confirmed_non_control_exposure_flows": 0,
                    "unclassified_ot_protocol_flows": 0,
                    "flows_by_protocol": {},
                },
                evidence={
                    "inspected_logs": [],
                    "skipped_logs": ["conn"],
                    "segments_loaded": 0,
                    "notes": ["conn.log is required for OT protocol exposure analysis."],
                },
                warnings=[],
            )

        segments = _load_segments(context.metadata)
        protocol_log_uids = _protocol_log_uid_index(context)
        observed: list[_ObservedFlow] = []

        for row in context.connections:
            match = _match_protocol(row, protocol_log_uids)
            if match is None:
                continue
            rule, basis, confirmed = match
            source = str(_first(row, "source_ip", "id.orig_h") or "")
            destination = str(_first(row, "destination_ip", "id.resp_h") or "")
            if not source or not destination:
                continue
            observed.append(
                _ObservedFlow(
                    row=row,
                    rule=rule,
                    source=source,
                    destination=destination,
                    source_port=_as_int(_first(row, "source_port", "id.orig_p")),
                    destination_port=_as_int(_first(row, "destination_port", "id.resp_p")),
                    transport=str(_first(row, "protocol", "proto") or "").lower(),
                    timestamp=_first(row, "timestamp", "ts"),
                    detection_basis=basis,
                    protocol_confirmed=confirmed,
                    source_segment=_segment_for_ip(source, segments),
                    destination_segment=_segment_for_ip(destination, segments),
                )
            )

        findings = _build_findings(observed, segments_available=bool(segments))
        confirmed_exposure_flows = sum(_is_confirmed_exposure(item) for item in observed)
        unclassified_flows = sum(_is_unclassified(item) for item in observed)
        flows_by_protocol = Counter(item.rule.name for item in observed)

        optional_logs = ("modbus", "dnp3", "enip", "bacnet", "s7comm", "mms", "iec61850")
        inspected_optional = [name for name in optional_logs if context.log(name)]

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "ot_protocol_exposure_findings": len(findings),
                "ot_protocol_flows_observed": len(observed),
                "confirmed_non_control_exposure_flows": confirmed_exposure_flows,
                "unclassified_ot_protocol_flows": unclassified_flows,
                "flows_by_protocol": dict(sorted(flows_by_protocol.items())),
            },
            evidence={
                "inspected_logs": ["conn", *inspected_optional],
                "skipped_optional_logs": [name for name in optional_logs if name not in inspected_optional],
                "segments_loaded": len(segments),
                "segment_source": context.metadata.get("segments_source"),
                "supported_protocols": [
                    "Modbus/TCP",
                    "DNP3",
                    "EtherNet/IP",
                    "BACnet/IP",
                    "IEC 61850 MMS",
                    "S7comm",
                ],
                "notes": [
                    "A confirmed exposure finding requires at least one endpoint to map to a configured non-control segment.",
                    "When no segment classification is available, observed OT protocols are surfaced as low-confidence review findings rather than asserted as non-control exposure.",
                    "TCP/102 is shared by ISO-on-TCP applications. Port-only TCP/102 observations are reported as possible S7comm / IEC 61850 MMS rather than assigned to one protocol.",
                    "IEC 61850 GOOSE and Sampled Values are Layer-2 protocols and are not detectable from conn.log alone; a dedicated packet/analyzer source is required for those profiles.",
                    "Port-only matches are lower confidence than Zeek service or protocol-log confirmation.",
                ],
                "segment_config_format": {
                    "segments": [
                        {"cidr": "10.10.0.0/16", "name": "OT Control", "role": "control"},
                        {"cidr": "10.20.0.0/16", "name": "Enterprise", "role": "non_control"},
                    ]
                },
            },
            warnings=[],
        )


def _build_findings(observed: list[_ObservedFlow], *, segments_available: bool) -> list[Finding]:
    groups: dict[tuple[str, str], list[_ObservedFlow]] = defaultdict(list)
    for item in observed:
        exposure = _exposure_class(item)
        if exposure == "control_only":
            continue
        groups[(item.rule.id, exposure)].append(item)

    findings: list[Finding] = []
    for (rule_id, exposure), rows in sorted(groups.items()):
        rule = rows[0].rule
        bases = {row.detection_basis for row in rows}
        basis = "protocol_log" if "protocol_log" in bases else "zeek_service" if "zeek_service" in bases else "port"
        protocol_confidence = "high" if basis in {"protocol_log", "zeek_service"} else "low"

        if exposure == "cross_boundary":
            severity = rule.severity
            confidence = protocol_confidence
            title = f"OT protocol crosses into a non-control segment: {rule.name}"
            summary = (
                f"Observed {len(rows)} {rule.name} flow(s) crossing between a configured control-system segment "
                "and a configured non-control segment. Industrial control protocols outside their intended control boundary warrant investigation."
            )
        elif exposure == "non_control":
            severity = rule.severity
            confidence = protocol_confidence
            title = f"OT protocol observed in a non-control segment: {rule.name}"
            summary = (
                f"Observed {len(rows)} {rule.name} flow(s) where the participating endpoints are classified in non-control network segments. "
                "Industrial control protocols in enterprise, business, guest, or other non-control segments may indicate unintended exposure or segmentation failure."
            )
        elif exposure == "partial_non_control":
            severity = "medium" if rule.severity in {"high", "critical"} else rule.severity
            confidence = "medium" if protocol_confidence == "high" else "low"
            title = f"OT protocol involves a non-control segment: {rule.name}"
            summary = (
                f"Observed {len(rows)} {rule.name} flow(s) with at least one endpoint in a configured non-control segment; "
                "the other endpoint could not be classified. Review the segment boundary and asset roles."
            )
        else:
            # No usable segmentation context. Do not state that exposure has been proven.
            severity = "low"
            confidence = "low" if basis == "port" else "medium"
            title = f"OT protocol observed; segment classification unavailable: {rule.name}"
            summary = (
                f"Observed {len(rows)} {rule.name} flow(s), but the harness does not have enough segment classification data "
                "to determine whether the traffic is outside a control-system segment. Provide segments.json to evaluate exposure."
            )

        devices = sorted({value for row in rows for value in (row.source, row.destination) if value})
        ports = sorted({row.destination_port for row in rows if row.destination_port is not None})
        subnets = sorted({
            segment["cidr"]
            for row in rows
            for segment in (row.source_segment, row.destination_segment)
            if segment and segment.get("cidr")
        })
        pairs = []
        seen_pairs: set[tuple[str, str, int | None, str]] = set()
        for row in rows:
            key = (row.source, row.destination, row.destination_port, row.transport)
            if key in seen_pairs:
                continue
            seen_pairs.add(key)
            pairs.append(
                {
                    "source": row.source,
                    "destination": row.destination,
                    "port": row.destination_port,
                    "protocol": row.transport,
                    "service": rule.name,
                }
            )

        findings.append(
            Finding(
                title=title,
                severity=severity,
                summary=summary,
                confidence=confidence,
                detection_basis=basis,
                devices=devices,
                services=[rule.name],
                ports=ports,
                connection_pairs=pairs,
                flows=[row.row for row in rows[:MAX_EVIDENCE_ROWS]],
                subnets=subnets,
                timestamps=sorted({row.timestamp for row in rows if row.timestamp is not None}, key=str),
                tags=["ot", "industrial-protocol", "segmentation", "protocol-exposure", rule.id],
                metadata={
                    "rule_id": rule.id,
                    "flow_count": len(rows),
                    "exposure_class": exposure,
                    "segments_available": segments_available,
                    "protocol_confirmed": any(row.protocol_confirmed for row in rows),
                    "source_segments": _segments_summary(rows, "source_segment"),
                    "destination_segments": _segments_summary(rows, "destination_segment"),
                    "evidence_truncated": len(rows) > MAX_EVIDENCE_ROWS,
                },
            )
        )
    return findings


def _match_protocol(
    row: dict[str, Any], protocol_log_uids: dict[str, set[str]]
) -> tuple[ProtocolRule, str, bool] | None:
    uid = str(row.get("uid") or "")
    service = str(row.get("service") or "").strip().lower()
    port = _as_int(_first(row, "destination_port", "id.resp_p"))
    transport = str(_first(row, "protocol", "proto") or "").lower()

    # Strongest evidence: protocol-specific log tied to this connection UID.
    if uid:
        for rule in (*PROTOCOL_RULES, *SERVICE_ONLY_RULES):
            if any(uid in protocol_log_uids.get(log_name, set()) for log_name in rule.protocol_logs):
                return rule, "protocol_log", True

    # Then use Zeek's application service identification.
    if service:
        for rule in (*PROTOCOL_RULES, *SERVICE_ONLY_RULES):
            if service in rule.service_aliases:
                return rule, "zeek_service", True

    # Port-only fallback for protocols with unambiguous well-known ports.
    for rule in PROTOCOL_RULES:
        if port in rule.ports and transport in rule.transports:
            return rule, "port", False

    # TCP/102 is deliberately ambiguous without application confirmation.
    if port == 102 and transport == "tcp":
        return PORT_102_RULE, "port", False
    return None


def _protocol_log_uid_index(context: AnalysisContext) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    for name in ("modbus", "dnp3", "enip", "bacnet", "s7comm", "mms", "iec61850"):
        result[name] = {str(row.get("uid")) for row in context.log(name) if row.get("uid")}
    return result


def _load_segments(metadata: dict[str, Any]) -> list[dict[str, str]]:
    raw = metadata.get("segments") or []
    if not isinstance(raw, list):
        raw = []
    segments: list[dict[str, str]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        cidr = str(item.get("cidr") or item.get("subnet") or "").strip()
        role = _normalize_role(item.get("role") or item.get("classification") or item.get("type"))
        if not cidr or not role:
            continue
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        segments.append(
            {
                "cidr": cidr,
                "name": str(item.get("name") or cidr),
                "role": role,
            }
        )

    for cidr in metadata.get("control_system_subnets", []) or []:
        segments.append({"cidr": str(cidr), "name": str(cidr), "role": "control"})
    for cidr in metadata.get("non_control_subnets", []) or []:
        segments.append({"cidr": str(cidr), "name": str(cidr), "role": "non_control"})
    return segments


def _segment_for_ip(value: str, segments: list[dict[str, str]]) -> dict[str, str] | None:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    matches: list[tuple[int, dict[str, str]]] = []
    for segment in segments:
        try:
            network = ipaddress.ip_network(segment["cidr"], strict=False)
        except ValueError:
            continue
        if address in network:
            matches.append((network.prefixlen, segment))
    if not matches:
        return None
    return max(matches, key=lambda item: item[0])[1]


def _normalize_role(value: Any) -> str:
    role = str(value or "").strip().lower().replace("-", "_")
    if role.replace("_", " ") in {item.replace("-", " ").replace("_", " ") for item in CONTROL_ROLES}:
        return "control"
    if role.replace("_", " ") in {item.replace("-", " ").replace("_", " ") for item in NON_CONTROL_ROLES}:
        return "non_control"
    return role


def _role(segment: dict[str, str] | None) -> str:
    return segment.get("role", "") if segment else ""


def _exposure_class(item: _ObservedFlow) -> str:
    source_role = _role(item.source_segment)
    destination_role = _role(item.destination_segment)
    if source_role == "control" and destination_role == "control":
        return "control_only"
    if {source_role, destination_role} == {"control", "non_control"}:
        return "cross_boundary"
    if source_role == "non_control" and destination_role == "non_control":
        return "non_control"
    if "non_control" in {source_role, destination_role}:
        return "partial_non_control"
    return "unclassified"


def _is_confirmed_exposure(item: _ObservedFlow) -> bool:
    return _exposure_class(item) in {"cross_boundary", "non_control", "partial_non_control"}


def _is_unclassified(item: _ObservedFlow) -> bool:
    return _exposure_class(item) == "unclassified"


def _segments_summary(rows: list[_ObservedFlow], attr: str) -> list[dict[str, str]]:
    seen: dict[tuple[str, str, str], dict[str, str]] = {}
    for row in rows:
        segment = getattr(row, attr)
        if not segment:
            continue
        key = (segment.get("cidr", ""), segment.get("name", ""), segment.get("role", ""))
        seen[key] = segment
    return [seen[key] for key in sorted(seen)]


def _first(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = row.get(key)
        if value is not None:
            return value
    return None


def _as_int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None
