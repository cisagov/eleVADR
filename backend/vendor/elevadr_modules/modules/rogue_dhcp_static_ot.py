from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import ipaddress
import re
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata


MAX_EVIDENCE = 10
DEFAULT_OFFER_WINDOW_SECONDS = 15.0

MESSAGE_NAMES = {
    1: "discover",
    2: "offer",
    3: "request",
    4: "decline",
    5: "ack",
    6: "nak",
    7: "release",
    8: "inform",
}
SERVER_MESSAGE_TYPES = {"offer", "ack", "nak"}
ACTIVITY_MESSAGE_TYPES = {"discover", "offer", "request", "decline", "ack", "nak", "release", "inform"}
LEASE_MESSAGE_TYPES = {"offer", "ack"}


@dataclass(slots=True)
class _Segment:
    cidr: str
    name: str
    role: str
    addressing: str
    dhcp_allowed: bool | None
    network: ipaddress._BaseNetwork


@dataclass(slots=True)
class _Event:
    row: dict[str, Any]
    timestamp: float | None
    message_types: set[str]
    client_ip: str
    requested_ip: str
    assigned_ip: str
    server_ip: str
    client_mac: str
    transaction_id: str
    segment: _Segment | None

    @property
    def has_offer(self) -> bool:
        return "offer" in self.message_types

    @property
    def is_server_activity(self) -> bool:
        return bool(self.message_types & SERVER_MESSAGE_TYPES)

    @property
    def is_lease_activity(self) -> bool:
        return bool(self.message_types & LEASE_MESSAGE_TYPES) or bool(self.assigned_ip)


class RogueDhcpStaticOtModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="rogue_dhcp_static_ot",
        name="Rogue DHCP Server / DHCP Activity on Static OT Segment",
        description=(
            "Detects DHCP offers or lease activity from unapproved servers, competing offers from multiple DHCP servers, "
            "and DHCP request/offer/lease activity on explicitly static or DHCP-prohibited OT segments."
        ),
        category="security_analysis",
        required_logs=("dhcp",),
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        if not context.dhcp:
            return ModuleResult(
                module_id=self.metadata.id,
                findings=[],
                metrics={
                    "dhcp_events_evaluated": 0,
                    "classified_dhcp_events": 0,
                    "unexpected_server_events": 0,
                    "competing_offer_groups": 0,
                    "static_ot_dhcp_events": 0,
                    "dhcp_findings": 0,
                },
                evidence={
                    "inspected_logs": [],
                    "notes": [
                        "The detector requires dhcp.log protocol evidence and does not infer DHCP activity from UDP/67-68 alone."
                    ],
                },
                warnings=[],
            )

        policy = _policy(context.metadata)
        segments = _load_segments(context.metadata, policy)
        events = [event for row in context.dhcp if (event := _event(row, segments)) is not None]

        unexpected = _unexpected_server_events(events, policy)
        competing = _competing_offer_groups(events, policy)
        static_events = [event for event in events if _event_on_static_ot(event, policy)]

        findings = (
            _unexpected_server_findings(unexpected, policy)
            + _competing_offer_findings(competing, policy)
            + _static_ot_findings(static_events)
        )

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "dhcp_events_evaluated": len(context.dhcp),
                "classified_dhcp_events": len(events),
                "unexpected_server_events": len(unexpected),
                "competing_offer_groups": len(competing),
                "static_ot_dhcp_events": len(static_events),
                "dhcp_findings": len(findings),
                "observed_dhcp_servers": len({event.server_ip for event in events if event.server_ip}),
            },
            evidence={
                "inspected_logs": ["dhcp"],
                "policy_loaded": bool(policy),
                "configured_expected_servers": sorted(_expected_server_text(policy)),
                "configured_static_segments": sorted(_static_segment_text(policy)),
                "notes": [
                    "DHCP message types are taken from explicit dhcp.log fields such as msg_types, client_message, server_message, or message_type.",
                    "UDP/67-68 traffic without DHCP protocol-log evidence never creates a finding.",
                    "An approved-server policy allows the module to label offers/ACKs/NAKs from other servers as unexpected.",
                    "Multiple distinct DHCP servers offering to the same client within the configured offer window are surfaced as competing-server behavior even when no approved-server list exists.",
                    "Static OT findings require explicit static/DHCP-prohibited segment configuration; OT classification by itself does not imply static addressing.",
                    "Evidence is capped at 10 representative DHCP records while full event counts remain in finding metadata.",
                ],
            },
            warnings=[],
        )


def _event(row: dict[str, Any], segments: list[_Segment]) -> _Event | None:
    message_types = _message_types(row)
    if not message_types:
        # An assigned address/lease time in a DHCP protocol log is still explicit lease evidence.
        assigned = _ip(_first(row, "assigned_addr", "assigned_ip", "yiaddr", "lease_addr"))
        lease_time = _first(row, "lease_time", "lease_seconds")
        if not assigned and lease_time in (None, ""):
            return None
        message_types = {"ack"}

    client_ip = _ip(_first(row, "client_addr", "client_ip", "ciaddr"))
    requested_ip = _ip(_first(row, "requested_addr", "requested_ip", "requested_address"))
    assigned_ip = _ip(_first(row, "assigned_addr", "assigned_ip", "yiaddr", "lease_addr"))
    server_ip = _server_ip(row, message_types)
    client_mac = _normalize_mac(_first(row, "client_mac", "mac", "chaddr", "client_hardware_addr"))
    transaction_id = _text(_first(row, "xid", "transaction_id", "transaction", "uid"))
    timestamp = _as_float(_first(row, "timestamp", "ts"))

    segment = None
    for value in (client_ip, requested_ip, assigned_ip):
        if value and value not in {"0.0.0.0", "255.255.255.255", "::"}:
            segment = _segment_for_ip(value, segments)
            if segment is not None:
                break

    return _Event(
        row=row,
        timestamp=timestamp,
        message_types=message_types,
        client_ip=client_ip,
        requested_ip=requested_ip,
        assigned_ip=assigned_ip,
        server_ip=server_ip,
        client_mac=client_mac,
        transaction_id=transaction_id,
        segment=segment,
    )


def _message_types(row: dict[str, Any]) -> set[str]:
    values: list[Any] = []
    for name in (
        "msg_types", "message_types", "message_type", "msg_type", "type",
        "client_message", "server_message", "dhcp_message_type",
    ):
        value = row.get(name)
        if value not in (None, ""):
            if isinstance(value, (list, tuple, set)):
                values.extend(value)
            else:
                values.append(value)

    result: set[str] = set()
    for value in values:
        if isinstance(value, int):
            name = MESSAGE_NAMES.get(value)
            if name:
                result.add(name)
            continue
        text = _text(value).lower()
        if not text:
            continue
        # Zeek vectors may be rendered as comma-delimited text in JSON pipelines.
        for token in re.split(r"[,;|\s]+", text):
            normalized = token.strip("[](){}'\"").replace("dhcp", "").strip("_- ")
            if not normalized:
                continue
            if normalized.isdigit():
                name = MESSAGE_NAMES.get(int(normalized))
                if name:
                    result.add(name)
            elif normalized in ACTIVITY_MESSAGE_TYPES:
                result.add(normalized)
        # Also catch phrases such as "DHCP Offer" without losing the word boundary.
        for name in ACTIVITY_MESSAGE_TYPES:
            if re.search(rf"\b{name}\b", text):
                result.add(name)
    return result


def _server_ip(row: dict[str, Any], message_types: set[str]) -> str:
    explicit = _ip(_first(row, "server_addr", "server_ip", "dhcp_server", "server_identifier", "siaddr"))
    if explicit:
        return explicit
    if message_types & SERVER_MESSAGE_TYPES:
        return _ip(_first(row, "source_ip", "id.orig_h", "src", "source"))
    return ""


def _unexpected_server_events(events: list[_Event], policy: dict[str, Any]) -> list[_Event]:
    rules = policy.get("expected_servers")
    if not isinstance(rules, list) or not rules:
        return []
    return [
        event for event in events
        if event.is_server_activity and event.server_ip and not _matches_any(event.server_ip, rules)
    ]


def _competing_offer_groups(events: list[_Event], policy: dict[str, Any]) -> list[list[_Event]]:
    offers = [event for event in events if event.has_offer and event.server_ip]
    if not offers:
        return []

    window = _as_float(policy.get("offer_window_seconds")) or DEFAULT_OFFER_WINDOW_SECONDS
    grouped: dict[str, list[_Event]] = defaultdict(list)
    for event in offers:
        key = event.client_mac or event.requested_ip or event.client_ip or event.transaction_id
        if key:
            grouped[key].append(event)

    results: list[list[_Event]] = []
    for key in sorted(grouped):
        ordered = sorted(grouped[key], key=lambda event: event.timestamp if event.timestamp is not None else -1.0)
        for index, event in enumerate(ordered):
            if event.timestamp is None:
                candidate = ordered
            else:
                candidate = [
                    other for other in ordered[index:]
                    if other.timestamp is not None and other.timestamp - event.timestamp <= window
                ]
            if len({item.server_ip for item in candidate if item.server_ip}) >= 2:
                results.append(candidate)
                break
    return results


def _event_on_static_ot(event: _Event, policy: dict[str, Any]) -> bool:
    segment = event.segment
    if segment is None:
        return False
    if not _segment_is_ot(segment):
        return False
    if _segment_is_static(segment):
        return True
    static_segments = policy.get("static_segments")
    if isinstance(static_segments, list):
        for value in static_segments:
            text = _text(value)
            if not text:
                continue
            if text.lower() == segment.name.lower() or _network_matches_segment(text, segment):
                return True
    return False


def _unexpected_server_findings(events: list[_Event], policy: dict[str, Any]) -> list[Finding]:
    groups: dict[str, list[_Event]] = defaultdict(list)
    for event in events:
        groups[event.server_ip].append(event)

    findings: list[Finding] = []
    for server, rows in sorted(groups.items()):
        message_types = sorted({kind for row in rows for kind in row.message_types & SERVER_MESSAGE_TYPES})
        findings.append(_finding(
            title="DHCP server activity from unexpected host",
            severity="high",
            confidence="high",
            summary=(
                f"Observed {len(rows)} DHCP server response event(s) from {server}, which is outside the configured "
                f"approved DHCP server set. Message types included {', '.join(message_types) or 'server responses'}. "
                "An unapproved DHCP server can redirect clients to incorrect gateways, DNS servers, or addressing and should be validated."
            ),
            rows=rows,
            tags=["dhcp", "rogue-dhcp", "unexpected-server", "ot"],
            metadata={
                "finding_type": "unexpected_dhcp_server",
                "server_ip": server,
                "event_count": len(rows),
                "message_types": message_types,
                "approved_servers_configured": True,
            },
        ))
    return findings


def _competing_offer_findings(groups: list[list[_Event]], policy: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    expected = policy.get("expected_servers") if isinstance(policy.get("expected_servers"), list) else []
    for rows in groups:
        servers = sorted({row.server_ip for row in rows if row.server_ip})
        client = next((row.client_mac for row in rows if row.client_mac), "") or next(
            (row.requested_ip or row.client_ip for row in rows if row.requested_ip or row.client_ip), "unknown client"
        )
        unexpected_servers = [server for server in servers if expected and not _matches_any(server, expected)]
        findings.append(_finding(
            title="Competing DHCP offers from multiple servers",
            severity="high" if unexpected_servers else "medium",
            confidence="high",
            summary=(
                f"Observed DHCP offers from {len(servers)} distinct servers ({', '.join(servers)}) for {client} within the "
                "configured response window. Multiple offer sources can indicate a rogue DHCP server, an unintended secondary "
                "server, or a legitimate redundant configuration that should be verified."
            ),
            rows=rows,
            tags=["dhcp", "rogue-dhcp", "multiple-offers", "competing-server"],
            metadata={
                "finding_type": "competing_dhcp_offers",
                "event_count": len(rows),
                "client_identifier": client,
                "offer_servers": servers,
                "unexpected_offer_servers": unexpected_servers,
                "offer_window_seconds": _as_float(policy.get("offer_window_seconds")) or DEFAULT_OFFER_WINDOW_SECONDS,
                "rogue_server_confirmed": False,
            },
        ))
    return findings


def _static_ot_findings(events: list[_Event]) -> list[Finding]:
    groups: dict[str, list[_Event]] = defaultdict(list)
    for event in events:
        if event.segment:
            groups[event.segment.name].append(event)

    findings: list[Finding] = []
    for segment_name, rows in sorted(groups.items()):
        message_types = sorted({kind for row in rows for kind in row.message_types})
        findings.append(_finding(
            title="DHCP activity observed on static OT segment",
            severity="high" if any(row.is_lease_activity for row in rows) else "medium",
            confidence="high",
            summary=(
                f"Observed {len(rows)} DHCP event(s) on OT segment {segment_name}, which is explicitly configured as static "
                f"or DHCP-prohibited. Message types included {', '.join(message_types) or 'DHCP lease activity'}. "
                "DHCP on a statically addressed control segment may indicate an unauthorized server/client, accidental configuration, "
                "or maintenance activity and should be reconciled with the segment design."
            ),
            rows=rows,
            tags=["dhcp", "ot", "static-addressing", "policy-violation"],
            metadata={
                "finding_type": "dhcp_on_static_ot_segment",
                "segment": segment_name,
                "event_count": len(rows),
                "message_types": message_types,
                "lease_activity_observed": any(row.is_lease_activity for row in rows),
                "static_segment_confirmed": True,
            },
        ))
    return findings


def _finding(*, title: str, severity: str, confidence: str, summary: str, rows: list[_Event], tags: list[str], metadata: dict[str, Any]) -> Finding:
    representative = rows[:MAX_EVIDENCE]
    devices = sorted({
        value for row in rows for value in
        (row.server_ip, row.client_ip, row.requested_ip, row.assigned_ip, row.client_mac)
        if value and value not in {"0.0.0.0", "255.255.255.255", "::"}
    })
    subnets = sorted({row.segment.cidr for row in rows if row.segment is not None})
    pairs = []
    seen: set[tuple[str, str]] = set()
    for row in representative:
        source = row.server_ip or row.client_ip or row.requested_ip
        destination = row.assigned_ip or row.client_ip or row.requested_ip
        key = (source, destination)
        if key in seen:
            continue
        seen.add(key)
        pairs.append({
            "source": source or None,
            "destination": destination or None,
            "port": 67 if row.is_server_activity else 68,
            "protocol": "udp",
            "service": "DHCP",
        })

    return Finding(
        title=title,
        severity=severity,
        summary=summary,
        confidence=confidence,
        detection_basis="protocol_log",
        devices=devices,
        services=["DHCP"],
        ports=[67, 68],
        connection_pairs=pairs,
        flows=[row.row for row in representative],
        subnets=subnets,
        timestamps=[row.timestamp for row in representative if row.timestamp is not None],
        tags=tags,
        metadata={
            **metadata,
            "evidence_event_count": len(representative),
            "evidence_truncated": len(rows) > MAX_EVIDENCE,
        },
    )


def _policy(metadata: dict[str, Any]) -> dict[str, Any]:
    raw = metadata.get("dhcp_ot_policy")
    if not isinstance(raw, dict):
        raw = metadata.get("rogue_dhcp_policy")
    raw = raw if isinstance(raw, dict) else {}
    return {
        "expected_servers": list(raw.get("expected_servers", raw.get("allowed_servers", [])))
        if isinstance(raw.get("expected_servers", raw.get("allowed_servers", [])), list) else [],
        "static_segments": list(raw.get("static_segments", raw.get("dhcp_prohibited_segments", [])))
        if isinstance(raw.get("static_segments", raw.get("dhcp_prohibited_segments", [])), list) else [],
        "offer_window_seconds": raw.get("offer_window_seconds", DEFAULT_OFFER_WINDOW_SECONDS),
    }


def _load_segments(metadata: dict[str, Any], policy: dict[str, Any]) -> list[_Segment]:
    raw = metadata.get("segments")
    if not isinstance(raw, list):
        raw = []
    segments: list[_Segment] = []
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
        name = _text(item.get("name") or item.get("label") or cidr) or cidr
        role = _text(item.get("role") or item.get("segment_role") or item.get("type"))
        addressing = _text(item.get("addressing") or item.get("addressing_mode") or item.get("ip_assignment"))
        dhcp_allowed = _as_bool(item.get("dhcp_allowed"))
        if dhcp_allowed is None and "dhcp" in item and isinstance(item.get("dhcp"), bool):
            dhcp_allowed = bool(item.get("dhcp"))
        segments.append(_Segment(
            cidr=cidr,
            name=name,
            role=role,
            addressing=addressing,
            dhcp_allowed=dhcp_allowed,
            network=network,
        ))
    return sorted(segments, key=lambda segment: segment.network.prefixlen, reverse=True)


def _segment_for_ip(value: str, segments: list[_Segment]) -> _Segment | None:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    for segment in segments:
        if address.version == segment.network.version and address in segment.network:
            return segment
    return None


def _segment_is_ot(segment: _Segment) -> bool:
    text = f"{segment.name} {segment.role}".lower().replace("-", " ").replace("_", " ")
    tokens = set(text.split())
    return bool(tokens.intersection({"ot", "ics", "control", "scada", "plc", "dcs"}))


def _segment_is_static(segment: _Segment) -> bool:
    if segment.dhcp_allowed is False:
        return True
    value = segment.addressing.lower().replace("-", " ").replace("_", " ")
    return value in {"static", "static only", "manual", "fixed", "no dhcp", "dhcp prohibited", "dhcp disabled"}


def _network_matches_segment(value: str, segment: _Segment) -> bool:
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False
    return network == segment.network or network.subnet_of(segment.network) or segment.network.subnet_of(network)


def _matches_any(ip_value: str, rules: list[Any]) -> bool:
    for rule in rules:
        text = _text(rule)
        if not text:
            continue
        if ip_value == text:
            return True
        try:
            if ipaddress.ip_address(ip_value) in ipaddress.ip_network(text, strict=False):
                return True
        except ValueError:
            continue
    return False


def _expected_server_text(policy: dict[str, Any]) -> set[str]:
    values = policy.get("expected_servers")
    return {_text(value) for value in values if _text(value)} if isinstance(values, list) else set()


def _static_segment_text(policy: dict[str, Any]) -> set[str]:
    values = policy.get("static_segments")
    return {_text(value) for value in values if _text(value)} if isinstance(values, list) else set()


def _first(row: dict[str, Any], *names: str) -> Any:
    for name in names:
        value = row.get(name)
        if value is not None and value != "":
            return value
    return None


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _ip(value: Any) -> str:
    text = _text(value)
    if not text:
        return ""
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return ""


def _normalize_mac(value: Any) -> str:
    text = _text(value).lower().replace("-", ":")
    if not text:
        return ""
    parts = text.split(":")
    if len(parts) == 6 and all(re.fullmatch(r"[0-9a-f]{1,2}", part) for part in parts):
        return ":".join(part.zfill(2) for part in parts)
    return text


def _as_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _as_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    text = _text(value).lower()
    if text in {"true", "yes", "1", "enabled", "allow", "allowed"}:
        return True
    if text in {"false", "no", "0", "disabled", "deny", "denied", "prohibited"}:
        return False
    return None
