from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import ipaddress
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata

MAX_EVIDENCE_FLOWS = 10
DEFAULT_MIN_EXTERNAL_SERVERS = 2
OT_ROLE_TOKENS = {"ot", "control", "ics", "scada", "operations", "industrial", "process", "plc"}


@dataclass(slots=True)
class _Segment:
    cidr: str
    name: str
    role: str
    purdue_level: str
    network: ipaddress._BaseNetwork


@dataclass(slots=True)
class _Event:
    row: dict[str, Any]
    timestamp: float | None
    source: str
    destination: str
    source_port: int | None
    destination_port: int | None
    segment: _Segment | None
    external: bool
    trusted: bool


class NtpInternetMultiDestOtModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="ntp_internet_multi_dest_ot",
        name="NTP Sourced from Internet (Multi-Dest / OT)",
        description=(
            "Detects OT hosts using multiple distinct globally routable NTP servers instead of a centralized trusted "
            "time source, with optional trusted-server and external-server allow-list policy."
        ),
        category="security_analysis",
        required_logs=("ntp",),
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        if not context.ntp:
            return ModuleResult(
                module_id=self.metadata.id,
                findings=[],
                metrics={
                    "ntp_events_evaluated": 0,
                    "ot_ntp_client_events": 0,
                    "external_ntp_events": 0,
                    "ot_clients_with_multiple_external_servers": 0,
                    "ntp_findings": 0,
                },
                evidence={
                    "inspected_logs": [],
                    "notes": ["The detector requires ntp.log protocol evidence and does not infer NTP use from UDP/123 alone."],
                },
                warnings=[],
            )

        policy = _policy(context.metadata)
        segments = _load_segments(context.metadata)
        trusted_rules = _rules(policy, "trusted_servers", "trusted_ntp_servers", "internal_servers")
        allowed_external_rules = _rules(policy, "allowed_external_servers", "approved_external_servers")
        min_external = max(2, _as_int(policy.get("min_external_servers")) or DEFAULT_MIN_EXTERNAL_SERVERS)

        events: list[_Event] = []
        skipped_non_ot = 0
        skipped_non_client = 0
        for row in context.ntp:
            event = _event(row, segments, trusted_rules)
            if event is None:
                skipped_non_client += 1
                continue
            if not _segment_is_ot(event.segment):
                skipped_non_ot += 1
                continue
            events.append(event)

        by_source: dict[str, list[_Event]] = defaultdict(list)
        for event in events:
            by_source[event.source].append(event)

        findings: list[Finding] = []
        multi_clients = 0
        external_events = 0
        for source, source_events in sorted(by_source.items()):
            external = [
                event for event in source_events
                if event.external and not _matches_any(event.destination, allowed_external_rules)
            ]
            external_events += len(external)
            destinations = sorted({event.destination for event in external if event.destination})
            if len(destinations) < min_external:
                continue
            multi_clients += 1
            findings.append(_finding(source, source_events, external, destinations, trusted_rules))

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "ntp_events_evaluated": len(context.ntp),
                "ot_ntp_client_events": len(events),
                "external_ntp_events": external_events,
                "ot_clients_with_multiple_external_servers": multi_clients,
                "ntp_findings": len(findings),
                "skipped_non_ot_events": skipped_non_ot,
                "skipped_non_client_events": skipped_non_client,
            },
            evidence={
                "inspected_logs": ["ntp"],
                "configured_trusted_servers": trusted_rules,
                "configured_allowed_external_servers": allowed_external_rules,
                "min_external_servers": min_external,
                "notes": [
                    "Only explicit ntp.log client-to-server activity is evaluated; UDP/123 alone is not evidence.",
                    "Internet NTP destinations are identified as globally routable IP addresses, not merely as addresses outside the source subnet.",
                    "A finding requires an OT/control source and at least the configured number of distinct external NTP destinations (default: 2).",
                    "Private, link-local, loopback, multicast, reserved, and other non-global destinations are not classified as public Internet NTP servers.",
                    "Trusted internal servers and explicitly approved external NTP servers can be configured to reduce expected-use noise.",
                    "Evidence is capped at 10 representative NTP records while full counts remain in finding metadata.",
                ],
            },
            warnings=[],
        )


def _finding(
    source: str,
    source_events: list[_Event],
    external: list[_Event],
    destinations: list[str],
    trusted_rules: list[Any],
) -> Finding:
    segment = next((event.segment for event in source_events if event.segment is not None), None)
    trusted_observed = sorted({event.destination for event in source_events if event.trusted})
    severity = "high" if trusted_rules and not trusted_observed else "medium"
    summary = (
        f"OT host {source} contacted {len(destinations)} distinct public Internet NTP server(s): "
        f"{', '.join(destinations[:8])}. Multiple external time sources can bypass centralized OT time controls and "
        "introduce inconsistent or untrusted clock sources."
    )
    if trusted_rules:
        if trusted_observed:
            summary += f" Trusted NTP use was also observed ({', '.join(trusted_observed[:5])}), so review why public sources are additionally required."
        else:
            summary += " No configured trusted NTP source was observed for this host in the analyzed telemetry."

    evidence = sorted(external, key=lambda event: event.timestamp if event.timestamp is not None else -1.0)
    flows = [_flow(event) for event in evidence[:MAX_EVIDENCE_FLOWS]]
    timestamps = [event.timestamp for event in evidence[:MAX_EVIDENCE_FLOWS] if event.timestamp is not None]

    return Finding(
        title="OT Host Using Multiple Internet NTP Servers",
        severity=severity,
        summary=summary,
        confidence="high",
        detection_basis="protocol_log",
        devices=sorted({source, *destinations}),
        services=["NTP"],
        ports=[123],
        connection_pairs=[{"source": source, "destination": destination} for destination in destinations[:MAX_EVIDENCE_FLOWS]],
        flows=flows,
        subnets=[segment.cidr] if segment is not None else [],
        timestamps=timestamps,
        tags=["ntp", "ot", "internet", "multi-destination", "time-synchronization"],
        metadata={
            "source_ip": source,
            "source_segment": segment.name if segment is not None else "",
            "external_server_count": len(destinations),
            "external_servers": destinations,
            "external_event_count": len(external),
            "trusted_server_policy_configured": bool(trusted_rules),
            "trusted_servers_observed": trusted_observed,
            "evidence_truncated": len(external) > MAX_EVIDENCE_FLOWS,
        },
    )


def _event(row: dict[str, Any], segments: list[_Segment], trusted_rules: list[Any]) -> _Event | None:
    source = _ip(_first(row, "source_ip", "id.orig_h", "src"))
    destination = _ip(_first(row, "destination_ip", "id.resp_h", "dst"))
    if not source or not destination:
        return None
    source_port = _as_int(_first(row, "source_port", "id.orig_p"))
    destination_port = _as_int(_first(row, "destination_port", "id.resp_p"))
    # Zeek ntp.log is already protocol evidence. Restrict to requests/queries toward an NTP service endpoint.
    if destination_port not in (None, 123):
        return None
    return _Event(
        row=row,
        timestamp=_as_float(_first(row, "timestamp", "ts")),
        source=source,
        destination=destination,
        source_port=source_port,
        destination_port=destination_port,
        segment=_segment_for_ip(source, segments),
        external=_is_public(destination),
        trusted=_matches_any(destination, trusted_rules),
    )


def _flow(event: _Event) -> dict[str, Any]:
    return {
        "timestamp": event.timestamp,
        "source_ip": event.source,
        "source_port": event.source_port,
        "destination_ip": event.destination,
        "destination_port": event.destination_port,
        "ntp_version": _first(event.row, "version"),
        "ntp_mode": _first(event.row, "mode"),
        "stratum": _first(event.row, "stratum"),
        "uid": _first(event.row, "uid"),
    }


def _policy(metadata: dict[str, Any]) -> dict[str, Any]:
    for key in ("ntp_ot_policy", "ntp_policy", "time_sync_policy"):
        value = metadata.get(key)
        if isinstance(value, dict):
            return value
    return {}


def _rules(policy: dict[str, Any], *keys: str) -> list[Any]:
    for key in keys:
        value = policy.get(key)
        if isinstance(value, list):
            return value
    return []


def _load_segments(metadata: dict[str, Any]) -> list[_Segment]:
    values = metadata.get("segments")
    if not isinstance(values, list):
        return []
    result: list[_Segment] = []
    for item in values:
        if not isinstance(item, dict):
            continue
        cidr = str(item.get("cidr") or item.get("subnet") or item.get("network") or "").strip()
        if not cidr:
            continue
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        result.append(_Segment(
            cidr=str(network),
            name=str(item.get("name") or cidr),
            role=str(item.get("role") or item.get("type") or ""),
            purdue_level=str(item.get("purdue_level") or item.get("purdue") or item.get("level") or ""),
            network=network,
        ))
    return result


def _segment_for_ip(value: str, segments: list[_Segment]) -> _Segment | None:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    matches = [segment for segment in segments if address in segment.network]
    return max(matches, key=lambda segment: segment.network.prefixlen) if matches else None


def _segment_is_ot(segment: _Segment | None) -> bool:
    if segment is None:
        return False
    text = f"{segment.name} {segment.role}".lower()
    if any(token in text for token in OT_ROLE_TOKENS):
        return True
    level = segment.purdue_level.lower().replace("level", "").strip().lstrip("l")
    try:
        return 0 <= int(level) <= 3
    except ValueError:
        return False


def _is_public(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def _matches_any(value: str, rules: list[Any]) -> bool:
    if not value:
        return False
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    for rule in rules:
        text = str(rule).strip()
        if not text:
            continue
        try:
            if "/" in text:
                if address in ipaddress.ip_network(text, strict=False):
                    return True
            elif address == ipaddress.ip_address(text):
                return True
        except ValueError:
            continue
    return False


def _first(row: dict[str, Any], *names: str) -> Any:
    for name in names:
        value = row.get(name)
        if value not in (None, ""):
            return value
    return None


def _ip(value: Any) -> str:
    if value in (None, ""):
        return ""
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return ""


def _as_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _as_float(value: Any) -> float | None:
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
