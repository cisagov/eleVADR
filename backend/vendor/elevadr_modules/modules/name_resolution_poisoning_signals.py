from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
import ipaddress
from typing import Any, Iterable

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata

MAX_EVIDENCE_ROWS = 10
DEFAULT_WINDOW_SECONDS = 60.0
DEFAULT_RESPONSE_WINDOW_SECONDS = 5.0
DEFAULT_RESPONDER_WINDOW_SECONDS = 300.0

PROTOCOLS = {
    "llmnr": {
        "ports": {5355},
        "query_threshold": 20,
        "unique_query_threshold": 8,
        "responder_name_threshold": 5,
        "responder_requester_threshold": 5,
        "multi_responder_threshold": 2,
    },
    "nbt_ns": {
        "ports": {137},
        "query_threshold": 20,
        "unique_query_threshold": 8,
        "responder_name_threshold": 5,
        "responder_requester_threshold": 5,
        "multi_responder_threshold": 2,
    },
    "mdns": {
        "ports": {5353},
        "query_threshold": 60,
        "unique_query_threshold": 15,
        "responder_name_threshold": 20,
        "responder_requester_threshold": 12,
        "multi_responder_threshold": 3,
    },
}

MULTICAST_DESTINATIONS = {
    "224.0.0.251",  # mDNS IPv4
    "224.0.0.252",  # LLMNR IPv4
    "ff02::fb",     # mDNS IPv6
    "ff02::1:3",    # LLMNR IPv6
}


@dataclass(frozen=True, slots=True)
class _Event:
    protocol: str
    timestamp: float
    query: str
    source: str
    destination: str
    source_port: int | None
    destination_port: int | None
    answers: tuple[str, ...]
    row: dict[str, Any]
    explicit_response: bool
    responder: str | None
    requester: str | None


class NameResolutionPoisoningSignalsModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="llmnr_nbtns_mdns_poisoning_signals",
        name="LLMNR/NBT-NS/mDNS Poisoning Signals",
        description=(
            "Detects unusually frequent multicast/broadcast name-resolution queries and suspicious "
            "LLMNR, NBT-NS, or mDNS responder patterns that can be consistent with name-resolution poisoning."
        ),
        category="security_analysis",
        required_logs=("dns",),
        default_enabled=True,
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        if not context.dns:
            return ModuleResult(
                module_id=self.metadata.id,
                metrics={
                    "name_resolution_events": 0,
                    "poisoning_signal_findings": 0,
                },
                evidence={"inspected_logs": [], "skipped_logs": ["dns"]},
            )

        policy = _policy(context.metadata)
        events = [event for row in context.dns if (event := _event(row)) is not None]
        findings: list[Finding] = []
        findings.extend(_frequent_query_findings(events, policy, context.metadata))
        findings.extend(_multi_responder_findings(events, policy, context.metadata))
        findings.extend(_responder_fanout_findings(events, policy, context.metadata))

        affected_devices = {device for finding in findings for device in finding.devices}
        response_events = sum(1 for event in events if event.explicit_response)
        protocol_counts: dict[str, int] = defaultdict(int)
        for event in events:
            protocol_counts[event.protocol] += 1

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "name_resolution_events": len(events),
                "explicit_response_events": response_events,
                "poisoning_signal_findings": len(findings),
                "affected_devices": len(affected_devices),
                "events_by_protocol": dict(sorted(protocol_counts.items())),
            },
            evidence={
                "inspected_logs": ["dns"],
                "notes": [
                    "LLMNR, NBT-NS, and mDNS are legitimate local name-resolution/discovery protocols; their presence alone is not evidence of poisoning.",
                    "Frequent-query findings are low-severity behavioral indicators and require unusually dense, diverse query activity within a short window.",
                    "Responder findings require response attribution from explicit response fields or response-direction port semantics; ambiguous multicast DNS transactions are not assigned to a responder.",
                    "Multiple responders for the same name or a single responder answering many names/requesters can be consistent with poisoning tools, but may also have benign explanations.",
                    "No finding produced by this module independently confirms credential interception, spoofing, or lateral movement.",
                ],
                "policy": policy,
            },
        )


def _policy(metadata: dict[str, Any]) -> dict[str, Any]:
    raw = metadata.get("name_resolution_poisoning_policy")
    raw = raw if isinstance(raw, dict) else {}
    return {
        "query_window_seconds": _positive_float(raw.get("query_window_seconds"), DEFAULT_WINDOW_SECONDS),
        "response_window_seconds": _positive_float(raw.get("response_window_seconds"), DEFAULT_RESPONSE_WINDOW_SECONDS),
        "responder_window_seconds": _positive_float(raw.get("responder_window_seconds"), DEFAULT_RESPONDER_WINDOW_SECONDS),
        "llmnr_query_threshold": _positive_int(raw.get("llmnr_query_threshold"), PROTOCOLS["llmnr"]["query_threshold"]),
        "nbt_ns_query_threshold": _positive_int(raw.get("nbt_ns_query_threshold"), PROTOCOLS["nbt_ns"]["query_threshold"]),
        "mdns_query_threshold": _positive_int(raw.get("mdns_query_threshold"), PROTOCOLS["mdns"]["query_threshold"]),
    }


def _event(row: dict[str, Any]) -> _Event | None:
    source = _text(row.get("source_ip") or row.get("id.orig_h"))
    destination = _text(row.get("destination_ip") or row.get("id.resp_h"))
    source_port = _integer(row.get("source_port") or row.get("id.orig_p"))
    destination_port = _integer(row.get("destination_port") or row.get("id.resp_p"))
    protocol = _protocol_for_ports(source_port, destination_port)
    if protocol is None:
        return None

    query = _text(row.get("query") or row.get("name") or row.get("hostname")).lower().rstrip(".")
    if not query:
        return None
    timestamp = _number(row.get("timestamp") or row.get("ts"))
    if timestamp is None:
        return None

    answers = tuple(sorted(_answers(row)))
    explicit_response, responder, requester = _response_attribution(
        row,
        protocol=protocol,
        source=source,
        destination=destination,
        source_port=source_port,
        destination_port=destination_port,
        answers=answers,
    )
    return _Event(
        protocol=protocol,
        timestamp=timestamp,
        query=query,
        source=source,
        destination=destination,
        source_port=source_port,
        destination_port=destination_port,
        answers=answers,
        row=row,
        explicit_response=explicit_response,
        responder=responder,
        requester=requester,
    )


def _protocol_for_ports(source_port: int | None, destination_port: int | None) -> str | None:
    for protocol, config in PROTOCOLS.items():
        ports = config["ports"]
        if source_port in ports or destination_port in ports:
            return protocol
    return None


def _answers(row: dict[str, Any]) -> set[str]:
    result: set[str] = set()
    for key in ("answers", "answer", "resolved_ips", "addresses"):
        value = row.get(key)
        if isinstance(value, str):
            for item in value.replace(";", ",").split(","):
                item = item.strip()
                if item and item != "-":
                    result.add(item)
        elif isinstance(value, (list, tuple, set)):
            for item in value:
                text = _text(item)
                if text:
                    result.add(text)
    return result


def _response_attribution(
    row: dict[str, Any],
    *,
    protocol: str,
    source: str,
    destination: str,
    source_port: int | None,
    destination_port: int | None,
    answers: tuple[str, ...],
) -> tuple[bool, str | None, str | None]:
    explicit = _boolish(row.get("is_response") or row.get("response") or row.get("qr"))
    response_type = _text(row.get("message_type") or row.get("msg_type") or row.get("direction")).lower()
    if response_type in {"response", "reply", "answer"}:
        explicit = True

    explicit_responder = _text(row.get("responder_ip") or row.get("response_source") or row.get("answering_host"))
    explicit_requester = _text(row.get("requester_ip") or row.get("query_source") or row.get("client_ip"))
    if explicit_responder:
        return True, explicit_responder, explicit_requester or destination or None
    if explicit and source:
        return True, source, explicit_requester or destination or None

    ports = PROTOCOLS[protocol]["ports"]
    if answers and source_port in ports and destination_port not in ports and source:
        return True, source, destination or None

    # Conventional transaction-shaped row: requester -> unicast responder. This is
    # safe only when the destination is a real host, not the multicast/broadcast group.
    if answers and destination_port in ports and destination and not _is_multicast_or_broadcast(destination):
        return True, destination, source or None

    return False, None, None


def _frequent_query_findings(
    events: list[_Event], policy: dict[str, Any], metadata: dict[str, Any]
) -> list[Finding]:
    findings: list[Finding] = []
    by_source_protocol: dict[tuple[str, str], list[_Event]] = defaultdict(list)
    for event in events:
        if event.source:
            by_source_protocol[(event.source, event.protocol)].append(event)

    window_seconds = float(policy["query_window_seconds"])
    for (source, protocol), rows in sorted(by_source_protocol.items()):
        rows.sort(key=lambda event: event.timestamp)
        threshold = int(policy[f"{protocol}_query_threshold"])
        unique_threshold = int(PROTOCOLS[protocol]["unique_query_threshold"])
        best = _densest_window(rows, window_seconds)
        if len(best) < threshold:
            continue
        unique_queries = {event.query for event in best}
        if len(unique_queries) < unique_threshold:
            continue

        destinations = sorted({event.destination for event in best if event.destination})
        subnets = _event_segments(best, metadata)
        findings.append(
            Finding(
                title=f"Frequent {_label(protocol)} name queries from {source}",
                severity="low",
                confidence="medium",
                detection_basis="heuristic",
                summary=(
                    f"Observed {len(best)} {_label(protocol)} name-resolution events from {source} within "
                    f"{window_seconds:.0f} seconds covering {len(unique_queries)} unique names. Dense local name-resolution "
                    "activity can increase exposure to spoofed responses and can also occur during normal discovery or misconfiguration; "
                    "this finding does not by itself indicate poisoning."
                ),
                devices=sorted({source, *destinations}),
                services=[_label(protocol)],
                ports=sorted(PROTOCOLS[protocol]["ports"]),
                connection_pairs=_pairs(best),
                flows=[event.row for event in best[:MAX_EVIDENCE_ROWS]],
                subnets=subnets,
                timestamps=[event.timestamp for event in best[:MAX_EVIDENCE_ROWS]],
                tags=["name-resolution", "poisoning-signal", protocol, "frequent-queries"],
                metadata={
                    "signal": "frequent_queries",
                    "protocol": protocol,
                    "window_seconds": window_seconds,
                    "event_count": len(best),
                    "unique_query_count": len(unique_queries),
                    "evidence_truncated": len(best) > MAX_EVIDENCE_ROWS,
                    "poisoning_confirmed": False,
                },
            )
        )
    return findings


def _multi_responder_findings(
    events: list[_Event], policy: dict[str, Any], metadata: dict[str, Any]
) -> list[Finding]:
    findings: list[Finding] = []
    responses = [event for event in events if event.explicit_response and event.responder]
    by_protocol_query: dict[tuple[str, str], list[_Event]] = defaultdict(list)
    for event in responses:
        by_protocol_query[(event.protocol, event.query)].append(event)

    response_window = float(policy["response_window_seconds"])
    for (protocol, query), rows in sorted(by_protocol_query.items()):
        rows.sort(key=lambda event: event.timestamp)
        threshold = int(PROTOCOLS[protocol]["multi_responder_threshold"])
        best = _densest_window_distinct_responders(rows, response_window)
        responders = sorted({event.responder for event in best if event.responder})
        if len(responders) < threshold:
            continue

        requesters = sorted({event.requester for event in best if event.requester})
        severity = "medium" if protocol in {"llmnr", "nbt_ns"} else "low"
        confidence = "high" if protocol in {"llmnr", "nbt_ns"} else "medium"
        findings.append(
            Finding(
                title=f"Multiple {_label(protocol)} responders for '{query}'",
                severity=severity,
                confidence=confidence,
                detection_basis="heuristic",
                summary=(
                    f"Observed {len(responders)} distinct hosts responding for the same {_label(protocol)} name '{query}' "
                    f"within {response_window:.0f} seconds. Conflicting responders are consistent with a name-resolution poisoning signal, "
                    "although duplicate legitimate responders or service discovery can produce similar behavior."
                ),
                devices=sorted(set(responders + requesters)),
                services=[_label(protocol)],
                ports=sorted(PROTOCOLS[protocol]["ports"]),
                connection_pairs=_response_pairs(best),
                flows=[event.row for event in best[:MAX_EVIDENCE_ROWS]],
                subnets=_event_segments(best, metadata),
                timestamps=[event.timestamp for event in best[:MAX_EVIDENCE_ROWS]],
                tags=["name-resolution", "poisoning-signal", protocol, "multiple-responders"],
                metadata={
                    "signal": "multiple_responders",
                    "protocol": protocol,
                    "query": query,
                    "distinct_responder_count": len(responders),
                    "responders": responders,
                    "requesters": requesters,
                    "window_seconds": response_window,
                    "evidence_truncated": len(best) > MAX_EVIDENCE_ROWS,
                    "spoofing_confirmed": False,
                },
            )
        )
    return findings


def _responder_fanout_findings(
    events: list[_Event], policy: dict[str, Any], metadata: dict[str, Any]
) -> list[Finding]:
    findings: list[Finding] = []
    responses = [event for event in events if event.explicit_response and event.responder]
    grouped: dict[tuple[str, str], list[_Event]] = defaultdict(list)
    for event in responses:
        grouped[(event.protocol, event.responder or "")].append(event)

    window = float(policy["responder_window_seconds"])
    for (protocol, responder), rows in sorted(grouped.items()):
        rows.sort(key=lambda event: event.timestamp)
        best = _densest_window(rows, window)
        names = sorted({event.query for event in best})
        requesters = sorted({event.requester for event in best if event.requester})
        name_threshold = int(PROTOCOLS[protocol]["responder_name_threshold"])
        requester_threshold = int(PROTOCOLS[protocol]["responder_requester_threshold"])
        if len(names) < name_threshold and len(requesters) < requester_threshold:
            continue

        severity = "medium" if protocol in {"llmnr", "nbt_ns"} else "low"
        confidence = "medium"
        findings.append(
            Finding(
                title=f"Broad {_label(protocol)} response activity from {responder}",
                severity=severity,
                confidence=confidence,
                detection_basis="heuristic",
                summary=(
                    f"Host {responder} produced {_label(protocol)} responses covering {len(names)} unique names and "
                    f"{len(requesters)} requester host(s) within {window:.0f} seconds. A responder claiming many names or answering many "
                    "clients can be consistent with poisoning tooling, but infrastructure, proxies, and legitimate discovery software may also do this."
                ),
                devices=sorted({responder, *requesters}),
                services=[_label(protocol)],
                ports=sorted(PROTOCOLS[protocol]["ports"]),
                connection_pairs=_response_pairs(best),
                flows=[event.row for event in best[:MAX_EVIDENCE_ROWS]],
                subnets=_event_segments(best, metadata),
                timestamps=[event.timestamp for event in best[:MAX_EVIDENCE_ROWS]],
                tags=["name-resolution", "poisoning-signal", protocol, "responder-fanout"],
                metadata={
                    "signal": "responder_fanout",
                    "protocol": protocol,
                    "responder": responder,
                    "unique_name_count": len(names),
                    "unique_requester_count": len(requesters),
                    "window_seconds": window,
                    "evidence_truncated": len(best) > MAX_EVIDENCE_ROWS,
                    "spoofing_confirmed": False,
                },
            )
        )
    return findings


def _densest_window(rows: list[_Event], seconds: float) -> list[_Event]:
    window: deque[_Event] = deque()
    best: list[_Event] = []
    for row in rows:
        window.append(row)
        while window and row.timestamp - window[0].timestamp > seconds:
            window.popleft()
        if len(window) > len(best):
            best = list(window)
    return best


def _densest_window_distinct_responders(rows: list[_Event], seconds: float) -> list[_Event]:
    window: deque[_Event] = deque()
    best: list[_Event] = []
    best_count = 0
    for row in rows:
        window.append(row)
        while window and row.timestamp - window[0].timestamp > seconds:
            window.popleft()
        count = len({item.responder for item in window if item.responder})
        if count > best_count:
            best_count = count
            best = list(window)
    return best


def _pairs(events: Iterable[_Event]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, int | None, str]] = set()
    result: list[dict[str, Any]] = []
    for event in events:
        if not event.source or not event.destination:
            continue
        port = event.destination_port if event.destination_port in PROTOCOLS[event.protocol]["ports"] else event.source_port
        key = (event.source, event.destination, port, event.protocol)
        if key in seen:
            continue
        seen.add(key)
        result.append(
            {
                "source": event.source,
                "destination": event.destination,
                "port": port,
                "protocol": "udp",
                "service": _label(event.protocol),
            }
        )
        if len(result) >= MAX_EVIDENCE_ROWS:
            break
    return result


def _response_pairs(events: Iterable[_Event]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, int]] = set()
    result: list[dict[str, Any]] = []
    for event in events:
        if not event.responder or not event.requester:
            continue
        port = next(iter(PROTOCOLS[event.protocol]["ports"]))
        key = (event.responder, event.requester, port)
        if key in seen:
            continue
        seen.add(key)
        result.append(
            {
                "source": event.responder,
                "destination": event.requester,
                "port": port,
                "protocol": "udp",
                "service": _label(event.protocol),
            }
        )
        if len(result) >= MAX_EVIDENCE_ROWS:
            break
    return result


def _event_segments(events: Iterable[_Event], metadata: dict[str, Any]) -> list[str]:
    segments = metadata.get("segments")
    if not isinstance(segments, list):
        return []
    labels: set[str] = set()
    for event in events:
        for address in (event.source, event.destination, event.responder or "", event.requester or ""):
            segment = _segment_for(address, segments)
            if segment:
                labels.add(segment)
    return sorted(labels)


def _segment_for(address: str, segments: list[Any]) -> str | None:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return None
    best: tuple[int, str] | None = None
    for item in segments:
        if not isinstance(item, dict):
            continue
        cidr = _text(item.get("cidr") or item.get("subnet") or item.get("network"))
        if not cidr:
            continue
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if ip in network:
            label = _text(item.get("name") or item.get("label") or cidr)
            candidate = (network.prefixlen, label)
            if best is None or candidate[0] > best[0]:
                best = candidate
    return best[1] if best else None


def _is_multicast_or_broadcast(address: str) -> bool:
    if address.lower() in MULTICAST_DESTINATIONS or address == "255.255.255.255":
        return True
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return ip.is_multicast


def _label(protocol: str) -> str:
    return {"llmnr": "LLMNR", "nbt_ns": "NBT-NS", "mdns": "mDNS"}[protocol]


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _integer(value: Any) -> int | None:
    try:
        return int(value) if value is not None and str(value).strip() else None
    except (TypeError, ValueError):
        return None


def _number(value: Any) -> float | None:
    try:
        return float(value) if value is not None and str(value).strip() else None
    except (TypeError, ValueError):
        return None


def _boolish(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return _text(value).lower() in {"1", "true", "t", "yes", "y", "response", "reply"}


def _positive_float(value: Any, default: float) -> float:
    parsed = _number(value)
    return parsed if parsed is not None and parsed > 0 else default


def _positive_int(value: Any, default: int) -> int:
    parsed = _integer(value)
    return parsed if parsed is not None and parsed > 0 else int(default)
