from __future__ import annotations

from collections import Counter, defaultdict
import ipaddress
from typing import Any, Callable

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata


WINDOW_SECONDS = 10.0
PORT_SCAN_MIN_DISTINCT_PORTS = 10
HOST_SWEEP_MIN_DISTINCT_HOSTS = 10
HIGH_CONFIDENCE_DISTINCT_COUNT = 20
HIGH_CONFIDENCE_FAILED_RATIO = 0.70
MAX_EVIDENCE_FLOWS = 200

# These are common infrastructure/discovery patterns that can legitimately fan
# out and otherwise look scan-like in packet captures.
_EXCLUDED_PORTS = {
    53,      # DNS
    67, 68,  # DHCPv4
    123,     # NTP
    137, 138,  # NetBIOS name/datagram
    161, 162,  # SNMP
    1900,    # SSDP
    5353,    # mDNS
    5355,    # LLMNR
    546, 547,  # DHCPv6
}
_EXCLUDED_SERVICES = {
    "dns",
    "ntp",
    "dhcp",
    "mdns",
    "llmnr",
    "ssdp",
    "nbns",
    "netbios_ns",
    "netbios_dgm",
}

_FAILED_STATES = {
    "S0",     # SYN seen, no reply
    "REJ",    # connection rejected
    "RSTO",   # originator reset
    "RSTR",   # responder reset
    "RSTOS0",
    "RSTRH",
    "SH",
    "SHR",
}


class PortHostScanningModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="port_host_scanning",
        name="Port / Host Scanning",
        description=(
            "Identifies rapid connection attempts from a single source to many ports on one host "
            "(port scan) or to many hosts on the same service/port (host sweep)."
        ),
        category="security_analysis",
        required_logs=("conn",),
        default_enabled=True,
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        normalized: list[dict[str, Any]] = []
        skipped_missing_fields = 0
        skipped_non_unicast = 0

        for row in context.connections:
            source = _text(row.get("source_ip", row.get("id.orig_h")))
            destination = _text(row.get("destination_ip", row.get("id.resp_h")))
            port = _as_int(row.get("destination_port", row.get("id.resp_p")))
            protocol = _text(row.get("protocol", row.get("proto"))).lower()
            timestamp = _as_float(row.get("timestamp", row.get("ts")))
            service = _text(row.get("service")).lower()

            if not source or not destination or port is None or timestamp is None or protocol not in {"tcp", "udp"}:
                skipped_missing_fields += 1
                continue
            if not _is_unicast_address(destination):
                skipped_non_unicast += 1
                continue

            normalized.append(
                {
                    "row": row,
                    "source": source,
                    "destination": destination,
                    "port": port,
                    "protocol": protocol,
                    "service": service,
                    "timestamp": timestamp,
                }
            )

        findings: list[Finding] = []
        port_scan_groups_evaluated = 0
        host_sweep_groups_evaluated = 0

        # Port scan: one source rapidly touches many destination ports on one host.
        by_src_dst_proto: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
        for item in normalized:
            by_src_dst_proto[(item["source"], item["destination"], item["protocol"])].append(item)

        for (source, destination, protocol), items in sorted(by_src_dst_proto.items()):
            if len({item["port"] for item in items}) < PORT_SCAN_MIN_DISTINCT_PORTS:
                continue
            port_scan_groups_evaluated += 1
            window = _best_window(
                items,
                distinct_key=lambda item: item["port"],
                minimum_distinct=PORT_SCAN_MIN_DISTINCT_PORTS,
            )
            if window is None:
                continue
            findings.append(_port_scan_finding(source, destination, protocol, window))

        # Host sweep: one source rapidly touches many destination hosts on the same port/protocol.
        by_src_port_proto: dict[tuple[str, int, str], list[dict[str, Any]]] = defaultdict(list)
        skipped_expected_fanout = 0
        for item in normalized:
            if item["port"] in _EXCLUDED_PORTS or item["service"] in _EXCLUDED_SERVICES:
                skipped_expected_fanout += 1
                continue
            by_src_port_proto[(item["source"], item["port"], item["protocol"])].append(item)

        for (source, port, protocol), items in sorted(by_src_port_proto.items()):
            if len({item["destination"] for item in items}) < HOST_SWEEP_MIN_DISTINCT_HOSTS:
                continue
            host_sweep_groups_evaluated += 1
            window = _best_window(
                items,
                distinct_key=lambda item: item["destination"],
                minimum_distinct=HOST_SWEEP_MIN_DISTINCT_HOSTS,
            )
            if window is None:
                continue
            findings.append(_host_sweep_finding(source, port, protocol, window))

        port_scan_count = sum("port-scan" in finding.tags for finding in findings)
        host_sweep_count = sum("host-sweep" in finding.tags for finding in findings)

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "scan_findings": len(findings),
                "port_scan_findings": port_scan_count,
                "host_sweep_findings": host_sweep_count,
                "port_scan_groups_evaluated": port_scan_groups_evaluated,
                "host_sweep_groups_evaluated": host_sweep_groups_evaluated,
                "affected_sources": len({finding.connection_pairs[0]["source"] for finding in findings if finding.connection_pairs}),
            },
            evidence={
                "inspected_logs": ["conn"],
                "skipped_missing_required_fields": skipped_missing_fields,
                "skipped_non_unicast_destinations": skipped_non_unicast,
                "skipped_expected_fanout_flows": skipped_expected_fanout,
                "excluded_fanout_ports": sorted(_EXCLUDED_PORTS),
                "excluded_fanout_services": sorted(_EXCLUDED_SERVICES),
                "thresholds": {
                    "window_seconds": WINDOW_SECONDS,
                    "minimum_distinct_ports_for_port_scan": PORT_SCAN_MIN_DISTINCT_PORTS,
                    "minimum_distinct_hosts_for_host_sweep": HOST_SWEEP_MIN_DISTINCT_HOSTS,
                    "high_confidence_distinct_count": HIGH_CONFIDENCE_DISTINCT_COUNT,
                    "high_confidence_failed_ratio": HIGH_CONFIDENCE_FAILED_RATIO,
                },
                "notes": [
                    "Port scans are detected when one source rapidly contacts many destination ports on the same host.",
                    "Host sweeps are detected when one source rapidly contacts many destination hosts on the same destination port/protocol.",
                    "Common discovery and infrastructure fan-out traffic is excluded from host-sweep detection by default.",
                    "Scanning is a behavioral heuristic; legitimate vulnerability scanners, inventory tools, and management systems can generate the same pattern.",
                ],
            },
            warnings=[],
        )


def _best_window(
    items: list[dict[str, Any]],
    *,
    distinct_key: Callable[[dict[str, Any]], Any],
    minimum_distinct: int,
) -> list[dict[str, Any]] | None:
    ordered = sorted(items, key=lambda item: item["timestamp"])
    left = 0
    best: list[dict[str, Any]] | None = None
    counts: Counter[Any] = Counter()

    for right, item in enumerate(ordered):
        counts[distinct_key(item)] += 1
        while item["timestamp"] - ordered[left]["timestamp"] > WINDOW_SECONDS:
            old_key = distinct_key(ordered[left])
            counts[old_key] -= 1
            if counts[old_key] <= 0:
                del counts[old_key]
            left += 1

        if len(counts) >= minimum_distinct:
            candidate = ordered[left : right + 1]
            if best is None:
                best = candidate
            else:
                candidate_distinct = len({distinct_key(x) for x in candidate})
                best_distinct = len({distinct_key(x) for x in best})
                if candidate_distinct > best_distinct or (
                    candidate_distinct == best_distinct and len(candidate) > len(best)
                ):
                    best = candidate
    return best


def _port_scan_finding(
    source: str,
    destination: str,
    protocol: str,
    items: list[dict[str, Any]],
) -> Finding:
    ports = sorted({item["port"] for item in items})
    timestamps = sorted(item["timestamp"] for item in items)
    failed_ratio = _failed_ratio(items)
    confidence = _scan_confidence(len(ports), failed_ratio)
    severity = "high" if confidence == "high" and len(ports) >= HIGH_CONFIDENCE_DISTINCT_COUNT else "medium"
    span = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0.0
    evidence_items = items[:MAX_EVIDENCE_FLOWS]

    return Finding(
        title="Rapid multi-port scan observed",
        severity=severity,
        confidence=confidence,
        detection_basis="heuristic",
        summary=(
            f"Source {source} attempted connections to {len(ports)} distinct destination ports on "
            f"{destination} over {span:.2f} seconds. {failed_ratio * 100:.1f}% of observed attempts "
            "used Zeek states commonly associated with failed or incomplete connections. The pattern "
            "is consistent with port scanning but may also be produced by authorized discovery or vulnerability-scanning tools."
        ),
        devices=sorted({source, destination}),
        services=[f"{protocol} multi-port scan"],
        ports=ports,
        connection_pairs=[
            {
                "source": source,
                "destination": destination,
                "port": item["port"],
                "protocol": protocol,
                "service": item["service"] or f"{protocol}/{item['port']}",
            }
            for item in _unique_by(items, lambda item: item["port"])
        ],
        flows=[item["row"] for item in evidence_items],
        subnets=[],
        timestamps=timestamps[:MAX_EVIDENCE_FLOWS],
        tags=["scan", "port-scan", "reconnaissance"],
        metadata={
            "scan_type": "port_scan",
            "source": source,
            "destination": destination,
            "protocol": protocol,
            "distinct_ports": len(ports),
            "event_count": len(items),
            "window_span_seconds": round(span, 6),
            "failed_or_incomplete_ratio": round(failed_ratio, 6),
            "zeek_state_counts": dict(sorted(_state_counts(items).items())),
            "evidence_flow_count": len(evidence_items),
            "evidence_truncated": len(items) > MAX_EVIDENCE_FLOWS,
        },
    )


def _host_sweep_finding(source: str, port: int, protocol: str, items: list[dict[str, Any]]) -> Finding:
    destinations = sorted({item["destination"] for item in items})
    timestamps = sorted(item["timestamp"] for item in items)
    failed_ratio = _failed_ratio(items)
    confidence = _scan_confidence(len(destinations), failed_ratio)
    severity = "high" if confidence == "high" and len(destinations) >= HIGH_CONFIDENCE_DISTINCT_COUNT else "medium"
    span = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0.0
    evidence_items = items[:MAX_EVIDENCE_FLOWS]
    services = sorted({item["service"] for item in items if item["service"]})
    service_label = services[0] if len(services) == 1 else f"{protocol}/{port}"

    return Finding(
        title="Rapid host sweep observed",
        severity=severity,
        confidence=confidence,
        detection_basis="heuristic",
        summary=(
            f"Source {source} attempted connections to {len(destinations)} distinct destination hosts on "
            f"{service_label} ({port}/{protocol}) over {span:.2f} seconds. {failed_ratio * 100:.1f}% of "
            "observed attempts used Zeek states commonly associated with failed or incomplete connections. "
            "The pattern is consistent with host discovery or service sweeping but may also be generated by authorized management or scanning tools."
        ),
        devices=sorted({source, *destinations}),
        services=[service_label],
        ports=[port],
        connection_pairs=[
            {
                "source": source,
                "destination": item["destination"],
                "port": port,
                "protocol": protocol,
                "service": item["service"] or service_label,
            }
            for item in _unique_by(items, lambda item: item["destination"])
        ],
        flows=[item["row"] for item in evidence_items],
        subnets=[],
        timestamps=timestamps[:MAX_EVIDENCE_FLOWS],
        tags=["scan", "host-sweep", "reconnaissance"],
        metadata={
            "scan_type": "host_sweep",
            "source": source,
            "destination_port": port,
            "protocol": protocol,
            "distinct_hosts": len(destinations),
            "event_count": len(items),
            "window_span_seconds": round(span, 6),
            "failed_or_incomplete_ratio": round(failed_ratio, 6),
            "zeek_state_counts": dict(sorted(_state_counts(items).items())),
            "evidence_flow_count": len(evidence_items),
            "evidence_truncated": len(items) > MAX_EVIDENCE_FLOWS,
        },
    )


def _scan_confidence(distinct_count: int, failed_ratio: float) -> str:
    if distinct_count >= HIGH_CONFIDENCE_DISTINCT_COUNT or failed_ratio >= HIGH_CONFIDENCE_FAILED_RATIO:
        return "high"
    return "medium"


def _failed_ratio(items: list[dict[str, Any]]) -> float:
    if not items:
        return 0.0
    failed = sum(
        1
        for item in items
        if _text(item["row"].get("zeek_state", item["row"].get("conn_state"))).upper() in _FAILED_STATES
    )
    return failed / len(items)


def _state_counts(items: list[dict[str, Any]]) -> Counter[str]:
    return Counter(
        _text(item["row"].get("zeek_state", item["row"].get("conn_state"))).upper() or "UNKNOWN"
        for item in items
    )


def _unique_by(items: list[dict[str, Any]], key: Callable[[dict[str, Any]], Any]) -> list[dict[str, Any]]:
    seen: set[Any] = set()
    result: list[dict[str, Any]] = []
    for item in items:
        value = key(item)
        if value in seen:
            continue
        seen.add(value)
        result.append(item)
    return result


def _is_unicast_address(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (ip.is_multicast or ip.is_unspecified)


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _as_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _as_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
