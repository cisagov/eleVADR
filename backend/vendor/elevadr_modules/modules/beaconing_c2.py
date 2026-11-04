from __future__ import annotations

from collections import Counter, defaultdict
import ipaddress
import math
import statistics
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata


# Conservative defaults: a beacon needs several repeated observations over time,
# and the timing must be substantially more regular than ordinary user traffic.
MIN_EVENTS = 6
MIN_SPAN_SECONDS = 60.0
MIN_MEDIAN_INTERVAL_SECONDS = 5.0
MAX_MEDIAN_INTERVAL_SECONDS = 6 * 60 * 60.0
MAX_JITTER_RATIO = 0.20
MAX_INTERVAL_CV = 0.30
MAX_EVIDENCE_FLOWS = 100

# Common infrastructure/discovery traffic is periodic by design and would
# otherwise dominate beaconing results in normal enterprise/OT captures.
_EXCLUDED_PORTS = {
    53,    # DNS
    67, 68,  # DHCPv4
    123,   # NTP
    137, 138,  # NetBIOS name/datagram
    161, 162,  # SNMP polling/traps
    1900,  # SSDP
    5353,  # mDNS
    5355,  # LLMNR
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


class BeaconingC2Module(AnalysisModule):
    metadata = ModuleMetadata(
        id="beaconing_c2_communication",
        name="Beaconing / C2 Communication",
        description=(
            "Identifies repeated outbound connections to the same destination at consistent intervals, "
            "a behavioral pattern commonly associated with malware command-and-control check-ins."
        ),
        category="security_analysis",
        required_logs=("conn",),
        default_enabled=True,
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        groups: dict[tuple[str, str, int, str, str], list[dict[str, Any]]] = defaultdict(list)
        skipped_non_outbound = 0
        skipped_expected_periodic = 0
        skipped_missing_fields = 0

        for row in context.connections:
            source = _text(row.get("source_ip", row.get("id.orig_h")))
            destination = _text(row.get("destination_ip", row.get("id.resp_h")))
            port = _as_int(row.get("destination_port", row.get("id.resp_p")))
            protocol = _text(row.get("protocol", row.get("proto"))).lower()
            service = _text(row.get("service")).lower()
            timestamp = _as_float(row.get("timestamp", row.get("ts")))

            if not source or not destination or port is None or timestamp is None or protocol not in {"tcp", "udp"}:
                skipped_missing_fields += 1
                continue
            if not _is_outbound(row, source, destination):
                skipped_non_outbound += 1
                continue
            if _is_expected_periodic(service, port, destination):
                skipped_expected_periodic += 1
                continue

            groups[(source, destination, port, protocol, service)].append(row)

        findings: list[Finding] = []
        candidates_evaluated = 0

        for (source, destination, port, protocol, service), rows in sorted(groups.items()):
            if len(rows) < MIN_EVENTS:
                continue
            candidates_evaluated += 1
            rows = sorted(rows, key=lambda item: _as_float(item.get("timestamp", item.get("ts"))) or 0.0)
            timestamps = sorted(
                {
                    ts
                    for row in rows
                    if (ts := _as_float(row.get("timestamp", row.get("ts")))) is not None
                }
            )
            if len(timestamps) < MIN_EVENTS:
                continue

            intervals = [b - a for a, b in zip(timestamps, timestamps[1:]) if b > a]
            if len(intervals) < MIN_EVENTS - 1:
                continue

            span = timestamps[-1] - timestamps[0]
            median_interval = statistics.median(intervals)
            if span < MIN_SPAN_SECONDS:
                continue
            if not (MIN_MEDIAN_INTERVAL_SECONDS <= median_interval <= MAX_MEDIAN_INTERVAL_SECONDS):
                continue

            jitter_ratio = _median_relative_jitter(intervals, median_interval)
            cv = _coefficient_of_variation(intervals)
            if jitter_ratio > MAX_JITTER_RATIO or cv > MAX_INTERVAL_CV:
                continue

            event_count = len(timestamps)
            confidence = "high" if (
                event_count >= 10 and jitter_ratio <= 0.08 and cv <= 0.12
            ) else "medium"
            service_label = service or f"{protocol}/{port}"
            state_counts = Counter(
                _text(row.get("zeek_state", row.get("conn_state"))) or "unknown"
                for row in rows
            )
            evidence_rows = rows[:MAX_EVIDENCE_FLOWS]
            truncated = len(rows) > MAX_EVIDENCE_FLOWS

            findings.append(
                Finding(
                    title="Periodic outbound beaconing pattern observed",
                    severity="medium",
                    confidence=confidence,
                    detection_basis="heuristic",
                    summary=(
                        f"Observed {event_count} outbound connection events from {source} to "
                        f"{destination}:{port}/{protocol} with a median interval of "
                        f"{median_interval:.1f} seconds and {jitter_ratio * 100:.1f}% median timing jitter. "
                        "The regular timing is consistent with automated beaconing/C2 check-in behavior, "
                        "but is not by itself proof of malware."
                    ),
                    devices=sorted({source, destination}),
                    services=[service_label],
                    ports=[port],
                    connection_pairs=[
                        {
                            "source": source,
                            "destination": destination,
                            "port": port,
                            "protocol": protocol,
                            "service": service_label,
                        }
                    ],
                    flows=evidence_rows,
                    subnets=[],
                    timestamps=timestamps[:MAX_EVIDENCE_FLOWS],
                    tags=["beaconing", "c2", "periodic-outbound"],
                    metadata={
                        "event_count": event_count,
                        "interval_count": len(intervals),
                        "observation_span_seconds": round(span, 3),
                        "median_interval_seconds": round(median_interval, 3),
                        "minimum_interval_seconds": round(min(intervals), 3),
                        "maximum_interval_seconds": round(max(intervals), 3),
                        "median_jitter_ratio": round(jitter_ratio, 6),
                        "interval_coefficient_of_variation": round(cv, 6),
                        "zeek_state_counts": dict(sorted(state_counts.items())),
                        "destination_is_public": _is_public_ip(destination),
                        "evidence_flow_count": len(evidence_rows),
                        "evidence_truncated": truncated,
                        "thresholds": {
                            "minimum_events": MIN_EVENTS,
                            "minimum_span_seconds": MIN_SPAN_SECONDS,
                            "minimum_median_interval_seconds": MIN_MEDIAN_INTERVAL_SECONDS,
                            "maximum_median_interval_seconds": MAX_MEDIAN_INTERVAL_SECONDS,
                            "maximum_median_jitter_ratio": MAX_JITTER_RATIO,
                            "maximum_interval_coefficient_of_variation": MAX_INTERVAL_CV,
                        },
                    },
                )
            )

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "beaconing_findings": len(findings),
                "candidate_connection_groups_evaluated": candidates_evaluated,
                "affected_source_devices": len({f.connection_pairs[0]["source"] for f in findings}),
                "affected_destinations": len({f.connection_pairs[0]["destination"] for f in findings}),
            },
            evidence={
                "inspected_logs": ["conn"],
                "skipped_non_outbound_flows": skipped_non_outbound,
                "skipped_expected_periodic_flows": skipped_expected_periodic,
                "skipped_missing_required_fields": skipped_missing_fields,
                "excluded_periodic_ports": sorted(_EXCLUDED_PORTS),
                "excluded_periodic_services": sorted(_EXCLUDED_SERVICES),
                "notes": [
                    "Outbound direction prefers Zeek local_orig/local_resp flags when available and otherwise falls back to private-source/public-destination inference.",
                    "Common infrastructure/discovery protocols such as DNS, NTP, DHCP, mDNS, LLMNR, SSDP, NetBIOS, and SNMP are excluded by default because periodic traffic is expected for them.",
                    "Beaconing is a behavioral heuristic. A finding indicates suspicious periodicity and should be correlated with destination reputation, process/asset context, and other evidence before labeling activity as command-and-control.",
                ],
            },
            warnings=[],
        )


def _is_expected_periodic(service: str, port: int, destination: str) -> bool:
    if service in _EXCLUDED_SERVICES or port in _EXCLUDED_PORTS:
        return True
    try:
        ip = ipaddress.ip_address(destination)
        return ip.is_multicast or ip.is_unspecified
    except ValueError:
        return False


def _is_outbound(row: dict[str, Any], source: str, destination: str) -> bool:
    local_orig = _truth_value(row.get("local_orig"))
    local_resp = _truth_value(row.get("local_resp"))
    if local_orig is True and local_resp is False:
        return True
    if local_orig is False and local_resp is True:
        return False
    if local_orig is True and local_resp is True:
        return False

    try:
        source_ip = ipaddress.ip_address(source)
        destination_ip = ipaddress.ip_address(destination)
    except ValueError:
        return False
    return source_ip.is_private and destination_ip.is_global


def _truth_value(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in {"t", "true", "1", "yes"}:
        return True
    if text in {"f", "false", "0", "no"}:
        return False
    return None


def _median_relative_jitter(intervals: list[float], median_interval: float) -> float:
    if median_interval <= 0:
        return math.inf
    deviations = [abs(value - median_interval) for value in intervals]
    return statistics.median(deviations) / median_interval


def _coefficient_of_variation(intervals: list[float]) -> float:
    if not intervals:
        return math.inf
    mean = statistics.fmean(intervals)
    if mean <= 0:
        return math.inf
    if len(intervals) == 1:
        return 0.0
    return statistics.pstdev(intervals) / mean


def _is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


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
