from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import ipaddress
import math
import statistics
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata


DEFAULT_MIN_EVENTS = 12
DEFAULT_MIN_SPAN_SECONDS = 60.0
DEFAULT_MAX_MEDIAN_INTERVAL_SECONDS = 300.0
DEFAULT_MAX_INTERVAL_CV = 0.20
DEFAULT_MAX_INTERVAL_MAD_RATIO = 0.15
DEFAULT_UNIFORM_SIZE_RATIO = 0.90
DEFAULT_SIZE_TOLERANCE_BYTES = 4
DEFAULT_MIN_MEAN_SIZE_BYTES = 32
DEFAULT_HIGH_EVENT_COUNT = 100
MAX_EVIDENCE_FLOWS = 10


@dataclass(slots=True)
class _Segment:
    cidr: str
    name: str
    trust_zone: str
    role: str
    network: ipaddress._BaseNetwork


@dataclass(slots=True)
class _Event:
    row: dict[str, Any]
    source: str
    destination: str
    timestamp: float
    size: int
    icmp_type: int | None
    external: bool
    unexpected: bool
    source_segment: _Segment | None
    destination_segment: _Segment | None


class IcmpDataChannelModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="icmp_data_channel",
        name="ICMP as Data Channel",
        description=(
            "Identifies sustained ICMPv4 echo traffic with unusually uniform packet sizes and regular timing "
            "to external or explicitly unexpected destinations."
        ),
        category="security_analysis",
        required_logs=("conn",),
        default_enabled=True,
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        policy = _policy(context.metadata)
        segments = _load_segments(context.metadata)
        groups: dict[tuple[str, str], list[_Event]] = defaultdict(list)

        icmp_rows = 0
        echo_rows = 0
        skipped_non_echo = 0
        skipped_missing_fields = 0
        skipped_non_external_or_expected = 0
        skipped_special_destination = 0

        for row in context.connections:
            if not _is_icmpv4(row):
                continue
            icmp_rows += 1

            source = _text(row.get("source_ip", row.get("id.orig_h")))
            destination = _text(row.get("destination_ip", row.get("id.resp_h")))
            timestamp = _as_float(row.get("timestamp", row.get("ts")))
            size = _event_size(row)
            if not source or not destination or timestamp is None or size is None:
                skipped_missing_fields += 1
                continue

            if _is_special_destination(destination):
                skipped_special_destination += 1
                continue

            icmp_type = _icmp_type(row)
            if icmp_type is not None and icmp_type not in {0, 8}:
                skipped_non_echo += 1
                continue
            echo_rows += 1

            src_segment = _segment_for_ip(source, segments)
            dst_segment = _segment_for_ip(destination, segments)
            external = _is_external_destination(row, destination, dst_segment)
            unexpected = _is_unexpected_destination(src_segment, dst_segment, destination, segments)
            if not external and not unexpected:
                skipped_non_external_or_expected += 1
                continue

            groups[(source, destination)].append(
                _Event(
                    row=row,
                    source=source,
                    destination=destination,
                    timestamp=timestamp,
                    size=size,
                    icmp_type=icmp_type,
                    external=external,
                    unexpected=unexpected,
                    source_segment=src_segment,
                    destination_segment=dst_segment,
                )
            )

        findings: list[Finding] = []
        evaluated_groups = 0
        rejected_event_count = 0
        rejected_span = 0
        rejected_size = 0
        rejected_timing = 0

        for (source, destination), events in sorted(groups.items()):
            events.sort(key=lambda event: event.timestamp)
            evaluated_groups += 1
            if len(events) < int(policy["minimum_events"]):
                rejected_event_count += 1
                continue

            span = events[-1].timestamp - events[0].timestamp
            if span < float(policy["minimum_span_seconds"]):
                rejected_span += 1
                continue

            sizes = [event.size for event in events]
            median_size = float(statistics.median(sizes))
            mean_size = float(statistics.fmean(sizes))
            if mean_size < float(policy["minimum_mean_size_bytes"]):
                rejected_size += 1
                continue
            tolerance = int(policy["size_tolerance_bytes"])
            uniform_count = sum(abs(size - median_size) <= tolerance for size in sizes)
            uniform_ratio = uniform_count / len(sizes)
            size_cv = _coefficient_of_variation(sizes)
            if uniform_ratio < float(policy["uniform_size_ratio"]):
                rejected_size += 1
                continue

            intervals = [
                events[index].timestamp - events[index - 1].timestamp
                for index in range(1, len(events))
                if events[index].timestamp > events[index - 1].timestamp
            ]
            if len(intervals) < max(2, int(policy["minimum_events"]) - 2):
                rejected_timing += 1
                continue
            median_interval = float(statistics.median(intervals))
            if median_interval <= 0 or median_interval > float(policy["maximum_median_interval_seconds"]):
                rejected_timing += 1
                continue

            interval_cv = _coefficient_of_variation(intervals)
            interval_mad = _median_absolute_deviation(intervals)
            interval_mad_ratio = interval_mad / median_interval if median_interval else math.inf
            if (
                interval_cv > float(policy["maximum_interval_cv"])
                and interval_mad_ratio > float(policy["maximum_interval_mad_ratio"])
            ):
                rejected_timing += 1
                continue

            representative = events[:MAX_EVIDENCE_FLOWS]
            external = any(event.external for event in events)
            unexpected = any(event.unexpected for event in events)
            src_segment = events[0].source_segment
            dst_segment = events[0].destination_segment
            source_role = _segment_role(src_segment)

            severity = "medium"
            if (
                len(events) >= int(policy["high_event_count"])
                and external
                and source_role in {"ot", "control", "ics", "scada", "operations"}
            ):
                severity = "high"

            destination_context = []
            if external:
                destination_context.append("external")
            if unexpected:
                destination_context.append("unexpected/cross-segment")
            context_text = " and ".join(destination_context) or "unexpected"

            findings.append(
                Finding(
                    title=f"Sustained regular ICMP pattern: {source} -> {destination}",
                    severity=severity,
                    summary=(
                        f"Observed {len(events)} ICMP echo connection record(s) from {source} to {destination} "
                        f"over {span:.1f} seconds. Packet sizes were highly uniform ({uniform_ratio:.0%} within "
                        f"±{tolerance} bytes of the median) and timing was regular (median interval "
                        f"{median_interval:.2f}s, interval CV {interval_cv:.3f}). The destination is {context_text}. "
                        "This pattern can be consistent with an ICMP data channel or beacon, but scheduled monitoring "
                        "and diagnostic traffic can produce similar behavior; corroborate with payload inspection and host context."
                    ),
                    confidence="medium",
                    detection_basis="heuristic",
                    devices=sorted({source, destination}),
                    services=["ICMP"],
                    ports=[],
                    connection_pairs=[
                        {
                            "source": source,
                            "destination": destination,
                            "port": None,
                            "protocol": "icmp",
                            "service": "ICMP echo",
                        }
                    ],
                    flows=[event.row for event in representative],
                    subnets=_subnets(src_segment, dst_segment),
                    timestamps=[event.timestamp for event in representative],
                    tags=_tags(external, unexpected, source_role),
                    metadata={
                        "event_count": len(events),
                        "evidence_event_count": len(representative),
                        "evidence_truncated": len(events) > len(representative),
                        "duration_seconds": span,
                        "median_packet_size_bytes": median_size,
                        "mean_packet_size_bytes": mean_size,
                        "packet_size_cv": size_cv,
                        "uniform_size_ratio": uniform_ratio,
                        "size_tolerance_bytes": tolerance,
                        "median_interval_seconds": median_interval,
                        "interval_cv": interval_cv,
                        "interval_mad_seconds": interval_mad,
                        "interval_mad_ratio": interval_mad_ratio,
                        "external_destination": external,
                        "unexpected_destination": unexpected,
                        "source_segment": src_segment.name if src_segment else None,
                        "destination_segment": dst_segment.name if dst_segment else None,
                        "source_trust_zone": src_segment.trust_zone if src_segment else None,
                        "destination_trust_zone": dst_segment.trust_zone if dst_segment else None,
                        "source_role": source_role or None,
                        "data_channel_confirmed": False,
                    },
                )
            )

        affected = sorted({device for finding in findings for device in finding.devices})
        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "icmp_rows_evaluated": icmp_rows,
                "icmp_echo_rows_evaluated": echo_rows,
                "candidate_destination_pairs": len(groups),
                "timing_size_groups_evaluated": evaluated_groups,
                "icmp_data_channel_findings": len(findings),
                "affected_devices": len(affected),
            },
            evidence={
                "inspected_logs": ["conn"] if context.connections else [],
                "skipped_non_echo_icmp": skipped_non_echo,
                "skipped_missing_timestamp_size_or_endpoint": skipped_missing_fields,
                "skipped_special_destinations": skipped_special_destination,
                "skipped_expected_internal_destinations": skipped_non_external_or_expected,
                "rejected_for_event_count": rejected_event_count,
                "rejected_for_short_duration": rejected_span,
                "rejected_for_nonuniform_or_small_size": rejected_size,
                "rejected_for_irregular_timing": rejected_timing,
                "policy": policy,
                "notes": [
                    "The detector evaluates ICMPv4 echo-style traffic only; IPv6 neighbor/router discovery and non-echo ICMP types are not treated as data-channel candidates.",
                    "A finding requires sustained activity, highly uniform observed packet/byte size, and regular inter-arrival timing; ICMP presence alone is never sufficient.",
                    "Destinations must be external or explicitly unexpected relative to configured segment metadata. Private same-segment traffic is not flagged merely for being periodic.",
                    "When Zeek orig_bytes is unavailable, the detector can use average orig_ip_bytes per originator packet as a size proxy; this is behavioral evidence rather than payload inspection.",
                    "Regular ICMP may be legitimate health monitoring, keepalive, or diagnostics. Findings do not independently confirm tunneling, command-and-control, or exfiltration.",
                ],
            },
            warnings=[],
        )


def _policy(metadata: dict[str, Any]) -> dict[str, Any]:
    raw = metadata.get("icmp_data_channel_policy") or {}
    if not isinstance(raw, dict):
        raw = {}
    return {
        "minimum_events": _positive_int(raw.get("minimum_events"), DEFAULT_MIN_EVENTS),
        "minimum_span_seconds": _positive_float(raw.get("minimum_span_seconds"), DEFAULT_MIN_SPAN_SECONDS),
        "maximum_median_interval_seconds": _positive_float(raw.get("maximum_median_interval_seconds"), DEFAULT_MAX_MEDIAN_INTERVAL_SECONDS),
        "maximum_interval_cv": _nonnegative_float(raw.get("maximum_interval_cv"), DEFAULT_MAX_INTERVAL_CV),
        "maximum_interval_mad_ratio": _nonnegative_float(raw.get("maximum_interval_mad_ratio"), DEFAULT_MAX_INTERVAL_MAD_RATIO),
        "uniform_size_ratio": _bounded_ratio(raw.get("uniform_size_ratio"), DEFAULT_UNIFORM_SIZE_RATIO),
        "size_tolerance_bytes": _positive_int(raw.get("size_tolerance_bytes"), DEFAULT_SIZE_TOLERANCE_BYTES),
        "minimum_mean_size_bytes": _positive_int(raw.get("minimum_mean_size_bytes"), DEFAULT_MIN_MEAN_SIZE_BYTES),
        "high_event_count": _positive_int(raw.get("high_event_count"), DEFAULT_HIGH_EVENT_COUNT),
    }


def _is_icmpv4(row: dict[str, Any]) -> bool:
    proto = _text(row.get("protocol", row.get("proto"))).lower()
    ip_proto = _as_int(row.get("ip_proto"))
    if ip_proto == 58 or proto in {"icmp6", "icmpv6"}:
        return False
    return proto == "icmp" or ip_proto == 1


def _icmp_type(row: dict[str, Any]) -> int | None:
    for key in ("icmp_type", "type", "source_port", "id.orig_p"):
        value = _as_int(row.get(key))
        if value is not None:
            return value
    return None


def _event_size(row: dict[str, Any]) -> int | None:
    for key in ("source_bytes", "orig_bytes"):
        value = _as_int(row.get(key))
        if value is not None and value > 0:
            return value
    ip_bytes = _as_int(row.get("orig_ip_bytes"))
    packets = _as_int(row.get("source_packets", row.get("orig_pkts")))
    if ip_bytes is not None and ip_bytes > 0 and packets is not None and packets > 0:
        return max(1, int(round(ip_bytes / packets)))
    if ip_bytes is not None and ip_bytes > 0:
        return ip_bytes
    return None


def _is_external_destination(row: dict[str, Any], destination: str, dst_segment: _Segment | None) -> bool:
    local_resp = _truth_state(row.get("local_resp"))
    local_orig = _truth_state(row.get("local_orig"))
    if local_orig is True and local_resp is False:
        return True
    if local_resp is True or dst_segment is not None:
        return False
    try:
        address = ipaddress.ip_address(destination)
    except ValueError:
        return False
    return not (address.is_private or address.is_loopback or address.is_link_local or address.is_multicast or address.is_reserved)


def _is_unexpected_destination(
    src_segment: _Segment | None,
    dst_segment: _Segment | None,
    destination: str,
    segments: list[_Segment],
) -> bool:
    if src_segment and dst_segment:
        if src_segment.network == dst_segment.network:
            return False
        if src_segment.trust_zone and dst_segment.trust_zone:
            return src_segment.trust_zone != dst_segment.trust_zone
        return src_segment.name != dst_segment.name
    if src_segment and not dst_segment and segments:
        try:
            address = ipaddress.ip_address(destination)
        except ValueError:
            return False
        return address.is_private
    return False


def _load_segments(metadata: dict[str, Any]) -> list[_Segment]:
    raw = metadata.get("segments") or metadata.get("network_segments") or []
    if not isinstance(raw, list):
        return []
    segments: list[_Segment] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        cidr = _text(item.get("cidr") or item.get("subnet") or item.get("network"))
        if not cidr:
            continue
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        name = _text(item.get("name") or item.get("segment") or cidr)
        trust_zone = _text(item.get("trust_zone") or item.get("security_zone") or item.get("zone")).lower()
        role = _text(item.get("role") or item.get("segment_role") or item.get("type")).lower()
        segments.append(_Segment(cidr=cidr, name=name, trust_zone=trust_zone, role=role, network=network))
    segments.sort(key=lambda segment: segment.network.prefixlen, reverse=True)
    return segments


def _segment_for_ip(value: str, segments: list[_Segment]) -> _Segment | None:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    for segment in segments:
        if address in segment.network:
            return segment
    return None


def _segment_role(segment: _Segment | None) -> str:
    if not segment:
        return ""
    text = f"{segment.role} {segment.trust_zone} {segment.name}".lower()
    for role in ("scada", "ics", "control", "ot", "operations", "enterprise", "it"):
        if role in text:
            return role
    return segment.role or segment.trust_zone


def _subnets(src: _Segment | None, dst: _Segment | None) -> list[str]:
    return sorted({segment.cidr for segment in (src, dst) if segment is not None})


def _tags(external: bool, unexpected: bool, source_role: str) -> list[str]:
    tags = ["icmp", "data-channel", "regular-timing", "uniform-size"]
    if external:
        tags.append("external-destination")
    if unexpected:
        tags.append("unexpected-destination")
    if source_role in {"ot", "control", "ics", "scada", "operations"}:
        tags.append("ot-source")
    return tags


def _is_special_destination(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return True
    return address.is_multicast or address.is_loopback or address.is_unspecified or address.is_link_local


def _coefficient_of_variation(values: list[int] | list[float]) -> float:
    if not values:
        return math.inf
    mean = statistics.fmean(values)
    if mean == 0:
        return 0.0 if all(value == 0 for value in values) else math.inf
    return float(statistics.pstdev(values) / mean)


def _median_absolute_deviation(values: list[float]) -> float:
    if not values:
        return math.inf
    median = statistics.median(values)
    return float(statistics.median(abs(value - median) for value in values))


def _truth_state(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    text = _text(value).lower()
    if text in {"t", "true", "1", "yes", "y"}:
        return True
    if text in {"f", "false", "0", "no", "n"}:
        return False
    return None


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _as_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def _as_float(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _positive_int(value: Any, default: int) -> int:
    parsed = _as_int(value)
    return parsed if parsed is not None and parsed > 0 else default


def _positive_float(value: Any, default: float) -> float:
    parsed = _as_float(value)
    return parsed if parsed is not None and parsed > 0 else default


def _nonnegative_float(value: Any, default: float) -> float:
    parsed = _as_float(value)
    return parsed if parsed is not None and parsed >= 0 else default


def _bounded_ratio(value: Any, default: float) -> float:
    parsed = _as_float(value)
    return parsed if parsed is not None and 0 < parsed <= 1 else default
