from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import ipaddress
import statistics
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata


MIB = 1024 * 1024
GIB = 1024 * MIB
DEFAULT_MIN_EXTERNAL_BYTES = 10 * MIB
DEFAULT_MIN_TRUST_BOUNDARY_BYTES = 5 * MIB
DEFAULT_ALWAYS_REPORT_BYTES = 100 * MIB
DEFAULT_HIGH_SEVERITY_BYTES = 1 * GIB
DEFAULT_MIN_BASELINE_FLOWS = 10
DEFAULT_MEDIAN_MULTIPLIER = 5.0
DEFAULT_MAD_MULTIPLIER = 6.0
MAX_EVIDENCE_FLOWS = 10


@dataclass(slots=True)
class _Segment:
    cidr: str
    name: str
    trust_zone: str
    network: ipaddress._BaseNetwork


@dataclass(slots=True)
class _Candidate:
    row: dict[str, Any]
    source: str
    destination: str
    destination_port: int | None
    protocol: str
    service: str
    source_bytes: int
    timestamp: Any
    external: bool
    trust_boundary: bool
    source_zone: str | None
    destination_zone: str | None


class UnusualOutboundDataVolumeModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="unusual_outbound_data_volume",
        name="Unusual Outbound Data Volume",
        description=(
            "Identifies connections with unusually large Zeek orig_bytes leaving local networks, "
            "especially to external destinations or across explicitly configured trust boundaries."
        ),
        category="security_analysis",
        required_logs=("conn",),
        default_enabled=True,
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        policy = _policy(context.metadata)
        segments = _load_segments(context.metadata)
        candidates: list[_Candidate] = []
        outbound_baselines: dict[str, list[int]] = defaultdict(list)
        skipped_non_outbound = 0
        skipped_missing_bytes = 0
        skipped_multicast_or_special = 0
        skipped_not_external_or_boundary = 0

        for row in context.connections:
            source = _text(row.get("source_ip", row.get("id.orig_h")))
            destination = _text(row.get("destination_ip", row.get("id.resp_h")))
            source_bytes = _as_int(row.get("source_bytes", row.get("orig_bytes")))
            if not source or not destination or source_bytes is None or source_bytes < 0:
                skipped_missing_bytes += 1
                continue
            if _is_multicast_or_special(destination):
                skipped_multicast_or_special += 1
                continue
            if not _is_outbound(row, source, destination, segments):
                skipped_non_outbound += 1
                continue

            outbound_baselines[source].append(source_bytes)
            src_segment = _segment_for_ip(source, segments)
            dst_segment = _segment_for_ip(destination, segments)
            trust_boundary = bool(
                src_segment
                and dst_segment
                and src_segment.trust_zone
                and dst_segment.trust_zone
                and src_segment.trust_zone != dst_segment.trust_zone
            )
            external = _is_external_destination(row, destination, dst_segment)
            if not external and not trust_boundary:
                skipped_not_external_or_boundary += 1
                continue

            candidates.append(
                _Candidate(
                    row=row,
                    source=source,
                    destination=destination,
                    destination_port=_as_int(row.get("destination_port", row.get("id.resp_p"))),
                    protocol=_text(row.get("protocol", row.get("proto"))).lower() or "unknown",
                    service=_text(row.get("service")) or "unknown",
                    source_bytes=source_bytes,
                    timestamp=row.get("timestamp", row.get("ts")),
                    external=external,
                    trust_boundary=trust_boundary,
                    source_zone=src_segment.trust_zone if src_segment else None,
                    destination_zone=dst_segment.trust_zone if dst_segment else None,
                )
            )

        findings: list[Finding] = []
        evaluated = 0
        for candidate in sorted(candidates, key=lambda item: item.source_bytes, reverse=True):
            baseline = outbound_baselines.get(candidate.source, [])
            threshold, baseline_stats = _anomaly_threshold(
                baseline,
                candidate.external,
                candidate.trust_boundary,
                policy,
            )
            evaluated += 1
            if candidate.source_bytes < threshold:
                continue

            ratio_to_median = None
            median = baseline_stats.get("median_bytes")
            if isinstance(median, (int, float)) and median > 0:
                ratio_to_median = candidate.source_bytes / median

            absolute_only = len(baseline) < policy["minimum_baseline_flows"]
            confidence = "medium"
            if not absolute_only and ratio_to_median is not None and ratio_to_median >= 10:
                confidence = "high"
            elif candidate.trust_boundary and candidate.source_zone and candidate.destination_zone:
                confidence = "high" if candidate.source_bytes >= policy["always_report_bytes"] else "medium"

            severity = "high" if candidate.source_bytes >= policy["high_severity_bytes"] else "medium"
            boundary_text = _boundary_text(candidate)
            title = "Unusually large outbound connection"
            if candidate.trust_boundary:
                title = "Unusually large transfer across trust boundary"

            pair = {
                "source": candidate.source,
                "destination": candidate.destination,
                "port": candidate.destination_port,
                "protocol": candidate.protocol,
                "service": candidate.service,
            }
            tags = ["outbound-volume", "large-transfer", "anomaly"]
            if candidate.external:
                tags.append("external-destination")
            if candidate.trust_boundary:
                tags.append("trust-boundary")

            findings.append(
                Finding(
                    title=title,
                    severity=severity,
                    confidence=confidence,
                    detection_basis="heuristic",
                    summary=(
                        f"Zeek recorded {candidate.source_bytes:,} outbound bytes "
                        f"({_format_bytes(candidate.source_bytes)}) from {candidate.source} to "
                        f"{candidate.destination}{_port_suffix(candidate.destination_port)}. "
                        f"{boundary_text} The volume exceeds this module's conservative anomaly threshold "
                        f"of {_format_bytes(int(threshold))}. A large transfer is not by itself proof of "
                        "data exfiltration; correlate with asset role, expected workflows, destination, "
                        "time of day, and application/file evidence."
                    ),
                    devices=sorted({candidate.source, candidate.destination}),
                    services=[candidate.service] if candidate.service != "unknown" else [],
                    ports=[candidate.destination_port] if candidate.destination_port is not None else [],
                    connection_pairs=[pair],
                    flows=[candidate.row],
                    subnets=_candidate_subnets(candidate, segments),
                    timestamps=[candidate.timestamp] if candidate.timestamp is not None else [],
                    tags=tags,
                    metadata={
                        "orig_bytes": candidate.source_bytes,
                        "orig_bytes_human": _format_bytes(candidate.source_bytes),
                        "anomaly_threshold_bytes": int(threshold),
                        "anomaly_threshold_human": _format_bytes(int(threshold)),
                        "external_destination": candidate.external,
                        "trust_boundary_crossing": candidate.trust_boundary,
                        "source_trust_zone": candidate.source_zone,
                        "destination_trust_zone": candidate.destination_zone,
                        "baseline_flow_count": len(baseline),
                        "baseline": baseline_stats,
                        "ratio_to_median": round(ratio_to_median, 3) if ratio_to_median is not None else None,
                        "absolute_threshold_only": absolute_only,
                        "evidence_flow_count": 1,
                        "evidence_truncated": False,
                    },
                )
            )

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "unusual_outbound_volume_findings": len(findings),
                "candidate_outbound_connections_evaluated": evaluated,
                "external_destination_findings": sum(1 for f in findings if f.metadata.get("external_destination")),
                "trust_boundary_findings": sum(1 for f in findings if f.metadata.get("trust_boundary_crossing")),
                "affected_sources": len({f.connection_pairs[0]["source"] for f in findings if f.connection_pairs}),
                "total_flagged_orig_bytes": sum(int(f.metadata.get("orig_bytes") or 0) for f in findings),
            },
            evidence={
                "inspected_logs": ["conn"],
                "segments_source": context.metadata.get("segments_source"),
                "skipped_non_outbound_flows": skipped_non_outbound,
                "skipped_missing_or_invalid_orig_bytes": skipped_missing_bytes,
                "skipped_multicast_or_special_destinations": skipped_multicast_or_special,
                "skipped_not_external_or_trust_boundary": skipped_not_external_or_boundary,
                "thresholds": {
                    "minimum_external_bytes": policy["minimum_external_bytes"],
                    "minimum_trust_boundary_bytes": policy["minimum_trust_boundary_bytes"],
                    "always_report_bytes": policy["always_report_bytes"],
                    "high_severity_bytes": policy["high_severity_bytes"],
                    "minimum_baseline_flows": policy["minimum_baseline_flows"],
                    "median_multiplier": policy["median_multiplier"],
                    "mad_multiplier": policy["mad_multiplier"],
                },
                "notes": [
                    "The detector uses Zeek orig_bytes/source_bytes and evaluates only outbound traffic to external destinations or across explicitly different trust zones.",
                    "With enough source history, the threshold combines an absolute floor with a robust median/MAD baseline. With sparse history, only the conservative absolute threshold is used.",
                    "Large outbound transfers can be legitimate backups, updates, historian replication, cloud uploads, or engineering workflows; findings are anomaly-review signals, not automatic exfiltration labels.",
                    "Trust-boundary detection requires segment metadata with trust_zone/security_zone/zone labels; the module does not infer trust zones from IP ranges alone.",
                ],
            },
            warnings=[],
        )


def _policy(metadata: dict[str, Any]) -> dict[str, float | int]:
    raw = metadata.get("outbound_volume_policy") or metadata.get("data_volume_policy") or {}
    if not isinstance(raw, dict):
        raw = {}
    return {
        "minimum_external_bytes": _positive_int(raw.get("minimum_external_bytes"), DEFAULT_MIN_EXTERNAL_BYTES),
        "minimum_trust_boundary_bytes": _positive_int(raw.get("minimum_trust_boundary_bytes"), DEFAULT_MIN_TRUST_BOUNDARY_BYTES),
        "always_report_bytes": _positive_int(raw.get("always_report_bytes"), DEFAULT_ALWAYS_REPORT_BYTES),
        "high_severity_bytes": _positive_int(raw.get("high_severity_bytes"), DEFAULT_HIGH_SEVERITY_BYTES),
        "minimum_baseline_flows": _positive_int(raw.get("minimum_baseline_flows"), DEFAULT_MIN_BASELINE_FLOWS),
        "median_multiplier": _positive_float(raw.get("median_multiplier"), DEFAULT_MEDIAN_MULTIPLIER),
        "mad_multiplier": _positive_float(raw.get("mad_multiplier"), DEFAULT_MAD_MULTIPLIER),
    }


def _anomaly_threshold(
    baseline: list[int],
    external: bool,
    trust_boundary: bool,
    policy: dict[str, float | int],
) -> tuple[float, dict[str, Any]]:
    absolute_floor = float(
        min(
            int(policy["minimum_external_bytes"]) if external else 2**63 - 1,
            int(policy["minimum_trust_boundary_bytes"]) if trust_boundary else 2**63 - 1,
        )
    )
    if absolute_floor >= 2**63 - 1:
        absolute_floor = float(policy["always_report_bytes"])

    stats: dict[str, Any] = {"method": "absolute_floor"}
    if len(baseline) < int(policy["minimum_baseline_flows"]):
        # With sparse history there is not enough evidence to build a robust
        # per-source baseline.  Fall back to the configured absolute floor
        # for the boundary type instead of raising the threshold to the
        # always-report ceiling.  The latter is a cap for baseline-derived
        # thresholds, not the sparse-baseline minimum.
        threshold = absolute_floor
        stats["sparse_baseline"] = True
        return threshold, stats

    values = [float(value) for value in baseline if value >= 0]
    median = statistics.median(values)
    deviations = [abs(value - median) for value in values]
    mad = statistics.median(deviations)
    robust_sigma = 1.4826 * mad
    robust_threshold = median + float(policy["mad_multiplier"]) * robust_sigma
    multiple_threshold = median * float(policy["median_multiplier"])
    threshold = max(absolute_floor, robust_threshold, multiple_threshold)
    # `always_report_bytes` is the upper bound on any learned anomaly
    # threshold: a transfer at or above that size should never be hidden by
    # an unusually large historical baseline.
    threshold = min(threshold, float(policy["always_report_bytes"]))
    stats.update(
        {
            "method": "median_mad",
            "sparse_baseline": False,
            "median_bytes": round(median, 3),
            "mad_bytes": round(mad, 3),
            "robust_sigma_bytes": round(robust_sigma, 3),
            "robust_threshold_bytes": round(robust_threshold, 3),
            "multiple_threshold_bytes": round(multiple_threshold, 3),
        }
    )
    return threshold, stats


def _load_segments(metadata: dict[str, Any]) -> list[_Segment]:
    raw = metadata.get("segments") or []
    if not isinstance(raw, list):
        return []
    segments: list[_Segment] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        cidr = _text(item.get("cidr") or item.get("subnet"))
        zone = _text(
            item.get("trust_zone")
            or item.get("security_zone")
            or item.get("zone")
            or item.get("trust_level")
        )
        if not cidr or not zone:
            continue
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        segments.append(
            _Segment(
                cidr=cidr,
                name=_text(item.get("name")) or cidr,
                trust_zone=zone,
                network=network,
            )
        )
    return segments


def _segment_for_ip(value: str, segments: list[_Segment]) -> _Segment | None:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    matches = [segment for segment in segments if address in segment.network]
    return max(matches, key=lambda segment: segment.network.prefixlen) if matches else None


def _is_outbound(row: dict[str, Any], source: str, destination: str, segments: list[_Segment]) -> bool:
    local_orig = _truth_value(row.get("local_orig"))
    local_resp = _truth_value(row.get("local_resp"))
    if local_orig is True and local_resp is False:
        return True
    if local_orig is False and local_resp is True:
        return False
    if local_orig is True and local_resp is True:
        return True if _different_trust_zones(source, destination, segments) else False

    src_segment = _segment_for_ip(source, segments)
    if src_segment is not None:
        return True
    try:
        src = ipaddress.ip_address(source)
    except ValueError:
        return False
    return src.is_private or src.is_link_local


def _is_external_destination(row: dict[str, Any], destination: str, dst_segment: _Segment | None) -> bool:
    local_resp = _truth_value(row.get("local_resp"))
    if local_resp is False:
        return True
    if dst_segment is not None:
        return False
    try:
        dst = ipaddress.ip_address(destination)
    except ValueError:
        return False
    return dst.is_global


def _different_trust_zones(source: str, destination: str, segments: list[_Segment]) -> bool:
    src = _segment_for_ip(source, segments)
    dst = _segment_for_ip(destination, segments)
    return bool(src and dst and src.trust_zone and dst.trust_zone and src.trust_zone != dst.trust_zone)


def _is_multicast_or_special(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return True
    return address.is_multicast or address.is_unspecified or address.is_loopback or address.is_link_local


def _boundary_text(candidate: _Candidate) -> str:
    parts: list[str] = []
    if candidate.external:
        parts.append("The destination is external to the locally observed network")
    if candidate.trust_boundary:
        parts.append(
            f"the connection crosses configured trust zones '{candidate.source_zone}' to '{candidate.destination_zone}'"
        )
    if not parts:
        return ""
    return "; ".join(parts) + "."


def _candidate_subnets(candidate: _Candidate, segments: list[_Segment]) -> list[str]:
    values: list[str] = []
    for address in (candidate.source, candidate.destination):
        segment = _segment_for_ip(address, segments)
        if segment and segment.cidr not in values:
            values.append(segment.cidr)
    return values


def _format_bytes(value: int) -> str:
    if value >= GIB:
        return f"{value / GIB:.2f} GiB"
    if value >= MIB:
        return f"{value / MIB:.2f} MiB"
    if value >= 1024:
        return f"{value / 1024:.2f} KiB"
    return f"{value} B"


def _port_suffix(port: int | None) -> str:
    return f":{port}" if port is not None else ""


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


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _as_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def _positive_int(value: Any, default: int) -> int:
    parsed = _as_int(value)
    return parsed if parsed is not None and parsed > 0 else default


def _positive_float(value: Any, default: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default
