from __future__ import annotations

from collections import Counter, defaultdict
import ipaddress
from typing import Any, Callable

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata


DEFAULT_WINDOW_SECONDS = 60.0
DEFAULT_FAN_OUT_MIN_DESTINATIONS = 20
DEFAULT_FAN_IN_MIN_SOURCES = 20
DEFAULT_NEW_DESTINATION_BASELINE_SECONDS = 60.0
DEFAULT_HIGH_CONFIDENCE_DISTINCT_COUNT = 50
MAX_EVIDENCE_FLOWS = 100

# Discovery/infrastructure traffic commonly reaches many peers by design and is
# noisy for generic fan-out/fan-in behavior analysis.
_EXCLUDED_PORTS = {
    53,       # DNS
    67, 68,   # DHCPv4
    123,      # NTP
    137, 138, # NetBIOS
    161, 162, # SNMP
    1900,     # SSDP
    5353,     # mDNS
    5355,     # LLMNR
    546, 547, # DHCPv6
}
_EXCLUDED_SERVICES = {
    "dns", "dhcp", "ntp", "snmp", "ssdp", "mdns", "llmnr",
    "nbns", "netbios_ns", "netbios_dgm",
}


class HighFanInOutModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="high_fan_in_out",
        name="High Fan-Out or Fan-In Patterns",
        description=(
            "Identifies bursts where one host contacts many distinct destinations (fan-out), "
            "or many distinct sources suddenly contact one newly observed destination (fan-in)."
        ),
        category="security_analysis",
        required_logs=("conn",),
        default_enabled=True,
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        policy = _policy(context.metadata)
        normalized: list[dict[str, Any]] = []
        skipped_missing = 0
        skipped_non_unicast = 0
        skipped_expected_infrastructure = 0

        for row in context.connections:
            source = _text(row.get("source_ip", row.get("id.orig_h")))
            destination = _text(row.get("destination_ip", row.get("id.resp_h")))
            timestamp = _as_float(row.get("timestamp", row.get("ts")))
            port = _as_int(row.get("destination_port", row.get("id.resp_p")))
            protocol = _text(row.get("protocol", row.get("proto"))).lower()
            service = _text(row.get("service")).lower()

            if not source or not destination or timestamp is None:
                skipped_missing += 1
                continue
            if not _is_unicast(source) or not _is_unicast(destination):
                skipped_non_unicast += 1
                continue
            if port in _EXCLUDED_PORTS or service in _EXCLUDED_SERVICES:
                skipped_expected_infrastructure += 1
                continue

            normalized.append(
                {
                    "row": row,
                    "source": source,
                    "destination": destination,
                    "timestamp": timestamp,
                    "port": port,
                    "protocol": protocol or "unknown",
                    "service": service or "unknown",
                }
            )

        findings: list[Finding] = []

        # Fan-out: one source reaches many distinct destinations inside a short window.
        by_source: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for item in normalized:
            by_source[item["source"]].append(item)

        fan_out_groups_evaluated = 0
        for source, items in sorted(by_source.items()):
            if len({item["destination"] for item in items}) < policy["fan_out_min_destinations"]:
                continue
            fan_out_groups_evaluated += 1
            window = _best_window(
                items,
                window_seconds=policy["window_seconds"],
                distinct_key=lambda item: item["destination"],
                minimum_distinct=policy["fan_out_min_destinations"],
            )
            if window is not None:
                findings.append(_fan_out_finding(source, window, policy))

        # Fan-in: many sources reach the same destination in a short window. By
        # default the destination must be newly observed after enough capture time
        # has elapsed to establish a baseline.
        by_destination: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for item in normalized:
            by_destination[item["destination"]].append(item)

        capture_start = min((item["timestamp"] for item in normalized), default=None)
        fan_in_groups_evaluated = 0
        fan_in_suppressed_not_new = 0
        for destination, items in sorted(by_destination.items()):
            if len({item["source"] for item in items}) < policy["fan_in_min_sources"]:
                continue
            fan_in_groups_evaluated += 1
            first_seen = min(item["timestamp"] for item in items)
            baseline_age = first_seen - capture_start if capture_start is not None else 0.0
            destination_is_new = baseline_age >= policy["new_destination_baseline_seconds"]
            if policy["require_new_destination"] and not destination_is_new:
                fan_in_suppressed_not_new += 1
                continue

            window = _best_window(
                items,
                window_seconds=policy["window_seconds"],
                distinct_key=lambda item: item["source"],
                minimum_distinct=policy["fan_in_min_sources"],
            )
            if window is not None:
                findings.append(
                    _fan_in_finding(
                        destination,
                        window,
                        policy,
                        destination_is_new=destination_is_new,
                        baseline_age=baseline_age,
                    )
                )

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "fan_pattern_findings": len(findings),
                "fan_out_findings": sum("fan-out" in f.tags for f in findings),
                "fan_in_findings": sum("fan-in" in f.tags for f in findings),
                "fan_out_groups_evaluated": fan_out_groups_evaluated,
                "fan_in_groups_evaluated": fan_in_groups_evaluated,
                "fan_in_suppressed_not_new": fan_in_suppressed_not_new,
                "affected_devices": len({device for f in findings for device in f.devices}),
            },
            evidence={
                "inspected_logs": ["conn"],
                "skipped_missing_required_fields": skipped_missing,
                "skipped_non_unicast_flows": skipped_non_unicast,
                "skipped_expected_infrastructure_flows": skipped_expected_infrastructure,
                "excluded_ports": sorted(_EXCLUDED_PORTS),
                "excluded_services": sorted(_EXCLUDED_SERVICES),
                "thresholds": policy,
                "notes": [
                    "Fan-out is a behavioral heuristic: one source contacting many distinct destinations in the configured window.",
                    "Fan-in is a behavioral heuristic: many distinct sources contacting one destination in the configured window.",
                    "By default fan-in additionally requires that the destination first appear after a baseline observation period; this avoids labeling already-active servers as new targets.",
                    "Common discovery and infrastructure protocols are excluded to reduce expected broadcast/discovery and centralized-service fan patterns.",
                    "Legitimate scanners, management systems, software distribution, load balancers, and newly started services can produce similar behavior and should be correlated with asset role and change context.",
                ],
            },
            warnings=[],
        )


def _fan_out_finding(source: str, items: list[dict[str, Any]], policy: dict[str, Any]) -> Finding:
    destinations = sorted({item["destination"] for item in items})
    timestamps = sorted(item["timestamp"] for item in items)
    span = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0.0
    confidence = "high" if len(destinations) >= policy["high_confidence_distinct_count"] else "medium"
    severity = "high" if confidence == "high" else "medium"
    evidence_rows = items[:MAX_EVIDENCE_FLOWS]
    ports = sorted({item["port"] for item in items if item["port"] is not None})
    services = sorted({item["service"] for item in items if item["service"] != "unknown"})

    return Finding(
        title="High fan-out burst observed",
        severity=severity,
        confidence=confidence,
        detection_basis="heuristic",
        summary=(
            f"Source {source} contacted {len(destinations)} distinct destinations over {span:.2f} seconds. "
            "This high fan-out pattern can indicate scanning, automated propagation, or unusual orchestration, "
            "but legitimate management and distribution systems can produce the same behavior."
        ),
        devices=[source] + destinations[:25],
        services=services[:25],
        ports=ports[:50],
        connection_pairs=[
            {"source": source, "destination": destination}
            for destination in destinations[:25]
        ],
        flows=[item["row"] for item in evidence_rows],
        timestamps=timestamps[:MAX_EVIDENCE_FLOWS],
        tags=["fan-out", "high-cardinality", "behavioral-anomaly"],
        metadata={
            "source": source,
            "distinct_destinations": len(destinations),
            "observation_span_seconds": round(span, 3),
            "window_seconds": policy["window_seconds"],
            "destination_sample": destinations[:50],
            "evidence_flow_count": len(evidence_rows),
            "evidence_truncated": len(items) > MAX_EVIDENCE_FLOWS,
        },
    )


def _fan_in_finding(
    destination: str,
    items: list[dict[str, Any]],
    policy: dict[str, Any],
    *,
    destination_is_new: bool,
    baseline_age: float,
) -> Finding:
    sources = sorted({item["source"] for item in items})
    timestamps = sorted(item["timestamp"] for item in items)
    span = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0.0
    confidence = "high" if destination_is_new and len(sources) >= policy["high_confidence_distinct_count"] else "medium"
    severity = "high" if confidence == "high" else "medium"
    evidence_rows = items[:MAX_EVIDENCE_FLOWS]
    ports = sorted({item["port"] for item in items if item["port"] is not None})
    services = sorted({item["service"] for item in items if item["service"] != "unknown"})
    novelty_text = (
        f"The destination was first observed {baseline_age:.2f} seconds after capture start. "
        if destination_is_new
        else "Policy does not require the destination to be newly observed. "
    )

    return Finding(
        title="High fan-in burst to newly observed destination" if destination_is_new else "High fan-in burst observed",
        severity=severity,
        confidence=confidence,
        detection_basis="heuristic",
        summary=(
            f"Destination {destination} was contacted by {len(sources)} distinct sources over {span:.2f} seconds. "
            f"{novelty_text}This sudden fan-in can indicate coordinated activity or a newly exposed/redirected service, "
            "but legitimate service startup, failover, or load-balancing changes can produce a similar pattern."
        ),
        devices=sources[:25] + [destination],
        services=services[:25],
        ports=ports[:50],
        connection_pairs=[
            {"source": source, "destination": destination}
            for source in sources[:25]
        ],
        flows=[item["row"] for item in evidence_rows],
        timestamps=timestamps[:MAX_EVIDENCE_FLOWS],
        tags=["fan-in", "high-cardinality", "behavioral-anomaly"] + (["new-destination"] if destination_is_new else []),
        metadata={
            "destination": destination,
            "distinct_sources": len(sources),
            "observation_span_seconds": round(span, 3),
            "window_seconds": policy["window_seconds"],
            "destination_newly_observed": destination_is_new,
            "destination_first_seen_age_seconds": round(baseline_age, 3),
            "source_sample": sources[:50],
            "evidence_flow_count": len(evidence_rows),
            "evidence_truncated": len(items) > MAX_EVIDENCE_FLOWS,
        },
    )


def _best_window(
    items: list[dict[str, Any]],
    *,
    window_seconds: float,
    distinct_key: Callable[[dict[str, Any]], Any],
    minimum_distinct: int,
) -> list[dict[str, Any]] | None:
    ordered = sorted(items, key=lambda item: item["timestamp"])
    left = 0
    counts: Counter[Any] = Counter()
    best: list[dict[str, Any]] | None = None

    for right, item in enumerate(ordered):
        counts[distinct_key(item)] += 1
        while item["timestamp"] - ordered[left]["timestamp"] > window_seconds:
            old_key = distinct_key(ordered[left])
            counts[old_key] -= 1
            if counts[old_key] <= 0:
                del counts[old_key]
            left += 1
        if len(counts) >= minimum_distinct:
            candidate = ordered[left:right + 1]
            if best is None or len({distinct_key(x) for x in candidate}) > len({distinct_key(x) for x in best}):
                best = candidate
    return best


def _policy(metadata: dict[str, Any]) -> dict[str, Any]:
    raw = metadata.get("fan_in_out_policy")
    raw = raw if isinstance(raw, dict) else {}
    return {
        "window_seconds": _positive_float(raw.get("window_seconds"), DEFAULT_WINDOW_SECONDS),
        "fan_out_min_destinations": _positive_int(raw.get("fan_out_min_destinations"), DEFAULT_FAN_OUT_MIN_DESTINATIONS),
        "fan_in_min_sources": _positive_int(raw.get("fan_in_min_sources"), DEFAULT_FAN_IN_MIN_SOURCES),
        "new_destination_baseline_seconds": _nonnegative_float(raw.get("new_destination_baseline_seconds"), DEFAULT_NEW_DESTINATION_BASELINE_SECONDS),
        "require_new_destination": _bool(raw.get("require_new_destination"), True),
        "high_confidence_distinct_count": _positive_int(raw.get("high_confidence_distinct_count"), DEFAULT_HIGH_CONFIDENCE_DISTINCT_COUNT),
    }


def _is_unicast(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (ip.is_multicast or ip.is_unspecified)


def _text(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    return "" if text in {"-", "(empty)"} else text


def _as_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _positive_float(value: Any, default: float) -> float:
    parsed = _as_float(value)
    return parsed if parsed is not None and parsed > 0 else default


def _nonnegative_float(value: Any, default: float) -> float:
    parsed = _as_float(value)
    return parsed if parsed is not None and parsed >= 0 else default


def _positive_int(value: Any, default: int) -> int:
    parsed = _as_int(value)
    return parsed if parsed is not None and parsed > 0 else default


def _bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    return default
