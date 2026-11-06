from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import ipaddress
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata


DEFAULT_BASELINE_SECONDS = 300.0
DEFAULT_MIN_POST_BASELINE_OCCURRENCES = 1
MAX_EVIDENCE_FLOWS = 10
OT_ROLE_TOKENS = {"ot", "control", "ics", "scada", "operations", "industrial", "process"}


@dataclass(slots=True)
class _Segment:
    cidr: str
    name: str
    role: str
    network: ipaddress._BaseNetwork


@dataclass(slots=True)
class _Observation:
    row: dict[str, Any]
    timestamp: float
    host: str
    peer: str
    protocol: str
    port: int | None
    service: str
    identity: str
    segment: _Segment
    detection_basis: str


class NewServiceEmergenceOtModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="new_service_emergence_ot",
        name="New Service Emergence in OT (Baseline Drift)",
        description=(
            "Identifies services newly observed on configured OT hosts after an established baseline period, "
            "using Zeek service identification when available and protocol/port identity as a fallback."
        ),
        category="security_analysis",
        required_logs=("conn",),
        default_enabled=True,
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        segments = _load_segments(context.metadata)
        policy = _policy(context.metadata)
        ot_segments = [segment for segment in segments if _is_ot_role(segment.role)]

        if not context.connections:
            return _empty_result(self.metadata.id, segments, policy, note="conn.log is required for baseline service-drift analysis.")
        if not ot_segments:
            return _empty_result(
                self.metadata.id,
                segments,
                policy,
                note="No configured OT/control segments were found; OT membership is not inferred from private addressing.",
            )

        capture_timestamps = [
            timestamp
            for row in context.connections
            if (timestamp := _as_float(row.get("timestamp", row.get("ts")))) is not None
        ]
        capture_start = min(capture_timestamps) if capture_timestamps else None
        capture_end = max(capture_timestamps) if capture_timestamps else None

        observations: list[_Observation] = []
        skipped_unclassified = 0
        skipped_missing_timestamp = 0
        skipped_allowlisted = 0

        for row in context.connections:
            host = _text(row.get("destination_ip", row.get("id.resp_h")))
            peer = _text(row.get("source_ip", row.get("id.orig_h")))
            if not host or not peer:
                skipped_unclassified += 1
                continue
            segment = _segment_for_ip(host, ot_segments)
            if segment is None:
                continue
            timestamp = _as_float(row.get("timestamp", row.get("ts")))
            if timestamp is None:
                skipped_missing_timestamp += 1
                continue
            protocol = _text(row.get("protocol", row.get("proto"))).lower() or "unknown"
            port = _as_int(row.get("destination_port", row.get("id.resp_p")))
            service = _normalize_service(row.get("service"))
            detection_basis = "zeek_service" if service != "unknown" else "port"
            identity = _service_identity(service, protocol, port)
            if _allowlisted(host, identity, policy):
                skipped_allowlisted += 1
                continue
            observations.append(
                _Observation(
                    row=row,
                    timestamp=timestamp,
                    host=host,
                    peer=peer,
                    protocol=protocol,
                    port=port,
                    service=service,
                    identity=identity,
                    segment=segment,
                    detection_basis=detection_basis,
                )
            )

        if not observations:
            return ModuleResult(
                module_id=self.metadata.id,
                findings=[],
                metrics={"service_drift_findings": 0, "ot_hosts_observed": 0, "baseline_services": 0, "new_services": 0},
                evidence={
                    "inspected_logs": ["conn"],
                    "segments_loaded": len(segments),
                    "ot_segments_loaded": len(ot_segments),
                    "thresholds": policy,
                    "skipped_unclassified": skipped_unclassified,
                    "skipped_missing_timestamp": skipped_missing_timestamp,
                    "skipped_allowlisted": skipped_allowlisted,
                },
                warnings=[],
            )

        # Anchor the baseline to the packet-capture timeline, not to the first
        # qualifying OT service observation. Otherwise a service that first
        # appears late in the capture can incorrectly start its own fresh
        # baseline and suppress the very drift this detector is meant to find.
        if capture_start is None:
            capture_start = min(item.timestamp for item in observations)
        if capture_end is None:
            capture_end = max(item.timestamp for item in observations)
        baseline_end = capture_start + policy["baseline_seconds"]

        baseline_by_host: dict[str, set[str]] = defaultdict(set)
        post_by_host_service: dict[tuple[str, str], list[_Observation]] = defaultdict(list)
        for item in observations:
            if item.timestamp <= baseline_end:
                baseline_by_host[item.host].add(item.identity)
            else:
                post_by_host_service[(item.host, item.identity)].append(item)

        findings: list[Finding] = []
        for (host, identity), items in sorted(post_by_host_service.items()):
            if identity in baseline_by_host.get(host, set()):
                continue
            if len(items) < policy["min_post_baseline_occurrences"]:
                continue
            findings.append(_finding(host, identity, items, baseline_by_host.get(host, set()), baseline_end, policy))

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "service_drift_findings": len(findings),
                "ot_hosts_observed": len({item.host for item in observations}),
                "baseline_services": sum(len(values) for values in baseline_by_host.values()),
                "new_services": len(findings),
                "post_baseline_service_groups": len(post_by_host_service),
            },
            evidence={
                "inspected_logs": ["conn"],
                "segments_loaded": len(segments),
                "ot_segments_loaded": len(ot_segments),
                "capture_start": capture_start,
                "capture_end": capture_end,
                "baseline_start": capture_start,
                "baseline_end": baseline_end,
                "thresholds": policy,
                "skipped_unclassified": skipped_unclassified,
                "skipped_missing_timestamp": skipped_missing_timestamp,
                "skipped_allowlisted": skipped_allowlisted,
                "notes": [
                    "The baseline window is anchored to the start of the packet capture, not to the first qualifying OT service observation.",
                    "A service is considered new only when it is first observed on the responding OT host after the configured baseline window.",
                    "Zeek service identification is preferred; protocol/destination-port identity is used only when Zeek has no application service label.",
                    "This detector requires configured OT segments and does not infer OT membership from RFC1918/private addressing.",
                    "Planned maintenance, firmware updates, temporary engineering access, or sensor placement changes can legitimately introduce new services and should be correlated with change records.",
                ],
            },
            warnings=[],
        )


def _finding(host: str, identity: str, items: list[_Observation], baseline: set[str], baseline_end: float, policy: dict[str, Any]) -> Finding:
    first = min(items, key=lambda item: item.timestamp)
    evidence = sorted(items, key=lambda item: item.timestamp)[:MAX_EVIDENCE_FLOWS]
    confidence = "high" if first.detection_basis == "zeek_service" and len(items) >= 2 else "medium"
    severity = "medium"
    peers = sorted({item.peer for item in items})
    services = sorted({item.service for item in items if item.service != "unknown"})
    ports = sorted({item.port for item in items if item.port is not None})
    return Finding(
        title=f"New service observed on OT host: {host} ({identity})",
        severity=severity,
        confidence=confidence,
        detection_basis=first.detection_basis,
        summary=(
            f"OT host {host} in segment {first.segment.name} began exhibiting service identity {identity} after the baseline period. "
            f"The service was not present in that host's established baseline and was observed {len(items)} time(s) after baseline end."
        ),
        devices=[host] + peers[:25],
        services=services,
        ports=ports,
        connection_pairs=[{"source": peer, "destination": host, "port": first.port, "protocol": first.protocol} for peer in peers[:25]],
        flows=[item.row for item in evidence],
        subnets=[first.segment.cidr],
        timestamps=[item.timestamp for item in evidence],
        tags=["ot", "baseline-drift", "new-service", "service-emergence"],
        metadata={
            "ot_host": host,
            "ot_segment": first.segment.name,
            "service_identity": identity,
            "first_seen_timestamp": first.timestamp,
            "baseline_end_timestamp": baseline_end,
            "post_baseline_occurrences": len(items),
            "baseline_service_count": len(baseline),
            "baseline_services": sorted(baseline),
            "peer_sample": peers[:50],
            "evidence_truncated": len(items) > len(evidence),
            "min_post_baseline_occurrences": policy["min_post_baseline_occurrences"],
        },
    )


def _empty_result(module_id: str, segments: list[_Segment], policy: dict[str, Any], *, note: str) -> ModuleResult:
    return ModuleResult(
        module_id=module_id,
        findings=[],
        metrics={"service_drift_findings": 0, "ot_hosts_observed": 0, "baseline_services": 0, "new_services": 0},
        evidence={
            "inspected_logs": ["conn"] if segments else [],
            "segments_loaded": len(segments),
            "thresholds": policy,
            "notes": [note],
        },
        warnings=[],
    )


def _load_segments(metadata: dict[str, Any]) -> list[_Segment]:
    raw = metadata.get("segments")
    if not isinstance(raw, list):
        return []
    result: list[_Segment] = []
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
        result.append(_Segment(cidr=cidr, name=_text(item.get("name")) or cidr, role=_text(item.get("role")), network=network))
    return result


def _segment_for_ip(value: str, segments: list[_Segment]) -> _Segment | None:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    matches = [segment for segment in segments if address in segment.network]
    return max(matches, key=lambda segment: segment.network.prefixlen) if matches else None


def _is_ot_role(role: str) -> bool:
    value = role.strip().lower()
    return any(token in value for token in OT_ROLE_TOKENS)


def _normalize_service(value: Any) -> str:
    text = _text(value).lower()
    if not text or text in {"-", "unknown"}:
        return "unknown"
    return text


def _service_identity(service: str, protocol: str, port: int | None) -> str:
    if service != "unknown":
        suffix = f"/{protocol}:{port}" if port is not None else f"/{protocol}"
        return f"{service}{suffix}"
    return f"{protocol}:{port}" if port is not None else protocol


def _allowlisted(host: str, identity: str, policy: dict[str, Any]) -> bool:
    if host in policy["ignored_hosts"]:
        return True
    return identity in policy["ignored_services"]


def _policy(metadata: dict[str, Any]) -> dict[str, Any]:
    raw = metadata.get("service_baseline_policy")
    raw = raw if isinstance(raw, dict) else {}
    return {
        "baseline_seconds": _positive_float(raw.get("baseline_seconds"), DEFAULT_BASELINE_SECONDS),
        "min_post_baseline_occurrences": _positive_int(raw.get("min_post_baseline_occurrences"), DEFAULT_MIN_POST_BASELINE_OCCURRENCES),
        "ignored_hosts": sorted({_text(v) for v in raw.get("ignored_hosts", []) if _text(v)}),
        "ignored_services": sorted({_text(v).lower() for v in raw.get("ignored_services", []) if _text(v)}),
    }


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


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


def _positive_int(value: Any, default: int) -> int:
    parsed = _as_int(value)
    return parsed if parsed is not None and parsed > 0 else default
