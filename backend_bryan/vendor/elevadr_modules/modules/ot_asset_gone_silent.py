from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import ipaddress
import statistics
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata


DEFAULT_BASELINE_SECONDS = 300.0
DEFAULT_MIN_BASELINE_OBSERVATIONS = 4
DEFAULT_SILENCE_MULTIPLIER = 3.0
DEFAULT_MIN_SILENCE_SECONDS = 60.0
DEFAULT_MAX_INTERVAL_DEVIATION_RATIO = 0.35
MAX_EVIDENCE_ROWS = 20
ICS_ROLE_TOKENS = {
    "ics", "ot", "scada", "plc", "rtu", "hmi", "bas", "bms", "historian",
    "dcs", "controller", "control", "control system", "industrial", "process",
    "engineering workstation", "engineering",
}


@dataclass(frozen=True, slots=True)
class _Segment:
    name: str
    role: str
    network: ipaddress._BaseNetwork


@dataclass(frozen=True, slots=True)
class _Identity:
    ip: str
    role: str
    source: str
    name: str


@dataclass(slots=True)
class _Observation:
    timestamp: float
    row: dict[str, Any]
    ot_host: str
    peer: str
    direction: str
    protocol: str
    port: int | None
    service: str
    identity: _Identity

    @property
    def conversation_key(self) -> tuple[str, str, str, str, int | None, str]:
        return (self.ot_host, self.peer, self.direction, self.protocol, self.port, self.service)


@dataclass(slots=True)
class _PeriodicSeries:
    observations: list[_Observation]
    median_interval: float
    max_deviation_ratio: float
    silence_threshold: float


class OtAssetGoneSilentModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="ot_asset_gone_silent",
        name="OT Asset Gone Silent (Loss of Expected Periodic Comms)",
        description=(
            "Learns regular OT host/conversation cadence during a baseline period and identifies expected periodic "
            "communications that cease for materially longer than their established interval."
        ),
        category="security_analysis",
        required_logs=("conn",),
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        policy = _policy(context.metadata)
        segments = _load_segments(context.metadata)
        inventory = _load_inventory(context.metadata)
        explicit_ot = _string_set(policy.get("ot_hosts"))
        ignored_hosts = _string_set(policy.get("ignored_hosts"))
        allowed_pairs = _pair_set(policy.get("allowed_pairs"))
        ignored_services = _string_set(policy.get("ignored_services"))

        classification_available = bool(segments or inventory or explicit_ot)
        timestamps = [
            ts for row in context.connections
            if (ts := _as_float(_first(row, "timestamp", "ts"))) is not None
        ]
        if not context.connections or not timestamps:
            return _empty_result(self.metadata.id, policy, segments, context, "conn.log with timestamps is required for cadence analysis.")
        if not classification_available:
            return _empty_result(
                self.metadata.id,
                policy,
                segments,
                context,
                "No OT/control-system classification was supplied; private addressing alone is not used to infer OT identity.",
                skipped_unclassified=len(context.connections),
            )

        capture_start = min(timestamps)
        capture_end = max(timestamps)
        baseline_end = capture_start + policy["baseline_seconds"]

        observations: list[_Observation] = []
        skipped_unclassified = 0
        skipped_allowlisted = 0
        for row in context.connections:
            ts = _as_float(_first(row, "timestamp", "ts"))
            source = _ip(_first(row, "source_ip", "id.orig_h"))
            destination = _ip(_first(row, "destination_ip", "id.resp_h"))
            if ts is None or not source or not destination:
                continue
            src_identity = _ot_identity(source, segments, inventory, explicit_ot)
            dst_identity = _ot_identity(destination, segments, inventory, explicit_ot)
            identities: list[tuple[str, str, str, _Identity]] = []
            if src_identity is not None:
                identities.append((source, destination, "outbound", src_identity))
            if dst_identity is not None and destination != source:
                identities.append((destination, source, "inbound", dst_identity))
            if not identities:
                skipped_unclassified += 1
                continue

            protocol = _text(_first(row, "protocol", "proto")).lower() or "unknown"
            port = _as_int(_first(row, "destination_port", "id.resp_p"))
            service = _normalize_service(row.get("service"))
            for ot_host, peer, direction, identity in identities:
                if ot_host in ignored_hosts or (ot_host, peer) in allowed_pairs or (peer, ot_host) in allowed_pairs:
                    skipped_allowlisted += 1
                    continue
                if service in ignored_services:
                    skipped_allowlisted += 1
                    continue
                observations.append(
                    _Observation(
                        timestamp=ts,
                        row=row,
                        ot_host=ot_host,
                        peer=peer,
                        direction=direction,
                        protocol=protocol,
                        port=port,
                        service=service,
                        identity=identity,
                    )
                )

        if capture_end <= baseline_end:
            hosts = {obs.ot_host for obs in observations}
            baseline_conversations = {obs.conversation_key for obs in observations}
            return ModuleResult(
                module_id=self.metadata.id,
                findings=[],
                metrics={
                    "connections_evaluated": len(context.connections),
                    "ot_observations": len(observations),
                    "ot_hosts_observed": len(hosts),
                    "baseline_conversations": len(baseline_conversations),
                    "periodic_conversations_learned": 0,
                    "stale_periodic_conversations": 0,
                    "host_silence_findings": 0,
                    "conversation_silence_findings": 0,
                    "ot_asset_gone_silent_findings": 0,
                    "skipped_unclassified": skipped_unclassified,
                    "skipped_allowlisted": skipped_allowlisted,
                },
                evidence={
                    "inspected_logs": ["conn"],
                    "capture_start": capture_start,
                    "capture_end": capture_end,
                    "baseline_end": baseline_end,
                    "segments_loaded": len(segments),
                    "asset_inventory_records": len(context.metadata.get("asset_inventory", []) or []),
                    "thresholds": policy,
                    "notes": [
                        "The capture does not extend beyond the configured baseline window, so silence cannot yet be evaluated.",
                        "Current OT endpoint observations are still classified and counted so short captures do not appear to contain zero OT traffic.",
                    ],
                },
                warnings=[],
            )

        baseline_by_conversation: dict[tuple[str, str, str, str, int | None, str], list[_Observation]] = defaultdict(list)
        all_by_conversation: dict[tuple[str, str, str, str, int | None, str], list[_Observation]] = defaultdict(list)
        all_by_host: dict[str, list[_Observation]] = defaultdict(list)
        for obs in observations:
            all_by_host[obs.ot_host].append(obs)
            all_by_conversation[obs.conversation_key].append(obs)
            if obs.timestamp <= baseline_end:
                baseline_by_conversation[obs.conversation_key].append(obs)

        periodic: dict[tuple[str, str, str, str, int | None, str], _PeriodicSeries] = {}
        rejected_irregular = 0
        rejected_sparse = 0
        for key, baseline_obs in baseline_by_conversation.items():
            series = _periodic_series(baseline_obs, policy)
            if series is None:
                if len(baseline_obs) < policy["min_baseline_observations"]:
                    rejected_sparse += 1
                else:
                    rejected_irregular += 1
                continue
            periodic[key] = series

        stale_by_host: dict[str, list[tuple[tuple[str, str, str, str, int | None, str], _PeriodicSeries, float]]] = defaultdict(list)
        for key, series in periodic.items():
            all_obs = all_by_conversation.get(key, [])
            if not all_obs:
                continue
            last_seen = max(obs.timestamp for obs in all_obs)
            if capture_end - last_seen > series.silence_threshold:
                stale_by_host[key[0]].append((key, series, last_seen))

        findings: list[Finding] = []
        host_silence_findings = 0
        conversation_silence_findings = 0
        for host, stale_items in sorted(stale_by_host.items()):
            host_periodic_keys = [key for key in periodic if key[0] == host]
            host_last_seen = max((obs.timestamp for obs in all_by_host.get(host, [])), default=None)
            all_periodic_stale = bool(host_periodic_keys) and len(stale_items) == len(host_periodic_keys)
            host_threshold = min((series.silence_threshold for _, series, _ in stale_items), default=policy["min_silence_seconds"])
            host_is_silent = host_last_seen is not None and (capture_end - host_last_seen > host_threshold) and all_periodic_stale
            if host_is_silent:
                findings.append(_host_finding(host, stale_items, all_by_host[host], capture_end))
                host_silence_findings += 1
                continue
            for key, series, last_seen in stale_items:
                findings.append(_conversation_finding(key, series, all_by_conversation[key], last_seen, capture_end))
                conversation_silence_findings += 1

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "connections_evaluated": len(context.connections),
                "ot_observations": len(observations),
                "ot_hosts_observed": len(all_by_host),
                "baseline_conversations": len(baseline_by_conversation),
                "periodic_conversations_learned": len(periodic),
                "stale_periodic_conversations": sum(len(v) for v in stale_by_host.values()),
                "host_silence_findings": host_silence_findings,
                "conversation_silence_findings": conversation_silence_findings,
                "ot_asset_gone_silent_findings": len(findings),
                "rejected_sparse_baselines": rejected_sparse,
                "rejected_irregular_baselines": rejected_irregular,
                "skipped_unclassified": skipped_unclassified,
                "skipped_allowlisted": skipped_allowlisted,
            },
            evidence={
                "inspected_logs": ["conn"],
                "capture_start": capture_start,
                "capture_end": capture_end,
                "baseline_end": baseline_end,
                "segments_loaded": len(segments),
                "asset_inventory_records": len(context.metadata.get("asset_inventory", []) or []),
                "thresholds": policy,
                "notes": [
                    "Only conversations that demonstrate a sufficiently regular cadence during the baseline can become expected periodic communications.",
                    "The silence threshold is max(min_silence_seconds, learned median interval x silence_multiplier).",
                    "If every learned periodic conversation for an OT host is stale and the host itself has disappeared beyond the learned threshold, one host-level finding is emitted and redundant conversation findings are suppressed.",
                    "A passive capture can only prove absence from the sensor's observation point; sensor outage, capture filtering, topology changes, maintenance, or asymmetric routing can also make a healthy asset appear silent.",
                ],
            },
            warnings=[],
        )


def _periodic_series(observations: list[_Observation], policy: dict[str, Any]) -> _PeriodicSeries | None:
    if len(observations) < policy["min_baseline_observations"]:
        return None
    times = sorted({obs.timestamp for obs in observations})
    if len(times) < policy["min_baseline_observations"]:
        return None
    intervals = [b - a for a, b in zip(times, times[1:]) if b > a]
    if len(intervals) < policy["min_baseline_observations"] - 1:
        return None
    median_interval = statistics.median(intervals)
    if median_interval <= 0:
        return None
    max_deviation_ratio = max(abs(value - median_interval) / median_interval for value in intervals)
    if max_deviation_ratio > policy["max_interval_deviation_ratio"]:
        return None
    silence_threshold = max(policy["min_silence_seconds"], median_interval * policy["silence_multiplier"])
    return _PeriodicSeries(
        observations=sorted(observations, key=lambda obs: obs.timestamp),
        median_interval=median_interval,
        max_deviation_ratio=max_deviation_ratio,
        silence_threshold=silence_threshold,
    )


def _host_finding(host: str, stale_items, host_observations: list[_Observation], capture_end: float) -> Finding:
    last_seen = max(obs.timestamp for obs in host_observations)
    first_series = stale_items[0][1]
    identity = first_series.observations[0].identity
    peers = sorted({key[1] for key, _, _ in stale_items})
    services = sorted({key[5] for key, _, _ in stale_items if key[5] != "unknown"})
    ports = sorted({key[4] for key, _, _ in stale_items if key[4] is not None})
    evidence_obs = sorted(
        [obs for _, series, _ in stale_items for obs in series.observations],
        key=lambda obs: obs.timestamp,
    )[-MAX_EVIDENCE_ROWS:]
    confidence = "high" if identity.source in {"asset_inventory", "policy"} else "medium"
    return Finding(
        title=f"OT asset gone silent: {host}",
        severity="high",
        confidence=confidence,
        detection_basis="derived",
        summary=(
            f"OT asset {host} stopped appearing in traffic after previously exhibiting {len(stale_items)} regular periodic "
            f"conversation(s). It has been absent for {capture_end - last_seen:.1f} seconds at the end of the capture."
        ),
        devices=[host, *peers[:25]],
        services=services,
        ports=ports,
        connection_pairs=[{"source": host, "destination": peer} for peer in peers[:25]],
        flows=[obs.row for obs in evidence_obs],
        timestamps=[obs.timestamp for obs in evidence_obs],
        tags=["ot", "availability", "gone-silent", "periodic-comms", "baseline"],
        metadata={
            "ot_host": host,
            "asset_name": identity.name,
            "asset_role": identity.role,
            "classification_source": identity.source,
            "last_seen_timestamp": last_seen,
            "capture_end_timestamp": capture_end,
            "silence_seconds": capture_end - last_seen,
            "periodic_conversations_gone_silent": len(stale_items),
            "peer_sample": peers[:50],
        },
    )


def _conversation_finding(key, series: _PeriodicSeries, observations: list[_Observation], last_seen: float, capture_end: float) -> Finding:
    host, peer, direction, protocol, port, service = key
    identity = series.observations[0].identity
    evidence_obs = sorted(observations, key=lambda obs: obs.timestamp)[-MAX_EVIDENCE_ROWS:]
    confidence = "high" if identity.source in {"asset_inventory", "policy"} else "medium"
    service_label = service if service != "unknown" else f"{protocol}/{port if port is not None else '?'}"
    return Finding(
        title=f"Expected OT periodic conversation ceased: {host} ↔ {peer}",
        severity="medium",
        confidence=confidence,
        detection_basis="derived",
        summary=(
            f"The expected periodic {service_label} conversation involving OT host {host} and peer {peer} stopped. "
            f"Baseline median interval was {series.median_interval:.1f} seconds; no matching conversation was seen for "
            f"{capture_end - last_seen:.1f} seconds before capture end."
        ),
        devices=[host, peer],
        services=[] if service == "unknown" else [service],
        ports=[] if port is None else [port],
        connection_pairs=[{"source": host if direction == "outbound" else peer, "destination": peer if direction == "outbound" else host, "port": port, "protocol": protocol}],
        flows=[obs.row for obs in evidence_obs],
        timestamps=[obs.timestamp for obs in evidence_obs],
        tags=["ot", "availability", "periodic-comms", "conversation-silent", "baseline"],
        metadata={
            "ot_host": host,
            "peer": peer,
            "direction_relative_to_ot": direction,
            "protocol": protocol,
            "destination_port": port,
            "service": service,
            "asset_name": identity.name,
            "asset_role": identity.role,
            "classification_source": identity.source,
            "baseline_observations": len(series.observations),
            "median_interval_seconds": series.median_interval,
            "max_interval_deviation_ratio": series.max_deviation_ratio,
            "silence_threshold_seconds": series.silence_threshold,
            "last_seen_timestamp": last_seen,
            "capture_end_timestamp": capture_end,
            "silence_seconds": capture_end - last_seen,
        },
    )


def _empty_result(module_id: str, policy: dict[str, Any], segments: list[_Segment], context: AnalysisContext, note: str, skipped_unclassified: int = 0) -> ModuleResult:
    return ModuleResult(
        module_id=module_id,
        findings=[],
        metrics={
            "connections_evaluated": len(context.connections),
            "ot_observations": 0,
            "ot_hosts_observed": 0,
            "baseline_conversations": 0,
            "periodic_conversations_learned": 0,
            "stale_periodic_conversations": 0,
            "host_silence_findings": 0,
            "conversation_silence_findings": 0,
            "ot_asset_gone_silent_findings": 0,
            "skipped_unclassified": skipped_unclassified,
        },
        evidence={
            "inspected_logs": ["conn"] if context.connections else [],
            "segments_loaded": len(segments),
            "asset_inventory_records": len(context.metadata.get("asset_inventory", []) or []),
            "thresholds": policy,
            "notes": [note],
        },
        warnings=[],
    )


def _policy(metadata: dict[str, Any]) -> dict[str, Any]:
    raw = {}
    for key in ("ot_asset_silence_policy", "ot_silence_policy", "periodic_comms_policy"):
        value = metadata.get(key)
        if isinstance(value, dict):
            raw = value
            break
    return {
        **raw,
        "baseline_seconds": _positive_float(raw.get("baseline_seconds"), DEFAULT_BASELINE_SECONDS),
        "min_baseline_observations": _positive_int(raw.get("min_baseline_observations"), DEFAULT_MIN_BASELINE_OBSERVATIONS),
        "silence_multiplier": _positive_float(raw.get("silence_multiplier"), DEFAULT_SILENCE_MULTIPLIER),
        "min_silence_seconds": _positive_float(raw.get("min_silence_seconds"), DEFAULT_MIN_SILENCE_SECONDS),
        "max_interval_deviation_ratio": _nonnegative_float(raw.get("max_interval_deviation_ratio"), DEFAULT_MAX_INTERVAL_DEVIATION_RATIO),
    }


def _load_segments(metadata: dict[str, Any]) -> list[_Segment]:
    result: list[_Segment] = []
    for item in metadata.get("segments", []) or []:
        if not isinstance(item, dict):
            continue
        cidr = item.get("cidr") or item.get("network") or item.get("subnet")
        if not cidr:
            continue
        try:
            network = ipaddress.ip_network(str(cidr), strict=False)
        except ValueError:
            continue
        result.append(_Segment(
            name=_text(item.get("name")) or str(network),
            role=_text(item.get("role") or item.get("type") or item.get("zone")),
            network=network,
        ))
    return result


def _load_inventory(metadata: dict[str, Any]) -> dict[str, _Identity]:
    result: dict[str, _Identity] = {}
    for item in metadata.get("asset_inventory", []) or []:
        if not isinstance(item, dict):
            continue
        ip = _ip(item.get("ip") or item.get("ip_address") or item.get("address"))
        role = _text(item.get("role") or item.get("type") or item.get("asset_type"))
        if not ip or not _is_ot_role(role):
            continue
        result[ip] = _Identity(
            ip=ip,
            role=role,
            source="asset_inventory",
            name=_text(item.get("name") or item.get("hostname") or item.get("device")),
        )
    return result


def _ot_identity(ip: str, segments: list[_Segment], inventory: dict[str, _Identity], explicit: set[str]) -> _Identity | None:
    if ip in explicit:
        return _Identity(ip=ip, role="OT", source="policy", name="")
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None

    # Explicit segment classification is authoritative for zone identity.  Asset
    # labels such as "engineering workstation" are descriptive and must not turn
    # a host in an explicitly IT/non-control segment into an OT endpoint.
    matching = [
        segment for segment in segments
        if addr.version == segment.network.version and addr in segment.network
    ]
    if matching:
        segment = max(matching, key=lambda value: value.network.prefixlen)
        if _is_ot_role(segment.role):
            return _Identity(ip=ip, role=segment.role, source="segment", name=segment.name)
        return None

    if ip in inventory:
        return inventory[ip]
    return None


def _is_ot_role(role: str) -> bool:
    value = role.lower().replace("_", " ").replace("-", " ").strip()
    return any(token == value or token in value for token in ICS_ROLE_TOKENS)


def _normalize_service(value: Any) -> str:
    text = _text(value).lower()
    if not text or text in {"-", "unknown"}:
        return "unknown"
    return text


def _pair_set(value: Any) -> set[tuple[str, str]]:
    result: set[tuple[str, str]] = set()
    if not isinstance(value, list):
        return result
    for item in value:
        if not isinstance(item, dict):
            continue
        source = _ip(item.get("source") or item.get("src"))
        destination = _ip(item.get("destination") or item.get("dst"))
        if source and destination:
            result.add((source, destination))
    return result


def _string_set(value: Any) -> set[str]:
    if value is None:
        return set()
    values = value if isinstance(value, (list, tuple, set)) else [value]
    return {_text(item).lower() if not _ip(item) else _ip(item) for item in values if _text(item)}


def _first(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = row.get(key)
        if value not in (None, "", "-"):
            return value
    return None


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _ip(value: Any) -> str:
    text = _text(value)
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return ""


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
