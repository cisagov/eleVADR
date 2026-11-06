from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
import ipaddress
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata


MAX_EVIDENCE_ROWS = 100

# A conservative default direct-communication path based on the Purdue model.
# Organizations can override this in segments.json via purdue_policy.allowed_direct_pairs.
DEFAULT_ALLOWED_DIRECT_PAIRS = {
    frozenset(("L0", "L1")),
    frozenset(("L1", "L2")),
    frozenset(("L2", "L3")),
    frozenset(("L3", "DMZ")),
    frozenset(("DMZ", "L4")),
    frozenset(("L4", "L5")),
}

LEVEL_ORDER = {"L0": 0.0, "L1": 1.0, "L2": 2.0, "L3": 3.0, "DMZ": 3.5, "L4": 4.0, "L5": 5.0}


@dataclass(slots=True)
class _Segment:
    cidr: str
    name: str
    level: str
    network: ipaddress._BaseNetwork


@dataclass(slots=True)
class _Violation:
    row: dict[str, Any]
    source: str
    destination: str
    source_port: int | None
    destination_port: int | None
    protocol: str
    service: str | None
    timestamp: Any
    source_segment: _Segment
    destination_segment: _Segment
    violation_type: str
    severity: str


class CrossPurdueLevelTrafficModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="cross_purdue_level_traffic",
        name="Cross-Purdue-Level Traffic",
        description=(
            "Identifies direct communications between Purdue levels that should not communicate directly, "
            "including control levels reaching enterprise levels without an intermediate industrial DMZ."
        ),
        category="security_analysis",
        required_logs=("conn",),
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        if not context.connections:
            return ModuleResult(
                module_id=self.metadata.id,
                findings=[],
                metrics={
                    "cross_purdue_findings": 0,
                    "violating_flows": 0,
                    "classified_flows": 0,
                    "unclassified_flows": 0,
                },
                evidence={
                    "inspected_logs": [],
                    "skipped_logs": ["conn"],
                    "segments_loaded": 0,
                    "notes": ["conn.log is required for Cross-Purdue-Level Traffic analysis."],
                },
                warnings=[],
            )

        segments = _load_segments(context.metadata)
        if not segments:
            return ModuleResult(
                module_id=self.metadata.id,
                findings=[],
                metrics={
                    "cross_purdue_findings": 0,
                    "violating_flows": 0,
                    "classified_flows": 0,
                    "unclassified_flows": len(context.connections),
                },
                evidence={
                    "inspected_logs": ["conn"],
                    "skipped_logs": [],
                    "segments_loaded": 0,
                    "segment_source": context.metadata.get("segments_source"),
                    "notes": [
                        "Purdue-aware segment metadata is required. Add purdue_level (L0-L5 or DMZ/L3.5) to segments.json entries.",
                        "No network level is inferred from IP address, private/public status, or traffic behavior.",
                    ],
                    "segment_config_format": _example_config(),
                },
                warnings=[],
            )

        allowed_pairs, policy_source = _load_policy(context.metadata)
        violations: list[_Violation] = []
        classified_flows = 0
        unclassified_flows = 0
        allowed_flows = 0

        for row in context.connections:
            source = str(_first(row, "source_ip", "id.orig_h") or "")
            destination = str(_first(row, "destination_ip", "id.resp_h") or "")
            if not source or not destination:
                unclassified_flows += 1
                continue

            src_seg = _segment_for_ip(source, segments)
            dst_seg = _segment_for_ip(destination, segments)
            if src_seg is None or dst_seg is None:
                unclassified_flows += 1
                continue

            classified_flows += 1
            if src_seg.level == dst_seg.level or frozenset((src_seg.level, dst_seg.level)) in allowed_pairs:
                allowed_flows += 1
                continue

            violation_type, severity = _classify_violation(src_seg.level, dst_seg.level)
            violations.append(
                _Violation(
                    row=row,
                    source=source,
                    destination=destination,
                    source_port=_as_int(_first(row, "source_port", "id.orig_p")),
                    destination_port=_as_int(_first(row, "destination_port", "id.resp_p")),
                    protocol=str(_first(row, "protocol", "proto") or "").lower(),
                    service=_clean_service(row.get("service")),
                    timestamp=_first(row, "timestamp", "ts"),
                    source_segment=src_seg,
                    destination_segment=dst_seg,
                    violation_type=violation_type,
                    severity=severity,
                )
            )

        findings = _build_findings(violations, policy_source=policy_source)
        counts_by_pair = Counter(
            f"{item.source_segment.level}->{item.destination_segment.level}" for item in violations
        )

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "cross_purdue_findings": len(findings),
                "violating_flows": len(violations),
                "classified_flows": classified_flows,
                "allowed_classified_flows": allowed_flows,
                "unclassified_flows": unclassified_flows,
                "violating_flows_by_level_pair": dict(sorted(counts_by_pair.items())),
            },
            evidence={
                "inspected_logs": ["conn"],
                "skipped_logs": [],
                "segments_loaded": len(segments),
                "segment_source": context.metadata.get("segments_source"),
                "policy_source": policy_source,
                "allowed_direct_pairs": [sorted(pair, key=_level_sort_key) for pair in sorted(allowed_pairs, key=lambda p: sorted(p))],
                "notes": [
                    "Both endpoints must map to configured Purdue levels before a finding can be emitted.",
                    "The default policy permits only same-level traffic and direct communication between adjacent Purdue stages through the industrial DMZ path.",
                    "Direct L0-L3 to L4/L5 communication is treated as a DMZ-bypass / segmentation concern.",
                    "Network architecture can legitimately differ from the reference model; use purdue_policy.allowed_direct_pairs in segments.json to encode the site's approved direct communication paths.",
                    "This detector identifies direct endpoint-to-endpoint communications in the capture. It does not infer routed intermediate hops that are not visible as endpoints in conn.log.",
                ],
                "segment_config_format": _example_config(),
            },
            warnings=[],
        )


def _build_findings(violations: list[_Violation], *, policy_source: str) -> list[Finding]:
    groups: dict[tuple[str, str, str], list[_Violation]] = defaultdict(list)
    for item in violations:
        groups[(item.source_segment.level, item.destination_segment.level, item.violation_type)].append(item)

    findings: list[Finding] = []
    for (src_level, dst_level, violation_type), rows in sorted(groups.items()):
        severity = _max_severity(row.severity for row in rows)
        confidence = "high" if policy_source == "configured" else "medium"
        src_names = sorted({row.source_segment.name for row in rows})
        dst_names = sorted({row.destination_segment.name for row in rows})

        if violation_type == "dmz_bypass":
            title = f"Direct Purdue {src_level} to {dst_level} traffic bypasses the expected DMZ path"
            summary = (
                f"Observed {len(rows)} direct flow(s) from Purdue {src_level} segment(s) to Purdue {dst_level} segment(s). "
                "The configured/reference Purdue policy does not permit this direct level-to-level communication and expects enterprise/control boundary traffic to traverse the industrial DMZ path."
            )
        else:
            title = f"Unexpected direct Cross-Purdue traffic: {src_level} to {dst_level}"
            summary = (
                f"Observed {len(rows)} direct flow(s) between Purdue {src_level} and Purdue {dst_level}. "
                "This level pair is not allowed by the configured/reference direct-communication policy and should be reviewed for segmentation or architecture exceptions."
            )

        devices = sorted({value for row in rows for value in (row.source, row.destination) if value})
        services = sorted({row.service for row in rows if row.service})
        ports = sorted({row.destination_port for row in rows if row.destination_port is not None})
        subnets = sorted({value for row in rows for value in (row.source_segment.cidr, row.destination_segment.cidr)})
        pairs: list[dict[str, Any]] = []
        seen: set[tuple[str, str, int | None, str, str | None]] = set()
        for row in rows:
            key = (row.source, row.destination, row.destination_port, row.protocol, row.service)
            if key in seen:
                continue
            seen.add(key)
            pairs.append(
                {
                    "source": row.source,
                    "destination": row.destination,
                    "port": row.destination_port,
                    "protocol": row.protocol,
                    "service": row.service,
                }
            )

        findings.append(
            Finding(
                title=title,
                severity=severity,
                summary=summary,
                confidence=confidence,
                detection_basis="derived",
                devices=devices,
                services=services,
                ports=ports,
                connection_pairs=pairs,
                flows=[row.row for row in rows[:MAX_EVIDENCE_ROWS]],
                subnets=subnets,
                timestamps=sorted({row.timestamp for row in rows if row.timestamp is not None}, key=str),
                tags=["purdue", "segmentation", "cross-level", violation_type],
                metadata={
                    "source_purdue_level": src_level,
                    "destination_purdue_level": dst_level,
                    "source_segments": src_names,
                    "destination_segments": dst_names,
                    "violation_type": violation_type,
                    "flow_count": len(rows),
                    "policy_source": policy_source,
                    "evidence_truncated": len(rows) > MAX_EVIDENCE_ROWS,
                },
            )
        )
    return findings


def _load_segments(metadata: dict[str, Any]) -> list[_Segment]:
    raw = metadata.get("segments") or []
    if not isinstance(raw, list):
        return []
    segments: list[_Segment] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        cidr = str(item.get("cidr") or item.get("subnet") or "").strip()
        level = _normalize_level(
            item.get("purdue_level")
            or item.get("purdue")
            or item.get("level")
            or item.get("purdueLevel")
        )
        if not cidr or not level:
            continue
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        segments.append(
            _Segment(
                cidr=cidr,
                name=str(item.get("name") or cidr),
                level=level,
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
    if not matches:
        return None
    return max(matches, key=lambda segment: segment.network.prefixlen)


def _normalize_level(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip().upper().replace("LEVEL", "L").replace(" ", "")
    aliases = {
        "0": "L0", "L0": "L0",
        "1": "L1", "L1": "L1",
        "2": "L2", "L2": "L2",
        "3": "L3", "L3": "L3",
        "3.5": "DMZ", "L3.5": "DMZ", "DMZ": "DMZ", "IDMZ": "DMZ", "LDMZ": "DMZ",
        "4": "L4", "L4": "L4",
        "5": "L5", "L5": "L5",
    }
    return aliases.get(text)


def _load_policy(metadata: dict[str, Any]) -> tuple[set[frozenset[str]], str]:
    policy = metadata.get("purdue_policy")
    if not isinstance(policy, dict):
        return set(DEFAULT_ALLOWED_DIRECT_PAIRS), "default_reference"

    raw_pairs = policy.get("allowed_direct_pairs")
    if not isinstance(raw_pairs, list):
        return set(DEFAULT_ALLOWED_DIRECT_PAIRS), "default_reference"

    parsed: set[frozenset[str]] = set()
    for pair in raw_pairs:
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            continue
        left = _normalize_level(pair[0])
        right = _normalize_level(pair[1])
        if left and right and left != right:
            parsed.add(frozenset((left, right)))
    return parsed, "configured"


def _classify_violation(source_level: str, destination_level: str) -> tuple[str, str]:
    src = LEVEL_ORDER[source_level]
    dst = LEVEL_ORDER[destination_level]
    lower, upper = sorted((src, dst))

    # Any direct crossing from the control hierarchy into enterprise levels without
    # a DMZ endpoint is the main high-value Purdue boundary violation.
    if lower <= 3.0 and upper >= 4.0:
        return "dmz_bypass", "high"

    # Larger jumps inside either side of the model are still unexpected, but are
    # less severe than bypassing the industrial/enterprise boundary.
    if abs(src - dst) >= 2.0:
        return "non_adjacent_levels", "medium"
    return "policy_violation", "medium"


def _max_severity(values: Any) -> str:
    order = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    return max(values, key=lambda value: order.get(value, -1), default="medium")


def _clean_service(value: Any) -> str | None:
    text = str(value or "").strip()
    return text or None


def _first(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = row.get(key)
        if value is not None:
            return value
    return None


def _as_int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _level_sort_key(value: str) -> float:
    return LEVEL_ORDER.get(value, 99.0)


def _example_config() -> dict[str, Any]:
    return {
        "segments": [
            {"cidr": "10.0.0.0/24", "name": "Process", "purdue_level": "L0"},
            {"cidr": "10.1.0.0/24", "name": "Basic Control", "purdue_level": "L1"},
            {"cidr": "10.2.0.0/24", "name": "Area Supervisory", "purdue_level": "L2"},
            {"cidr": "10.3.0.0/24", "name": "Site Operations", "purdue_level": "L3"},
            {"cidr": "10.35.0.0/24", "name": "Industrial DMZ", "purdue_level": "DMZ"},
            {"cidr": "10.4.0.0/24", "name": "Enterprise", "purdue_level": "L4"},
            {"cidr": "10.5.0.0/24", "name": "External Enterprise", "purdue_level": "L5"},
        ],
        "purdue_policy": {
            "allowed_direct_pairs": [
                ["L0", "L1"], ["L1", "L2"], ["L2", "L3"],
                ["L3", "DMZ"], ["DMZ", "L4"], ["L4", "L5"],
            ]
        },
    }
