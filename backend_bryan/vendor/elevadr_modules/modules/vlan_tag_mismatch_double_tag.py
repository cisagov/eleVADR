from __future__ import annotations

from collections import defaultdict
import ipaddress
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata


MAX_EVIDENCE = 10
VLAN_MIN = 0
VLAN_MAX = 4095


class VlanTagMismatchDoubleTagModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="vlan_tag_mismatch_double_tag",
        name="VLAN Tag Mismatch / Double-Tag Indicators",
        description=(
            "Detects explicit 802.1Q VLAN IDs in Zeek conn.log that fall outside configured VLAN policy, "
            "and double-tagged/Q-in-Q connections that may indicate VLAN hopping or unexpected trunk/provider tagging."
        ),
        category="security_analysis",
        required_logs=("conn",),
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        policy = _policy(context.metadata)
        segments = _segments(context.metadata)
        tagged = []
        double_tagged = []
        mismatches = []

        for row in context.connections:
            outer = _vlan_id(_first(row, "vlan", "outer_vlan", "vlan_id", "dot1q_vlan"))
            inner = _vlan_id(_first(row, "inner_vlan", "inner_vlan_id", "qinq_inner_vlan", "dot1q_inner_vlan"))
            if outer is None and inner is None:
                continue

            item = {
                "row": row,
                "outer": outer,
                "inner": inner,
                "expected": _expected_vlans_for_row(row, policy, segments),
            }
            tagged.append(item)

            if outer is not None and inner is not None:
                if not _allowed_double_tag_pair(outer, inner, policy):
                    double_tagged.append(item)

            unexpected = _unexpected_tags(outer, inner, item["expected"])
            if unexpected:
                item["unexpected"] = unexpected
                mismatches.append(item)

        findings = _double_tag_findings(double_tagged) + _mismatch_findings(mismatches)

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "connections_evaluated": len(context.connections),
                "tagged_connections": len(tagged),
                "double_tagged_connections": len(double_tagged),
                "vlan_mismatch_connections": len(mismatches),
                "vlan_findings": len(findings),
            },
            evidence={
                "inspected_logs": ["conn"],
                "policy_loaded": bool(policy),
                "configured_allowed_vlan_ids": sorted(_global_allowed(policy)),
                "configured_allowed_double_tag_pairs": _pair_list(policy),
                "notes": [
                    "The detector uses explicit Zeek conn.log VLAN fields such as vlan and inner_vlan; it does not infer tagging from IP subnets or switch behavior.",
                    "A VLAN mismatch requires configured expected VLAN IDs, either globally through vlan_policy.allowed_vlan_ids or through segment VLAN metadata.",
                    "Segment-derived mismatch checks are used only when the participating endpoints produce one unambiguous expected VLAN set; routed flows spanning differently tagged segments are not guessed from IP addressing.",
                    "A populated outer and inner VLAN field is treated as explicit double-tag/Q-in-Q evidence. Legitimate provider bridging or trunk designs can use Q-in-Q, so approved pairs can be allow-listed.",
                    "Double-tag presence is an indicator, not proof of VLAN hopping. Findings describe the observed tagging and retain representative conn.log records.",
                    "Evidence is capped at 10 representative records while full counts remain in finding metadata.",
                ],
            },
            warnings=[],
        )


def _double_tag_findings(items: list[dict[str, Any]]) -> list[Finding]:
    groups: dict[tuple[int, int], list[dict[str, Any]]] = defaultdict(list)
    for item in items:
        groups[(item["outer"], item["inner"])].append(item)

    findings: list[Finding] = []
    for (outer, inner), rows in sorted(groups.items()):
        # If policy also says one of the tags is unexpected, escalate the indicator.
        has_mismatch = any(item.get("unexpected") for item in rows)
        findings.append(
            _finding(
                title="Double-tagged 802.1Q traffic observed",
                severity="high" if has_mismatch else "medium",
                summary=(
                    f"Observed {len(rows)} connection(s) carrying an outer VLAN tag {outer} and inner VLAN tag {inner}. "
                    "Double tagging can be legitimate on Q-in-Q/provider or trunk links, but it is also a prerequisite for some VLAN-hopping techniques. "
                    "Validate that this tag pair is expected at the capture point and on the associated switch path."
                ),
                rows=rows,
                tags=["vlan", "802.1q", "double-tag", "qinq", "vlan-hopping-indicator"],
                metadata={
                    "finding_type": "double_tag_indicator",
                    "outer_vlan": outer,
                    "inner_vlan": inner,
                    "connection_count": len(rows),
                    "vlan_policy_mismatch_also_observed": has_mismatch,
                    "malicious_activity_confirmed": False,
                },
            )
        )
    return findings


def _mismatch_findings(items: list[dict[str, Any]]) -> list[Finding]:
    groups: dict[tuple[tuple[int, ...], tuple[int, ...]], list[dict[str, Any]]] = defaultdict(list)
    for item in items:
        expected = tuple(sorted(item["expected"]))
        unexpected = tuple(sorted(item["unexpected"]))
        groups[(expected, unexpected)].append(item)

    findings: list[Finding] = []
    for (expected, unexpected), rows in sorted(groups.items()):
        findings.append(
            _finding(
                title="Unexpected 802.1Q VLAN tag observed",
                severity="high",
                summary=(
                    f"Observed {len(rows)} connection(s) carrying VLAN tag(s) {', '.join(map(str, unexpected))} outside the "
                    f"configured expected VLAN set {', '.join(map(str, expected))}. Unexpected tags can indicate a trunking/configuration error, "
                    "misplaced traffic, or attempted VLAN boundary bypass and should be validated against switch and sensor placement."
                ),
                rows=rows,
                tags=["vlan", "802.1q", "tag-mismatch", "segmentation"],
                metadata={
                    "finding_type": "unexpected_vlan_tag",
                    "expected_vlan_ids": list(expected),
                    "unexpected_vlan_ids": list(unexpected),
                    "connection_count": len(rows),
                },
            )
        )
    return findings


def _finding(
    *,
    title: str,
    severity: str,
    summary: str,
    rows: list[dict[str, Any]],
    tags: list[str],
    metadata: dict[str, Any],
) -> Finding:
    raw_rows = [item["row"] for item in rows]
    devices = sorted({
        str(value)
        for row in raw_rows
        for value in (_first(row, "source_ip", "id.orig_h"), _first(row, "destination_ip", "id.resp_h"))
        if value not in (None, "")
    })
    ports = sorted({
        value
        for row in raw_rows
        if (value := _as_int(_first(row, "destination_port", "id.resp_p"))) is not None
    })
    services = sorted({str(row.get("service")) for row in raw_rows if row.get("service") not in (None, "", "-")})
    timestamps = sorted(
        {_first(row, "timestamp", "ts") for row in raw_rows if _first(row, "timestamp", "ts") is not None},
        key=str,
    )
    pairs = []
    seen = set()
    for row in raw_rows:
        pair = (
            _first(row, "source_ip", "id.orig_h"),
            _first(row, "destination_ip", "id.resp_h"),
            _as_int(_first(row, "destination_port", "id.resp_p")),
        )
        if pair in seen:
            continue
        seen.add(pair)
        pairs.append({"source": pair[0], "destination": pair[1], "port": pair[2]})

    metadata = dict(metadata)
    metadata["evidence_truncated"] = len(raw_rows) > MAX_EVIDENCE
    return Finding(
        title=title,
        severity=severity,
        summary=summary,
        confidence="high",
        detection_basis="protocol_log",
        devices=devices,
        services=services,
        ports=ports,
        connection_pairs=pairs,
        flows=raw_rows[:MAX_EVIDENCE],
        timestamps=timestamps,
        tags=tags,
        metadata=metadata,
    )


def _unexpected_tags(outer: int | None, inner: int | None, expected: set[int]) -> list[int]:
    if not expected:
        return []
    return sorted({tag for tag in (outer, inner) if tag is not None and tag not in expected})


def _expected_vlans_for_row(
    row: dict[str, Any], policy: dict[str, Any], segments: list[tuple[ipaddress._BaseNetwork, set[int]]]
) -> set[int]:
    global_allowed = _global_allowed(policy)
    if global_allowed:
        return global_allowed

    source = str(_first(row, "source_ip", "id.orig_h") or "")
    destination = str(_first(row, "destination_ip", "id.resp_h") or "")
    src = _segment_vlans(source, segments)
    dst = _segment_vlans(destination, segments)

    configured = [value for value in (src, dst) if value]
    if not configured:
        return set()
    if len(configured) == 1:
        return configured[0]
    if configured[0] == configured[1]:
        return configured[0]
    # Different VLAN expectations on the two routed endpoints do not reveal which tag
    # should be visible at this sensor, so do not manufacture a mismatch.
    return set()


def _segments(metadata: dict[str, Any]) -> list[tuple[ipaddress._BaseNetwork, set[int]]]:
    raw = metadata.get("segments")
    if not isinstance(raw, list):
        return []
    result = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        cidr = str(item.get("cidr") or item.get("subnet") or "").strip()
        if not cidr:
            continue
        vlans = _ids(
            item.get("vlan_ids")
            if item.get("vlan_ids") is not None
            else item.get("allowed_vlan_ids")
            if item.get("allowed_vlan_ids") is not None
            else item.get("vlan_id")
            if item.get("vlan_id") is not None
            else item.get("vlan")
        )
        if not vlans:
            continue
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        result.append((network, vlans))
    return result


def _segment_vlans(value: str, segments: list[tuple[ipaddress._BaseNetwork, set[int]]]) -> set[int]:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return set()
    matches = [(network.prefixlen, vlans) for network, vlans in segments if address in network]
    if not matches:
        return set()
    return max(matches, key=lambda item: item[0])[1]


def _policy(metadata: dict[str, Any]) -> dict[str, Any]:
    value = metadata.get("vlan_policy")
    return value if isinstance(value, dict) else {}


def _global_allowed(policy: dict[str, Any]) -> set[int]:
    return _ids(policy.get("allowed_vlan_ids"))


def _allowed_double_tag_pair(outer: int, inner: int, policy: dict[str, Any]) -> bool:
    pairs = policy.get("allowed_double_tag_pairs")
    if not isinstance(pairs, list):
        return False
    for item in pairs:
        if isinstance(item, dict):
            allowed_outer = _vlan_id(item.get("outer"))
            allowed_inner = _vlan_id(item.get("inner"))
            if allowed_outer == outer and allowed_inner == inner:
                return True
        elif isinstance(item, (list, tuple)) and len(item) >= 2:
            if _vlan_id(item[0]) == outer and _vlan_id(item[1]) == inner:
                return True
        elif isinstance(item, str) and ":" in item:
            left, right = item.split(":", 1)
            if _vlan_id(left) == outer and _vlan_id(right) == inner:
                return True
    return False


def _pair_list(policy: dict[str, Any]) -> list[dict[str, int]]:
    result: list[dict[str, int]] = []
    pairs = policy.get("allowed_double_tag_pairs")
    if not isinstance(pairs, list):
        return result
    seen: set[tuple[int, int]] = set()
    for item in pairs:
        outer = inner = None
        if isinstance(item, dict):
            outer = _vlan_id(item.get("outer"))
            inner = _vlan_id(item.get("inner"))
        elif isinstance(item, (list, tuple)) and len(item) >= 2:
            outer = _vlan_id(item[0])
            inner = _vlan_id(item[1])
        elif isinstance(item, str) and ":" in item:
            left, right = item.split(":", 1)
            outer = _vlan_id(left)
            inner = _vlan_id(right)
        if outer is not None and inner is not None and (outer, inner) not in seen:
            seen.add((outer, inner))
            result.append({"outer": outer, "inner": inner})
    return result


def _ids(value: Any) -> set[int]:
    values = value if isinstance(value, (list, tuple, set)) else [value]
    result: set[int] = set()
    for item in values:
        vlan = _vlan_id(item)
        if vlan is not None:
            result.add(vlan)
    return result


def _vlan_id(value: Any) -> int | None:
    if value in (None, "", "-"):
        return None
    try:
        number = int(str(value), 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError):
        return None
    return number if VLAN_MIN <= number <= VLAN_MAX else None


def _first(row: dict[str, Any], *names: str) -> Any:
    for name in names:
        value = row.get(name)
        if value not in (None, "", "-"):
            return value
    return None


def _as_int(value: Any) -> int | None:
    try:
        return int(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None
