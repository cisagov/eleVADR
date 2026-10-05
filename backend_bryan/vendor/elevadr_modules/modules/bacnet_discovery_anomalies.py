from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
import ipaddress
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata


MAX_EVIDENCE = 10
DEFAULT_WINDOW_SECONDS = 60.0
DEFAULT_WHO_IS_THRESHOLD = 20
DEFAULT_I_AM_THRESHOLD = 50

DISCOVERY_WHO_IS = {"who is", "whois", "who_is"}
DISCOVERY_I_AM = {"i am", "iam", "i_am"}
ROLE_KEYS = ("role", "segment_role", "trust_zone", "security_zone", "zone", "type", "classification")
LEVEL_KEYS = ("purdue_level", "purdue", "level", "purdueLevel")


@dataclass(slots=True)
class _Segment:
    cidr: str
    name: str
    role: str
    purdue_level: str
    network: ipaddress._BaseNetwork


@dataclass(slots=True)
class _Event:
    row: dict[str, Any]
    kind: str
    source: str
    destination: str
    source_port: int | None
    destination_port: int | None
    timestamp: float | None


class BacnetDiscoveryAnomaliesModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="bacnet_discovery_anomalies",
        name="BACnet Who-Is/I-Am Flood or External Discovery",
        description=(
            "Detects abnormal BACnet Who-Is/I-Am discovery bursts and BACnet discovery activity "
            "originating from explicitly non-BAS network segments."
        ),
        category="security_analysis",
        required_logs=("bacnet",),
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        if not context.bacnet:
            return ModuleResult(
                module_id=self.metadata.id,
                findings=[],
                metrics={
                    "bacnet_events_evaluated": 0,
                    "bacnet_discovery_events": 0,
                    "who_is_events": 0,
                    "i_am_events": 0,
                    "discovery_burst_findings": 0,
                    "non_bas_discovery_findings": 0,
                    "bacnet_discovery_findings": 0,
                    "affected_devices": 0,
                },
                evidence={
                    "inspected_logs": [],
                    "notes": [
                        "The detector requires explicit BACnet protocol-log evidence and never infers Who-Is/I-Am discovery from UDP/47808-47823 alone."
                    ],
                },
                warnings=[],
            )

        policy = _policy(context.metadata)
        segments = _segments(context.metadata)
        events = [event for row in context.bacnet if (event := _event(row)) is not None]
        who_is = [event for event in events if event.kind == "who_is"]
        i_am = [event for event in events if event.kind == "i_am"]

        burst_findings = _burst_findings(events, policy)
        external_findings = _non_bas_findings(events, segments, policy)
        findings = burst_findings + external_findings
        devices = {device for finding in findings for device in finding.devices}

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "bacnet_events_evaluated": len(context.bacnet),
                "bacnet_discovery_events": len(events),
                "who_is_events": len(who_is),
                "i_am_events": len(i_am),
                "discovery_burst_findings": len(burst_findings),
                "non_bas_discovery_findings": len(external_findings),
                "bacnet_discovery_findings": len(findings),
                "affected_devices": len(devices),
            },
            evidence={
                "inspected_logs": ["bacnet"],
                "segment_metadata_loaded": bool(segments),
                "notes": [
                    "Who-Is and I-Am are normal BACnet discovery messages; their presence alone is not a finding.",
                    "Burst findings require explicit BACnet discovery messages concentrated inside a short sliding time window.",
                    "Non-BAS discovery findings require segment metadata that explicitly classifies the source outside BAS/OT/control networks; private addressing alone is not sufficient.",
                    "A non-BAS source issuing Who-Is can indicate unexpected building-automation discovery, but the finding does not independently prove reconnaissance or compromise.",
                    "Repeated I-Am messages can result from legitimate device discovery, commissioning, controller restarts, or misconfiguration and are evaluated with a higher default threshold than Who-Is.",
                    "UDP/47808-47823 without explicit BACnet Who-Is/I-Am protocol evidence never generates a finding.",
                    "Evidence is capped at 10 representative events while full counts remain in finding metadata.",
                ],
                "policy": {
                    "window_seconds": _float_policy(policy, "window_seconds", DEFAULT_WINDOW_SECONDS),
                    "who_is_threshold": _int_policy(policy, "who_is_threshold", DEFAULT_WHO_IS_THRESHOLD),
                    "i_am_threshold": _int_policy(policy, "i_am_threshold", DEFAULT_I_AM_THRESHOLD),
                },
            },
            warnings=[],
        )


def _event(row: dict[str, Any]) -> _Event | None:
    value = _first(
        row,
        "service",
        "service_name",
        "function",
        "function_name",
        "message_type",
        "message",
        "apdu_service",
        "confirmed_service",
        "unconfirmed_service",
        "bacnet_service",
        "pdu_type",
    )
    kind = _kind(value)
    if kind is None:
        return None
    return _Event(
        row=row,
        kind=kind,
        source=_text(_first(row, "source_ip", "id.orig_h", "src", "source")),
        destination=_text(_first(row, "destination_ip", "id.resp_h", "dst", "destination")),
        source_port=_as_int(_first(row, "source_port", "id.orig_p", "src_port")),
        destination_port=_as_int(_first(row, "destination_port", "id.resp_p", "dst_port")),
        timestamp=_as_float(_first(row, "timestamp", "ts")),
    )


def _kind(value: Any) -> str | None:
    if value is None:
        return None
    normalized = _norm(str(value))
    compact = normalized.replace(" ", "")
    if normalized in DISCOVERY_WHO_IS or compact == "whois" or "who is" in normalized:
        return "who_is"
    if normalized in DISCOVERY_I_AM or compact == "iam" or "i am" in normalized:
        return "i_am"
    return None


def _burst_findings(events: list[_Event], policy: dict[str, Any]) -> list[Finding]:
    window = _float_policy(policy, "window_seconds", DEFAULT_WINDOW_SECONDS)
    thresholds = {
        "who_is": _int_policy(policy, "who_is_threshold", DEFAULT_WHO_IS_THRESHOLD),
        "i_am": _int_policy(policy, "i_am_threshold", DEFAULT_I_AM_THRESHOLD),
    }
    groups: dict[tuple[str, str], list[_Event]] = defaultdict(list)
    for event in events:
        if event.timestamp is not None:
            groups[(event.kind, event.source)].append(event)

    findings: list[Finding] = []
    for (kind, source), rows in sorted(groups.items()):
        rows.sort(key=lambda item: item.timestamp or 0.0)
        best = _largest_window(rows, window)
        threshold = thresholds[kind]
        if len(best) < threshold:
            continue
        label = "Who-Is" if kind == "who_is" else "I-Am"
        severity = "medium" if kind == "who_is" else "low"
        summary = (
            f"Observed {len(best)} BACnet {label} discovery message(s) from {source or 'an unknown source'} "
            f"within {window:g} seconds, meeting the configured burst threshold of {threshold}. "
            + (
                "A dense Who-Is burst can be consistent with aggressive BACnet discovery or scanning; verify whether the source is an expected BAS management host."
                if kind == "who_is"
                else "Dense I-Am responses can occur during legitimate discovery or device restarts; review whether the volume is expected for this BAS segment."
            )
        )
        findings.append(_finding(
            title=f"BACnet {label} discovery burst",
            severity=severity,
            confidence="high",
            summary=summary,
            rows=best,
            tags=["bacnet", "discovery", kind.replace("_", "-"), "burst"],
            metadata={
                "finding_type": "discovery_burst",
                "discovery_type": kind,
                "event_count": len(best),
                "window_seconds": window,
                "threshold": threshold,
                "reconnaissance_confirmed": False,
            },
        ))
    return findings


def _largest_window(rows: list[_Event], window: float) -> list[_Event]:
    q: deque[_Event] = deque()
    best: list[_Event] = []
    for row in rows:
        assert row.timestamp is not None
        q.append(row)
        while q and row.timestamp - (q[0].timestamp or row.timestamp) > window:
            q.popleft()
        if len(q) > len(best):
            best = list(q)
    return best


def _non_bas_findings(events: list[_Event], segments: list[_Segment], policy: dict[str, Any]) -> list[Finding]:
    if not segments:
        return []
    allowed_sources = policy.get("allowed_discovery_sources")
    groups: dict[tuple[str, str, str], list[_Event]] = defaultdict(list)
    for event in events:
        segment = _segment_for_ip(event.source, segments)
        if segment is None or _segment_is_bas(segment):
            continue
        if _endpoint_allowed(event.source, allowed_sources):
            continue
        groups[(event.kind, event.source, segment.name or segment.cidr)].append(event)

    findings: list[Finding] = []
    for (kind, source, segment_name), rows in sorted(groups.items()):
        label = "Who-Is" if kind == "who_is" else "I-Am"
        severity = "medium" if kind == "who_is" else "low"
        summary = (
            f"Observed {len(rows)} explicit BACnet {label} discovery message(s) originating from {source} in segment "
            f"'{segment_name}', which is not classified as BAS/OT/control by the supplied segment metadata. "
            "Review whether BACnet discovery is authorized from this network location."
        )
        findings.append(_finding(
            title=f"BACnet {label} discovery from non-BAS segment",
            severity=severity,
            confidence="high",
            summary=summary,
            rows=rows,
            tags=["bacnet", "discovery", kind.replace("_", "-"), "non-bas-segment"],
            metadata={
                "finding_type": "non_bas_discovery",
                "discovery_type": kind,
                "event_count": len(rows),
                "source_segment": segment_name,
                "reconnaissance_confirmed": False,
            },
        ))
    return findings


def _finding(*, title: str, severity: str, confidence: str, summary: str, rows: list[_Event], tags: list[str], metadata: dict[str, Any]) -> Finding:
    evidence = [row.row for row in rows[:MAX_EVIDENCE]]
    timestamps = [row.timestamp for row in rows[:MAX_EVIDENCE] if row.timestamp is not None]
    devices = sorted({value for row in rows for value in (row.source, row.destination) if value})
    ports = sorted({port for row in rows for port in (row.source_port, row.destination_port) if port is not None})
    pairs = []
    seen: set[tuple[str, str, int | None]] = set()
    for row in rows:
        key = (row.source, row.destination, row.destination_port)
        if key in seen:
            continue
        seen.add(key)
        pairs.append({
            "source": row.source or None,
            "destination": row.destination or None,
            "port": row.destination_port,
            "protocol": str(_first(row.row, "protocol", "proto") or "udp"),
            "service": "BACnet",
        })
        if len(pairs) >= MAX_EVIDENCE:
            break
    return Finding(
        title=title,
        severity=severity,
        summary=summary,
        confidence=confidence,
        detection_basis="protocol_log",
        devices=devices,
        services=["BACnet"],
        ports=ports,
        connection_pairs=pairs,
        flows=evidence,
        subnets=[],
        timestamps=timestamps,
        tags=tags,
        metadata={
            **metadata,
            "evidence_event_count": len(evidence),
            "evidence_truncated": len(rows) > MAX_EVIDENCE,
        },
    )


def _segments(metadata: dict[str, Any]) -> list[_Segment]:
    raw = metadata.get("segments")
    if not isinstance(raw, list):
        return []
    result: list[_Segment] = []
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
        role = " ".join(_text(item.get(key)) for key in ROLE_KEYS if item.get(key) not in (None, "")).strip()
        level = " ".join(_text(item.get(key)) for key in LEVEL_KEYS if item.get(key) not in (None, "")).strip()
        name = _text(item.get("name") or item.get("label") or cidr)
        result.append(_Segment(cidr=cidr, name=name, role=role, purdue_level=level, network=network))
    result.sort(key=lambda item: item.network.prefixlen, reverse=True)
    return result


def _segment_for_ip(value: str, segments: list[_Segment]) -> _Segment | None:
    if not value:
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    return next((segment for segment in segments if address in segment.network), None)


def _segment_is_bas(segment: _Segment) -> bool:
    text = f"{segment.name} {segment.role}".lower().replace("-", " ").replace("_", " ")
    if any(token in text for token in ("bas", "building automation", "bacnet", "bms", "ot", "control", "ics", "scada")):
        return True
    level = _norm(segment.purdue_level).replace("level ", "")
    return level in {"l0", "0", "l1", "1", "l2", "2", "l3", "3"}


def _endpoint_allowed(value: str, rules: Any) -> bool:
    if not value or not isinstance(rules, list):
        return False
    for rule in rules:
        text = _text(rule)
        if not text:
            continue
        if value == text:
            return True
        try:
            if ipaddress.ip_address(value) in ipaddress.ip_network(text, strict=False):
                return True
        except ValueError:
            continue
    return False


def _policy(metadata: dict[str, Any]) -> dict[str, Any]:
    value = metadata.get("bacnet_discovery_policy")
    return value if isinstance(value, dict) else {}


def _first(row: dict[str, Any], *names: str) -> Any:
    for name in names:
        value = row.get(name)
        if value is not None and value != "":
            return value
    return None


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _norm(value: str) -> str:
    return " ".join(value.strip().lower().replace("-", " ").replace("_", " ").split())


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _as_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _int_policy(policy: dict[str, Any], key: str, default: int) -> int:
    value = _as_int(policy.get(key))
    return value if value is not None and value > 0 else default


def _float_policy(policy: dict[str, Any], key: str, default: float) -> float:
    value = _as_float(policy.get(key))
    return value if value is not None and value > 0 else default
