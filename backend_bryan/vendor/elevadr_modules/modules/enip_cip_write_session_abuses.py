from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
import ipaddress
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata


MAX_EVIDENCE = 10
DEFAULT_FORWARD_OPEN_WINDOW = 60.0
DEFAULT_FORWARD_OPEN_THRESHOLD = 20
DEFAULT_FORWARD_OPEN_HIGH_THRESHOLD = 50
DEFAULT_FORWARD_OPEN_FAILURE_RATIO = 0.50

# Common Logix/CIP write services plus generic Set_Attribute_Single.
CIP_WRITE_CODES = {0x10, 0x4D, 0x53}
CIP_WRITE_NAMES = {
    "set_attribute_single",
    "set attribute single",
    "write_tag",
    "write tag",
    "write_tag_fragmented",
    "write tag fragmented",
    "write fragmented tag",
}

FORWARD_OPEN_CODES = {0x54, 0x5B}
FORWARD_OPEN_NAMES = {
    "forward_open",
    "forward open",
    "large_forward_open",
    "large forward open",
}


@dataclass(slots=True)
class _CipEvent:
    row: dict[str, Any]
    source: str
    destination: str
    source_port: int | None
    destination_port: int | None
    timestamp: float | None
    service_code: int | None
    service_name: str | None
    kind: str
    success: bool | None


class EnipCipWriteSessionAbusesModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="enip_cip_write_session_abuses",
        name="EtherNet/IP CIP Write and Session Abuses",
        description=(
            "Detects explicit CIP write services and excessive Forward_Open/Large_Forward_Open activity "
            "in EtherNet/IP telemetry, with optional policy checks for approved write paths."
        ),
        category="security_analysis",
        required_logs=("enip",),
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        if not context.enip:
            return ModuleResult(
                module_id=self.metadata.id,
                findings=[],
                metrics={
                    "enip_events_evaluated": 0,
                    "cip_write_events": 0,
                    "forward_open_events": 0,
                    "forward_open_abuse_windows": 0,
                    "enip_cip_findings": 0,
                    "affected_devices": 0,
                },
                evidence={
                    "inspected_logs": [],
                    "notes": [
                        "The detector requires EtherNet/IP/CIP protocol-log evidence and never infers writes or Forward_Open activity from TCP/44818 or UDP/2222 alone."
                    ],
                },
                warnings=[],
            )

        policy = _policy(context.metadata)
        events = [_event(row) for row in context.enip]
        events = [event for event in events if event is not None]
        writes = [event for event in events if event.kind == "write"]
        opens = [event for event in events if event.kind == "forward_open"]

        findings = []
        findings.extend(_write_findings(writes, policy))
        abuse_findings, abuse_windows = _forward_open_findings(opens, policy)
        findings.extend(abuse_findings)

        devices = {device for finding in findings for device in finding.devices}
        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "enip_events_evaluated": len(context.enip),
                "classified_cip_events": len(events),
                "cip_write_events": len(writes),
                "forward_open_events": len(opens),
                "forward_open_abuse_windows": abuse_windows,
                "enip_cip_findings": len(findings),
                "affected_devices": len(devices),
            },
            evidence={
                "inspected_logs": ["enip"],
                "policy_loaded": bool(policy),
                "notes": [
                    "CIP writes require explicit service-code/name evidence such as Write Tag (0x4D), Write Tag Fragmented (0x53), or Set Attribute Single (0x10).",
                    "Forward_Open abuse requires explicit Forward_Open/Large_Forward_Open service evidence and is evaluated as a time-windowed behavioral pattern.",
                    "Repeated Forward_Open activity can result from controller reconnect storms, commissioning, or unstable networks; findings indicate abnormal session establishment behavior, not confirmed malicious control.",
                    "When no write-path policy is configured, explicit CIP writes are surfaced as low-severity review findings rather than labeled unauthorized.",
                    "TCP/44818 and UDP/2222 alone are never sufficient evidence for a finding.",
                    "Evidence is capped at 10 representative events while full counts remain in finding metadata.",
                ],
                "policy": {
                    "forward_open_window_seconds": _float_policy(policy, "forward_open_window_seconds", DEFAULT_FORWARD_OPEN_WINDOW),
                    "forward_open_threshold": _int_policy(policy, "forward_open_threshold", DEFAULT_FORWARD_OPEN_THRESHOLD),
                    "forward_open_high_threshold": _int_policy(policy, "forward_open_high_threshold", DEFAULT_FORWARD_OPEN_HIGH_THRESHOLD),
                    "forward_open_failure_ratio": _float_policy(policy, "forward_open_failure_ratio", DEFAULT_FORWARD_OPEN_FAILURE_RATIO),
                },
            },
            warnings=[],
        )


def _event(row: dict[str, Any]) -> _CipEvent | None:
    code, name = _service(row)
    kind = _kind(code, name)
    if kind is None:
        return None
    source = str(_first(row, "source_ip", "id.orig_h", "src", "source") or "")
    destination = str(_first(row, "destination_ip", "id.resp_h", "dst", "destination") or "")
    return _CipEvent(
        row=row,
        source=source,
        destination=destination,
        source_port=_as_int(_first(row, "source_port", "id.orig_p", "src_port")),
        destination_port=_as_int(_first(row, "destination_port", "id.resp_p", "dst_port")),
        timestamp=_as_float(_first(row, "timestamp", "ts")),
        service_code=code,
        service_name=name,
        kind=kind,
        success=_success(row),
    )


def _service(row: dict[str, Any]) -> tuple[int | None, str | None]:
    value = _first(
        row,
        "cip_service",
        "cip_service_code",
        "service_code",
        "service",
        "service_id",
        "service_name",
        "cip_service_name",
        "request_service",
        "request_service_code",
        "function",
    )
    if value is None:
        return None, None
    code = _as_int(value)
    if code is not None:
        # Some decoders set the response bit (0x80). Normalize to request service.
        return code & 0x7F, None
    text = str(value).strip()
    return None, text if text else None


def _kind(code: int | None, name: str | None) -> str | None:
    normalized = _norm(name)
    if code in CIP_WRITE_CODES or normalized in {_norm(value) for value in CIP_WRITE_NAMES}:
        return "write"
    if code in FORWARD_OPEN_CODES or normalized in {_norm(value) for value in FORWARD_OPEN_NAMES}:
        return "forward_open"
    return None


def _success(row: dict[str, Any]) -> bool | None:
    explicit = _first(row, "success", "succeeded", "ok", "accepted")
    parsed = _as_bool(explicit)
    if parsed is not None:
        return parsed

    status = _first(row, "general_status", "status", "cip_status", "response_status", "error_status")
    if status is None:
        return None
    number = _as_int(status)
    if number is not None:
        return number == 0
    text = str(status).strip().lower()
    if text in {"success", "ok", "accepted", "complete", "completed", "no error", "no_error"}:
        return True
    if any(token in text for token in ("fail", "error", "reject", "denied", "timeout", "invalid")):
        return False
    return None


def _write_findings(events: list[_CipEvent], policy: dict[str, Any]) -> list[Finding]:
    if not events:
        return []
    groups: dict[tuple[str, str], list[_CipEvent]] = defaultdict(list)
    for event in events:
        groups[(event.source, event.destination)].append(event)

    findings: list[Finding] = []
    for (source, destination), rows in sorted(groups.items()):
        allowed = _write_path_allowed(source, destination, rows, policy)
        if allowed is True:
            continue
        if allowed is False:
            severity = "high"
            title = "CIP write operation outside allowed EtherNet/IP path"
            summary = (
                f"Observed {len(rows)} explicit CIP write event(s) from {source or 'unknown source'} to "
                f"{destination or 'unknown destination'} outside the configured approved write paths. "
                "Review whether this source is authorized to issue state-changing CIP services to the destination."
            )
            policy_status = "disallowed_path"
            unauthorized = True
        else:
            severity = "low"
            title = "CIP write operation observed; write-path policy unavailable"
            summary = (
                f"Observed {len(rows)} explicit CIP write event(s) from {source or 'unknown source'} to "
                f"{destination or 'unknown destination'}. No approved CIP write-path policy is configured, so the "
                "module can confirm state-changing service use but cannot determine whether it is authorized."
            )
            policy_status = "unprofiled_write"
            unauthorized = False

        findings.append(_finding(
            title=title,
            severity=severity,
            confidence="high",
            summary=summary,
            rows=rows,
            tags=["ethernet-ip", "cip", "write", policy_status],
            metadata={
                "finding_type": "cip_write",
                "policy_status": policy_status,
                "event_count": len(rows),
                "service_codes": sorted({row.service_code for row in rows if row.service_code is not None}),
                "service_names": sorted({row.service_name for row in rows if row.service_name}),
                "state_change_confirmed": True,
                "unauthorized_operation_confirmed": unauthorized,
            },
        ))
    return findings


def _forward_open_findings(events: list[_CipEvent], policy: dict[str, Any]) -> tuple[list[Finding], int]:
    if not events:
        return [], 0

    window = _float_policy(policy, "forward_open_window_seconds", DEFAULT_FORWARD_OPEN_WINDOW)
    threshold = _int_policy(policy, "forward_open_threshold", DEFAULT_FORWARD_OPEN_THRESHOLD)
    high_threshold = _int_policy(policy, "forward_open_high_threshold", DEFAULT_FORWARD_OPEN_HIGH_THRESHOLD)
    failure_ratio_threshold = _float_policy(policy, "forward_open_failure_ratio", DEFAULT_FORWARD_OPEN_FAILURE_RATIO)

    groups: dict[tuple[str, str], list[_CipEvent]] = defaultdict(list)
    for event in events:
        if event.timestamp is not None:
            groups[(event.source, event.destination)].append(event)

    findings: list[Finding] = []
    abuse_windows = 0
    for (source, destination), rows in sorted(groups.items()):
        rows.sort(key=lambda item: item.timestamp or 0.0)
        q: deque[_CipEvent] = deque()
        best: list[_CipEvent] = []
        for row in rows:
            assert row.timestamp is not None
            q.append(row)
            while q and row.timestamp - (q[0].timestamp or row.timestamp) > window:
                q.popleft()
            if len(q) > len(best):
                best = list(q)

        if len(best) < threshold:
            continue

        failures = sum(item.success is False for item in best)
        known_results = sum(item.success is not None for item in best)
        failure_ratio = failures / known_results if known_results else None

        # Frequent successful opens can still be a reconnect/session churn signal, but use a
        # stronger count threshold unless failures corroborate instability/abuse.
        corroborated_failure = failure_ratio is not None and failure_ratio >= failure_ratio_threshold
        if len(best) < high_threshold and not corroborated_failure:
            continue

        abuse_windows += 1
        severity = "high" if len(best) >= high_threshold and corroborated_failure else "medium"
        confidence = "high" if known_results else "medium"
        reason = (
            f"{failures}/{known_results} requests with known results failed ({failure_ratio:.0%})"
            if failure_ratio is not None else
            "response status was not available for the observed requests"
        )
        summary = (
            f"Observed {len(best)} explicit CIP Forward_Open/Large_Forward_Open request(s) from "
            f"{source or 'unknown source'} to {destination or 'unknown destination'} within {window:g} seconds; {reason}. "
            "This can indicate excessive session establishment, reconnect storms, unstable communications, or abusive connection setup."
        )
        findings.append(_finding(
            title="Excessive EtherNet/IP CIP Forward_Open activity",
            severity=severity,
            confidence=confidence,
            summary=summary,
            rows=best,
            tags=["ethernet-ip", "cip", "forward-open", "session-abuse-signal"],
            metadata={
                "finding_type": "forward_open_abuse",
                "event_count": len(best),
                "window_seconds": window,
                "threshold": threshold,
                "high_threshold": high_threshold,
                "known_result_count": known_results,
                "failure_count": failures,
                "failure_ratio": failure_ratio,
                "session_abuse_confirmed": False,
                "malicious_control_confirmed": False,
            },
        ))

    return findings, abuse_windows


def _finding(*, title: str, severity: str, confidence: str, summary: str, rows: list[_CipEvent], tags: list[str], metadata: dict[str, Any]) -> Finding:
    evidence = [row.row for row in rows[:MAX_EVIDENCE]]
    timestamps = [row.timestamp for row in rows[:MAX_EVIDENCE] if row.timestamp is not None]
    devices = sorted({value for row in rows for value in (row.source, row.destination) if value})
    ports = sorted({row.destination_port for row in rows if row.destination_port is not None})
    pairs = []
    seen_pairs: set[tuple[str, str, int | None]] = set()
    for row in rows:
        key = (row.source, row.destination, row.destination_port)
        if key in seen_pairs:
            continue
        seen_pairs.add(key)
        pairs.append({
            "source": row.source or None,
            "destination": row.destination or None,
            "port": row.destination_port,
            "protocol": str(_first(row.row, "protocol", "proto") or "tcp"),
            "service": "EtherNet/IP CIP",
        })
        if len(pairs) >= MAX_EVIDENCE:
            break
    metadata = {
        **metadata,
        "evidence_event_count": len(evidence),
        "evidence_truncated": len(rows) > MAX_EVIDENCE,
    }
    return Finding(
        title=title,
        severity=severity,
        summary=summary,
        confidence=confidence,
        detection_basis="protocol_log",
        devices=devices,
        services=["EtherNet/IP CIP"],
        ports=ports,
        connection_pairs=pairs,
        flows=evidence,
        subnets=[],
        timestamps=timestamps,
        tags=tags,
        metadata=metadata,
    )


def _write_path_allowed(source: str, destination: str, rows: list[_CipEvent], policy: dict[str, Any]) -> bool | None:
    paths = policy.get("allowed_write_paths")
    if not isinstance(paths, list):
        return None
    if not paths:
        return False
    for item in paths:
        if not isinstance(item, dict):
            continue
        if not _endpoint_matches(source, item.get("source")) or not _endpoint_matches(destination, item.get("destination")):
            continue
        allowed_services = item.get("allowed_service_codes")
        if isinstance(allowed_services, list):
            if any(not _service_allowed(row, allowed_services) for row in rows):
                continue
        return True
    return False


def _service_allowed(row: _CipEvent, allowed: list[Any]) -> bool:
    for item in allowed:
        code = _as_int(item)
        if row.service_code is not None and code is not None and (code & 0x7F) == row.service_code:
            return True
        if row.service_name and _norm(str(item)) == _norm(row.service_name):
            return True
    return False


def _endpoint_matches(value: str, rule: Any) -> bool:
    if rule in (None, "", "*"):
        return True
    if not value:
        return False
    values = rule if isinstance(rule, list) else [rule]
    for item in values:
        text = str(item).strip()
        if not text:
            continue
        if value == text:
            return True
        try:
            if ipaddress.ip_address(value) in ipaddress.ip_network(text, strict=False):
                return True
        except ValueError:
            pass
    return False


def _policy(metadata: dict[str, Any]) -> dict[str, Any]:
    value = metadata.get("enip_cip_policy")
    return value if isinstance(value, dict) else {}


def _first(row: dict[str, Any], *names: str) -> Any:
    for name in names:
        value = row.get(name)
        if value is not None and value != "":
            return value
    return None


def _norm(value: str | None) -> str:
    return " ".join((value or "").strip().lower().replace("-", " ").replace("_", " ").split())


def _as_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip().lower()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        # Some telemetry emits bare hexadecimal service values such as "4d".
        if all(ch in "0123456789abcdef" for ch in text) and any(ch in "abcdef" for ch in text):
            try:
                return int(text, 16)
            except ValueError:
                return None
        return None


def _as_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _as_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in {"true", "t", "yes", "y", "1", "success", "ok"}:
        return True
    if text in {"false", "f", "no", "n", "0", "failed", "failure"}:
        return False
    return None


def _int_policy(policy: dict[str, Any], key: str, default: int) -> int:
    value = _as_int(policy.get(key))
    return value if value is not None and value > 0 else default


def _float_policy(policy: dict[str, Any], key: str, default: float) -> float:
    value = _as_float(policy.get(key))
    return value if value is not None and value > 0 else default
