from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import ipaddress
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata


MAX_EVIDENCE = 10

# Siemens S7comm job/function identifiers commonly exposed by protocol decoders.
WRITE_CODES = {0x05}
DOWNLOAD_CODES = {0x1A, 0x1B, 0x1C}
CONTROL_CODES = {0x28}
STOP_CODES = {0x29}

WRITE_NAMES = {
    "write var", "write variable", "write_vars", "write_var", "write",
    "download block", "request download", "download end", "download",
    "plc control", "plc_control", "control",
}
STOP_NAMES = {
    "plc stop", "plc_stop", "stop plc", "stop cpu", "cpu stop", "stop",
}
READ_NAMES = {"read var", "read variable", "read_vars", "read_var", "read"}


@dataclass(slots=True)
class _Event:
    row: dict[str, Any]
    source: str
    destination: str
    source_port: int | None
    destination_port: int | None
    timestamp: float | None
    function_code: int | None
    function_name: str | None
    operation: str


class S7commUnauthorizedWriteStopModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="s7comm_unauthorized_write_stop",
        name="S7comm Unauthorized Write/Stop PLC",
        description=(
            "Detects explicit Siemens S7comm write/download/control operations and PLC STOP commands, "
            "with optional policy checks for approved source-to-destination control paths."
        ),
        category="security_analysis",
        required_logs=("s7comm",),
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        if not context.s7comm:
            return ModuleResult(
                module_id=self.metadata.id,
                findings=[],
                metrics={
                    "s7comm_events_evaluated": 0,
                    "state_changing_events": 0,
                    "write_control_events": 0,
                    "plc_stop_events": 0,
                    "s7comm_findings": 0,
                    "affected_devices": 0,
                },
                evidence={
                    "inspected_logs": [],
                    "notes": [
                        "The detector requires explicit S7comm protocol-log evidence and never infers a write or PLC STOP from TCP/102 alone."
                    ],
                },
                warnings=[],
            )

        policy = _policy(context.metadata)
        events = [event for row in context.s7comm if (event := _event(row)) is not None]
        state_changes = [event for event in events if event.operation in {"write", "download", "control", "stop"}]
        writes = [event for event in state_changes if event.operation != "stop"]
        stops = [event for event in state_changes if event.operation == "stop"]

        findings = _state_change_findings(writes, policy) + _stop_findings(stops, policy)
        devices = {device for finding in findings for device in finding.devices}

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "s7comm_events_evaluated": len(context.s7comm),
                "classified_s7comm_events": len(events),
                "state_changing_events": len(state_changes),
                "write_control_events": len(writes),
                "plc_stop_events": len(stops),
                "s7comm_findings": len(findings),
                "affected_devices": len(devices),
            },
            evidence={
                "inspected_logs": ["s7comm"],
                "policy_loaded": bool(policy),
                "notes": [
                    "Explicit S7comm function names/codes are required; TCP/102 alone never creates a finding.",
                    "Read-only S7 operations are ignored.",
                    "Write Var (0x05), download functions (0x1A-0x1C), PLC Control (0x28), and PLC Stop (0x29) are treated as state-changing operations when explicitly logged.",
                    "Without an authorization policy, state-changing operations are surfaced for review but are not labeled unauthorized.",
                    "PLC STOP is treated as higher impact than ordinary writes because it can halt controller execution; a policy violation raises severity further.",
                    "Evidence is capped at 10 representative events while full counts remain in finding metadata.",
                ],
            },
            warnings=[],
        )


def _event(row: dict[str, Any]) -> _Event | None:
    code, name = _function(row)
    operation = _operation(code, name)
    if operation is None:
        return None
    return _Event(
        row=row,
        source=_text(_first(row, "source_ip", "id.orig_h", "src", "source")),
        destination=_text(_first(row, "destination_ip", "id.resp_h", "dst", "destination")),
        source_port=_as_int(_first(row, "source_port", "id.orig_p", "src_port")),
        destination_port=_as_int(_first(row, "destination_port", "id.resp_p", "dst_port")),
        timestamp=_as_float(_first(row, "timestamp", "ts")),
        function_code=code,
        function_name=name,
        operation=operation,
    )


def _function(row: dict[str, Any]) -> tuple[int | None, str | None]:
    value = _first(
        row,
        "function_code",
        "function",
        "function_id",
        "s7_function_code",
        "s7_function",
        "parameter_function",
        "job_function",
        "command",
        "operation",
        "message_type",
    )
    if value is None:
        return None, None
    code = _as_int(value)
    if code is not None:
        return code, None
    text = _text(value)
    return None, text or None


def _operation(code: int | None, name: str | None) -> str | None:
    normalized = _norm(name or "")
    if code in STOP_CODES or normalized in {_norm(value) for value in STOP_NAMES} or "plc stop" in normalized or "cpu stop" in normalized:
        return "stop"
    if code in WRITE_CODES or normalized in {_norm(value) for value in WRITE_NAMES if "download" not in _norm(value) and "control" not in _norm(value)}:
        return "write"
    if code in DOWNLOAD_CODES or "download" in normalized:
        return "download"
    if code in CONTROL_CODES or "plc control" in normalized:
        return "control"
    if normalized in {_norm(value) for value in READ_NAMES}:
        return "read"
    return None


def _state_change_findings(events: list[_Event], policy: dict[str, Any]) -> list[Finding]:
    groups: dict[tuple[str, str], list[_Event]] = defaultdict(list)
    for event in events:
        groups[(event.source, event.destination)].append(event)

    findings: list[Finding] = []
    for (source, destination), rows in sorted(groups.items()):
        allowed = _path_allowed(source, destination, rows, policy)
        if allowed is True:
            continue
        operations = sorted({row.operation for row in rows})
        if allowed is False:
            severity = "high"
            title = "S7comm write/control operation outside allowed path"
            summary = (
                f"Observed {len(rows)} explicit S7comm state-changing operation(s) from {source or 'unknown source'} to "
                f"{destination or 'unknown destination'} outside the configured approved control paths. "
                "Review whether this source is authorized to modify or control the Siemens PLC."
            )
            policy_status = "disallowed_path"
            unauthorized = True
        else:
            severity = "low"
            title = "S7comm write/control operation observed; authorization policy unavailable"
            summary = (
                f"Observed {len(rows)} explicit S7comm state-changing operation(s) from {source or 'unknown source'} to "
                f"{destination or 'unknown destination'}. No approved S7comm control-path policy is configured, so the "
                "module can confirm the operation but cannot determine whether it is authorized."
            )
            policy_status = "unprofiled_state_change"
            unauthorized = False
        findings.append(_finding(
            title=title,
            severity=severity,
            confidence="high",
            summary=summary,
            rows=rows,
            tags=["s7comm", "siemens", "plc", "state-change", policy_status],
            metadata={
                "finding_type": "s7_state_change",
                "policy_status": policy_status,
                "event_count": len(rows),
                "operations": operations,
                "function_codes": sorted({row.function_code for row in rows if row.function_code is not None}),
                "function_names": sorted({row.function_name for row in rows if row.function_name}),
                "state_change_confirmed": True,
                "unauthorized_operation_confirmed": unauthorized,
            },
        ))
    return findings


def _stop_findings(events: list[_Event], policy: dict[str, Any]) -> list[Finding]:
    groups: dict[tuple[str, str], list[_Event]] = defaultdict(list)
    for event in events:
        groups[(event.source, event.destination)].append(event)

    findings: list[Finding] = []
    for (source, destination), rows in sorted(groups.items()):
        allowed = _path_allowed(source, destination, rows, policy)
        if allowed is True:
            continue
        if allowed is False:
            severity = "critical"
            title = "S7comm PLC STOP outside allowed control path"
            summary = (
                f"Observed {len(rows)} explicit S7comm PLC STOP command(s) from {source or 'unknown source'} to "
                f"{destination or 'unknown destination'} outside the configured approved control paths. "
                "A PLC STOP can halt controller execution and should be investigated immediately."
            )
            policy_status = "disallowed_path"
            unauthorized = True
        else:
            severity = "high"
            title = "S7comm PLC STOP command observed; authorization policy unavailable"
            summary = (
                f"Observed {len(rows)} explicit S7comm PLC STOP command(s) from {source or 'unknown source'} to "
                f"{destination or 'unknown destination'}. No authorization policy is configured, so the module cannot "
                "determine whether the stop was approved, but the operation can halt PLC execution and warrants review."
            )
            policy_status = "unprofiled_stop"
            unauthorized = False
        findings.append(_finding(
            title=title,
            severity=severity,
            confidence="high",
            summary=summary,
            rows=rows,
            tags=["s7comm", "siemens", "plc", "plc-stop", policy_status],
            metadata={
                "finding_type": "plc_stop",
                "policy_status": policy_status,
                "event_count": len(rows),
                "function_codes": sorted({row.function_code for row in rows if row.function_code is not None}),
                "function_names": sorted({row.function_name for row in rows if row.function_name}),
                "plc_stop_confirmed": True,
                "unauthorized_operation_confirmed": unauthorized,
            },
        ))
    return findings


def _path_allowed(source: str, destination: str, rows: list[_Event], policy: dict[str, Any]) -> bool | None:
    rules = policy.get("allowed_paths")
    if not isinstance(rules, list) or not rules:
        return None
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        if not _endpoint_matches(source, rule.get("source")) or not _endpoint_matches(destination, rule.get("destination")):
            continue
        allowed_ops = rule.get("allowed_operations")
        if isinstance(allowed_ops, list) and allowed_ops:
            normalized = {_norm(_text(value)) for value in allowed_ops}
            if any(_norm(row.operation) not in normalized for row in rows):
                continue
        allowed_codes = rule.get("allowed_function_codes")
        if isinstance(allowed_codes, list) and allowed_codes:
            codes = {_as_int(value) for value in allowed_codes}
            codes.discard(None)
            if any(row.function_code is not None and row.function_code not in codes for row in rows):
                continue
        return True
    return False


def _endpoint_matches(value: str, rule: Any) -> bool:
    text = _text(rule)
    if not text:
        return False
    if value == text:
        return True
    try:
        return ipaddress.ip_address(value) in ipaddress.ip_network(text, strict=False)
    except ValueError:
        return False


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
            "protocol": str(_first(row.row, "protocol", "proto") or "tcp"),
            "service": "S7comm",
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
        services=["S7comm"],
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


def _policy(metadata: dict[str, Any]) -> dict[str, Any]:
    value = metadata.get("s7comm_control_policy")
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
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip().lower()
    try:
        return int(text, 16) if text.startswith("0x") else int(text)
    except ValueError:
        return None


def _as_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
