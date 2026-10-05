from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import ipaddress
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata


MAX_EVIDENCE = 10

MODBUS_WRITE_CODES = {5, 6, 15, 16, 22, 23}
MODBUS_WRITE_NAMES = {
    "write_single_coil",
    "write single coil",
    "write_single_register",
    "write single register",
    "write_multiple_coils",
    "write multiple coils",
    "write_multiple_registers",
    "write multiple registers",
    "mask_write_register",
    "mask write register",
    "read_write_multiple_registers",
    "read/write multiple registers",
    "read write multiple registers",
}

DNP3_CONTROL_CODES = {2, 3, 4, 5, 6}
MODBUS_FUNCTION_NAME_TO_CODE = {
    "read_coils": 1,
    "read_discrete_inputs": 2,
    "read_holding_registers": 3,
    "read_input_registers": 4,
    "write_single_coil": 5,
    "write_single_register": 6,
    "write_multiple_coils": 15,
    "write_multiple_registers": 16,
    "mask_write_register": 22,
    "read_write_multiple_registers": 23,
}

DNP3_CONTROL_NAMES = {
    "write",
    "select",
    "operate",
    "direct_operate",
    "direct operate",
    "direct_operate_nr",
    "direct operate no response",
    "direct_operate_no_response",
}


@dataclass(slots=True)
class _Event:
    protocol: str
    row: dict[str, Any]
    source: str
    destination: str
    source_port: int | None
    destination_port: int | None
    timestamp: float | str | None
    function_code: int | None
    function_name: str | None
    is_write: bool
    policy_status: str
    policy_reason: str


class IcsWriteOperationsModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="ics_write_operations",
        name="Modbus/DNP3 Write Operations Outside Allowed Paths",
        description=(
            "Detects Modbus write operations and DNP3 write/control operations outside configured "
            "source-to-destination paths, plus protocol function codes outside an optional approved profile."
        ),
        category="security_analysis",
        required_logs=(),
        required_any_logs=("modbus", "dnp3"),
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        policy = _policy(context.metadata)
        rows_by_protocol = {"modbus": context.modbus, "dnp3": context.dnp3}
        inspected = [name for name, rows in rows_by_protocol.items() if rows]
        if not inspected:
            return ModuleResult(
                module_id=self.metadata.id,
                findings=[],
                metrics={
                    "ics_protocol_events_evaluated": 0,
                    "write_or_control_events": 0,
                    "disallowed_path_events": 0,
                    "out_of_profile_function_events": 0,
                    "ics_write_findings": 0,
                    "affected_devices": 0,
                },
                evidence={
                    "inspected_logs": [],
                    "notes": [
                        "The detector requires Modbus or DNP3 protocol-log evidence and does not infer write operations from TCP/502 or port 20000 alone."
                    ],
                },
                warnings=[],
            )

        events: list[_Event] = []
        evaluated = 0
        for protocol, rows in rows_by_protocol.items():
            for row in rows:
                evaluated += 1
                event = _event_from_row(protocol, row, policy)
                if event is not None:
                    events.append(event)

        findings = _build_findings(events, policy_present=bool(policy))
        devices = {value for finding in findings for value in finding.devices}
        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "ics_protocol_events_evaluated": evaluated,
                "write_or_control_events": sum(event.is_write for event in events),
                "disallowed_path_events": sum(event.policy_status == "disallowed_path" for event in events),
                "out_of_profile_function_events": sum(event.policy_status == "out_of_profile_function" for event in events),
                "ics_write_findings": len(findings),
                "affected_devices": len(devices),
            },
            evidence={
                "inspected_logs": inspected,
                "policy_loaded": bool(policy),
                "notes": [
                    "Modbus write identification uses explicit function codes/names for write coils/registers; DNP3 uses explicit WRITE/SELECT/OPERATE/DIRECT_OPERATE request evidence.",
                    "A configured allowed-path policy is required to assert that a write occurred outside an approved control path.",
                    "When no policy is configured, explicit write/control operations are surfaced only as low-severity review findings rather than labeled policy violations.",
                    "Any explicit function code can be evaluated against configured allowed function-code profiles, including non-write functions.",
                    "Port-only Modbus/DNP3 traffic is not sufficient evidence for this module.",
                    "Evidence is capped at 10 representative protocol events while full counts remain in metadata.",
                ],
                "policy_example": {
                    "ics_write_policy": {
                        "allowed_paths": [
                            {
                                "protocol": "modbus",
                                "source": "10.10.1.10",
                                "destination": "10.10.2.20",
                                "allowed_function_codes": [3, 4, 5, 6, 15, 16],
                            }
                        ],
                        "allowed_function_codes": {"dnp3": [1, 2, 3, 4, 5, 6]},
                    }
                },
            },
            warnings=[],
        )


def _event_from_row(protocol: str, row: dict[str, Any], policy: dict[str, Any]) -> _Event | None:
    source = str(_first(row, "source_ip", "id.orig_h", "src", "source") or "")
    destination = str(_first(row, "destination_ip", "id.resp_h", "dst", "destination") or "")
    source_port = _as_int(_first(row, "source_port", "id.orig_p", "src_port"))
    destination_port = _as_int(_first(row, "destination_port", "id.resp_p", "dst_port"))
    timestamp = _first(row, "timestamp", "ts")
    code, name = _function(protocol, row)
    if code is None and name is None:
        return None

    is_write = _is_write(protocol, code, name)
    profile_allowed = _function_allowed(protocol, code, name, policy)
    path_allowed = _path_allowed(protocol, source, destination, code, name, policy)

    if profile_allowed is False:
        status = "out_of_profile_function"
        reason = "Function code/name is outside the configured protocol profile."
    elif is_write and path_allowed is False:
        status = "disallowed_path"
        reason = "Write/control operation does not match an allowed source-to-destination path."
    elif is_write and path_allowed is None:
        status = "unprofiled_write"
        reason = "Write/control operation was observed but no allowed-path policy is configured."
    else:
        return None

    return _Event(
        protocol=protocol,
        row=row,
        source=source,
        destination=destination,
        source_port=source_port,
        destination_port=destination_port,
        timestamp=timestamp,
        function_code=code,
        function_name=name,
        is_write=is_write,
        policy_status=status,
        policy_reason=reason,
    )


def _build_findings(events: list[_Event], *, policy_present: bool) -> list[Finding]:
    groups: dict[tuple[str, str, str, str], list[_Event]] = defaultdict(list)
    for event in events:
        groups[(event.protocol, event.policy_status, event.source, event.destination)].append(event)

    findings: list[Finding] = []
    for (protocol, status, source, destination), rows in sorted(groups.items()):
        write_count = sum(row.is_write for row in rows)
        functions = sorted({_function_label(row) for row in rows})

        if status == "disallowed_path":
            severity = "high"
            confidence = "high"
            title = f"{protocol.upper()} write/control operation outside allowed path"
            summary = (
                f"Observed {len(rows)} explicit {protocol.upper()} write/control event(s) from {source or 'unknown source'} "
                f"to {destination or 'unknown destination'} that do not match the configured allowed control paths. "
                "Review whether the source is authorized to issue state-changing commands to this destination."
            )
        elif status == "out_of_profile_function":
            severity = "medium" if not write_count else "high"
            confidence = "high"
            title = f"{protocol.upper()} function code outside approved profile"
            summary = (
                f"Observed {len(rows)} {protocol.upper()} protocol event(s) using function(s) outside the configured "
                f"approved function-code profile: {', '.join(functions)}."
            )
        else:
            severity = "low"
            confidence = "high"
            title = f"{protocol.upper()} write/control operation observed; path policy unavailable"
            summary = (
                f"Observed {len(rows)} explicit {protocol.upper()} write/control event(s) from {source or 'unknown source'} "
                f"to {destination or 'unknown destination'}, but no allowed-path policy is configured. The module can confirm "
                "the state-changing operation but cannot determine whether the path is authorized."
            )

        devices = sorted({value for row in rows for value in (row.source, row.destination) if value})
        ports = sorted({row.destination_port for row in rows if row.destination_port is not None})
        pairs = []
        if source or destination:
            pairs.append({
                "source": source or None,
                "destination": destination or None,
                "port": rows[0].destination_port,
                "protocol": "tcp" if protocol == "modbus" else str(_first(rows[0].row, "protocol", "proto") or ""),
                "service": protocol.upper(),
            })
        evidence = [row.row for row in rows[:MAX_EVIDENCE]]
        timestamps = [row.timestamp for row in rows[:MAX_EVIDENCE] if row.timestamp is not None]

        findings.append(Finding(
            title=title,
            severity=severity,
            summary=summary,
            confidence=confidence,
            detection_basis="protocol_log",
            devices=devices,
            services=[protocol.upper()],
            ports=ports,
            connection_pairs=pairs,
            flows=evidence,
            subnets=[],
            timestamps=timestamps,
            tags=[protocol, "ics", "write-operation" if write_count else "function-profile", status],
            metadata={
                "protocol": protocol,
                "policy_status": status,
                "event_count": len(rows),
                "write_or_control_event_count": write_count,
                "function_codes": sorted({row.function_code for row in rows if row.function_code is not None}),
                "function_names": sorted({row.function_name for row in rows if row.function_name}),
                "policy_loaded": policy_present,
                "policy_reason": rows[0].policy_reason,
                "state_change_confirmed": bool(write_count),
                "unauthorized_operation_confirmed": status in {"disallowed_path", "out_of_profile_function"},
                "evidence_event_count": len(evidence),
                "evidence_truncated": len(rows) > MAX_EVIDENCE,
            },
        ))
    return findings


def _function(protocol: str, row: dict[str, Any]) -> tuple[int | None, str | None]:
    if protocol == "modbus":
        value = _first(row, "func", "function", "function_code", "fc", "func_code", "function_name")
    else:
        value = _first(row, "fc_request", "function_code", "function", "func", "request_function", "function_name")
    if value is None:
        return None, None
    code = _as_int(value)
    if code is not None:
        return code, None
    text = str(value).strip()
    return None, text if text else None


def _is_write(protocol: str, code: int | None, name: str | None) -> bool:
    normalized = (name or "").strip().lower().replace("-", "_")
    if protocol == "modbus":
        return code in MODBUS_WRITE_CODES or normalized in MODBUS_WRITE_NAMES or normalized.replace("_", " ") in MODBUS_WRITE_NAMES
    return code in DNP3_CONTROL_CODES or normalized in DNP3_CONTROL_NAMES or normalized.replace("_", " ") in DNP3_CONTROL_NAMES


def _function_allowed(protocol: str, code: int | None, name: str | None, policy: dict[str, Any]) -> bool | None:
    profiles = policy.get("allowed_function_codes") if isinstance(policy, dict) else None
    if not isinstance(profiles, dict) or protocol not in profiles:
        return None
    allowed = profiles.get(protocol)
    if not isinstance(allowed, list):
        return None
    return _matches_function(allowed, code, name)


def _path_allowed(protocol: str, source: str, destination: str, code: int | None, name: str | None, policy: dict[str, Any]) -> bool | None:
    paths = policy.get("allowed_paths") if isinstance(policy, dict) else None
    if not isinstance(paths, list):
        return None
    matching_protocol_paths = [item for item in paths if isinstance(item, dict) and str(item.get("protocol", "")).lower() == protocol]
    if not matching_protocol_paths:
        return None
    for item in matching_protocol_paths:
        if not _endpoint_matches(source, item.get("source")):
            continue
        if not _endpoint_matches(destination, item.get("destination")):
            continue
        allowed_functions = item.get("allowed_function_codes")
        if isinstance(allowed_functions, list) and not _matches_function(allowed_functions, code, name):
            continue
        return True
    return False


def _endpoint_matches(value: str, rule: Any) -> bool:
    if rule in (None, "", "*"):
        return True
    if not value:
        return False
    rules = rule if isinstance(rule, list) else [rule]
    for item in rules:
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


def _matches_function(allowed: list[Any], code: int | None, name: str | None) -> bool:
    normalized_name = (name or "").strip().lower().replace("-", "_").replace(" ", "_")
    name_code = MODBUS_FUNCTION_NAME_TO_CODE.get(normalized_name)
    for item in allowed:
        item_code = _as_int(item)
        if code is not None and item_code == code:
            return True
        if name_code is not None and item_code == name_code:
            return True
        text = str(item).strip().lower().replace("-", "_").replace(" ", "_")
        if normalized_name and text == normalized_name:
            return True
    return False


def _policy(metadata: dict[str, Any]) -> dict[str, Any]:
    value = metadata.get("ics_write_policy")
    return value if isinstance(value, dict) else {}


def _function_label(event: _Event) -> str:
    if event.function_code is not None:
        return str(event.function_code)
    return event.function_name or "unknown"


def _first(row: dict[str, Any], *names: str) -> Any:
    for name in names:
        value = row.get(name)
        if value is not None and value != "":
            return value
    return None


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return None
