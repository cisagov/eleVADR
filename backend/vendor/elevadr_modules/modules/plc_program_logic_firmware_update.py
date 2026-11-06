from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import ipaddress
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata

MAX_EVIDENCE = 10

# Modbus FC90 (decimal 90 / 0x5A) is treated as a program/firmware-transfer
# indicator when exposed by the protocol decoder or site-specific implementation.
MODBUS_PROGRAM_CODES = {90}

# Siemens S7 job functions for block download/upload.
S7_DOWNLOAD_CODES = {0x1A, 0x1B, 0x1C}
S7_UPLOAD_CODES = {0x1D, 0x1E, 0x1F}

# DNP3 application functions associated with restart and file operations.
DNP3_COLD_RESTART_CODES = {13}
DNP3_FILE_CODES = {25, 26, 27, 28, 29, 30}

PROGRAM_TERMS = (
    "program download", "program upload", "logic download", "logic upload",
    "download block", "request download", "download end", "start upload",
    "end upload", "firmware update", "firmware download", "firmware upload",
    "firmware transfer", "flash update", "flash firmware", "flash download",
    "file transfer", "open file", "close file", "activate config",
)


@dataclass(slots=True)
class _Event:
    protocol: str
    row: dict[str, Any]
    source: str
    destination: str
    source_port: int | None
    destination_port: int | None
    timestamp: float | None
    operation: str
    function_code: int | None
    function_name: str | None


class PlcProgramLogicFirmwareUpdateModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="plc_program_logic_firmware_update",
        name="PLC Program / Logic Download or Firmware Update",
        description=(
            "Detects explicit ICS protocol operations associated with PLC program/logic transfer, "
            "firmware update, or DNP3 restart/file-transfer activity."
        ),
        category="security_analysis",
        required_logs=(),
        required_any_logs=("modbus", "s7comm", "enip", "dnp3"),
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        policy = _policy(context.metadata)
        events: list[_Event] = []
        for protocol, rows in (
            ("modbus", context.modbus),
            ("s7comm", context.s7comm),
            ("enip", context.enip),
            ("dnp3", context.dnp3),
        ):
            for row in rows:
                event = _event(protocol, row, policy)
                if event is not None:
                    events.append(event)

        findings = _findings(events, policy)
        devices = {device for finding in findings for device in finding.devices}
        by_protocol = {p: sum(e.protocol == p for e in events) for p in ("modbus", "s7comm", "enip", "dnp3")}

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "protocol_events_evaluated": len(context.modbus) + len(context.s7comm) + len(context.enip) + len(context.dnp3),
                "program_firmware_events": len(events),
                "modbus_program_firmware_events": by_protocol["modbus"],
                "s7comm_program_firmware_events": by_protocol["s7comm"],
                "enip_program_firmware_events": by_protocol["enip"],
                "dnp3_program_firmware_events": by_protocol["dnp3"],
                "program_firmware_findings": len(findings),
                "affected_devices": len(devices),
            },
            evidence={
                "inspected_logs": [name for name, rows in (
                    ("modbus", context.modbus), ("s7comm", context.s7comm),
                    ("enip", context.enip), ("dnp3", context.dnp3),
                ) if rows],
                "policy_loaded": bool(policy),
                "notes": [
                    "The detector requires explicit protocol-log function/service evidence and never infers a program or firmware transfer from an ICS port alone.",
                    "S7 block download functions 0x1A-0x1C and upload functions 0x1D-0x1F are treated as program-transfer evidence.",
                    "Modbus FC90 is treated as a program/firmware-transfer indicator when exposed by the decoder or implementation.",
                    "DNP3 cold restart and file-operation functions are surfaced because they can accompany configuration or firmware workflows; a restart alone does not prove that firmware changed.",
                    "CIP/EtherNet/IP firmware activity requires an explicit firmware/program/flash service name or a site-configured service code; TCP/44818 alone is insufficient.",
                    "Ordinary Modbus writes, generic CIP writes, and S7 Write Var operations remain the responsibility of the existing state-change modules unless program/firmware-specific evidence is present.",
                    "Evidence is capped at 10 representative events while full counts remain in finding metadata.",
                ],
            },
            warnings=[],
        )


def _event(protocol: str, row: dict[str, Any], policy: dict[str, Any]) -> _Event | None:
    code, name = _function(protocol, row)
    operation = _operation(protocol, code, name, policy)
    if operation is None:
        return None
    return _Event(
        protocol=protocol,
        row=row,
        source=_text(_first(row, "source_ip", "id.orig_h", "src", "source")),
        destination=_text(_first(row, "destination_ip", "id.resp_h", "dst", "destination")),
        source_port=_as_int(_first(row, "source_port", "id.orig_p", "src_port")),
        destination_port=_as_int(_first(row, "destination_port", "id.resp_p", "dst_port")),
        timestamp=_as_float(_first(row, "timestamp", "ts")),
        operation=operation,
        function_code=code,
        function_name=name,
    )


def _function(protocol: str, row: dict[str, Any]) -> tuple[int | None, str | None]:
    keys = {
        "modbus": ("function_code", "function", "function_name", "modbus_function", "fc", "operation"),
        "s7comm": ("function_code", "function", "function_id", "s7_function_code", "s7_function", "job_function", "command", "operation"),
        "enip": ("cip_service", "cip_service_code", "service_code", "service", "service_id", "service_name", "cip_service_name", "request_service", "function", "operation"),
        "dnp3": ("function_code", "function", "function_name", "application_function", "app_function", "operation"),
    }[protocol]
    value = _first(row, *keys)
    if value is None:
        return None, None
    code = _as_int(value)
    if code is not None:
        if protocol == "enip":
            code &= 0x7F
        return code, None
    text = _text(value)
    return None, text or None


def _operation(protocol: str, code: int | None, name: str | None, policy: dict[str, Any]) -> str | None:
    n = _norm(name or "")

    if protocol == "modbus":
        extra = set(_int_list(policy.get("additional_modbus_function_codes")))
        if code in MODBUS_PROGRAM_CODES | extra:
            return "program_or_firmware_transfer"
        if _contains_program_term(n):
            return "program_or_firmware_transfer"
        return None

    if protocol == "s7comm":
        if code in S7_DOWNLOAD_CODES:
            return "program_download"
        if code in S7_UPLOAD_CODES:
            return "program_upload"
        if "download" in n and ("block" in n or "program" in n or "logic" in n):
            return "program_download"
        if "upload" in n and ("block" in n or "program" in n or "logic" in n):
            return "program_upload"
        return None

    if protocol == "enip":
        extra = set(_int_list(policy.get("cip_firmware_service_codes")))
        if code is not None and code in extra:
            return "firmware_update"
        if any(term in n for term in ("firmware", "flash", "program download", "logic download", "download program")):
            return "firmware_update"
        if any(term in n for term in ("program upload", "logic upload", "upload program")):
            return "program_upload"
        return None

    if protocol == "dnp3":
        if code in DNP3_COLD_RESTART_CODES:
            return "cold_restart"
        if code in DNP3_FILE_CODES:
            return "file_transfer"
        if "cold restart" in n:
            return "cold_restart"
        if any(term in n for term in ("file transfer", "open file", "close file", "delete file", "get file info", "authenticate file", "abort file", "activate config")):
            return "file_transfer"
        return None

    return None


def _findings(events: list[_Event], policy: dict[str, Any]) -> list[Finding]:
    groups: dict[tuple[str, str, str, str], list[_Event]] = defaultdict(list)
    for event in events:
        if _allowed(event, policy):
            continue
        groups[(event.protocol, event.source, event.destination, event.operation)].append(event)

    findings: list[Finding] = []
    for (protocol, source, destination, operation), rows in sorted(groups.items()):
        severity = _severity(operation)
        title = _title(protocol, operation)
        summary = (
            f"Observed {len(rows)} explicit {protocol.upper()} event(s) from {source or 'unknown source'} to "
            f"{destination or 'unknown destination'} consistent with {operation.replace('_', ' ')}. "
            "Review whether this program/firmware activity was expected and authorized."
        )
        evidence_rows = rows[:MAX_EVIDENCE]
        findings.append(Finding(
            title=title,
            severity=severity,
            confidence="high",
            detection_basis="protocol_log",
            summary=summary,
            devices=sorted({x for row in rows for x in (row.source, row.destination) if x}),
            services=[protocol],
            ports=sorted({p for row in rows for p in (row.source_port, row.destination_port) if p is not None}),
            connection_pairs=[{"source": source, "destination": destination}],
            flows=[_flow(row) for row in evidence_rows],
            timestamps=[row.timestamp for row in evidence_rows if row.timestamp is not None],
            tags=[protocol, "ics", "plc", "program-transfer", "firmware-update", operation],
            metadata={
                "finding_type": "plc_program_logic_firmware_update",
                "protocol": protocol,
                "operation": operation,
                "event_count": len(rows),
                "function_codes": sorted({row.function_code for row in rows if row.function_code is not None}),
                "function_names": sorted({row.function_name for row in rows if row.function_name}),
                "evidence_event_count": len(evidence_rows),
                "evidence_truncated": len(rows) > MAX_EVIDENCE,
                "program_or_firmware_change_confirmed": operation != "cold_restart",
                "cold_restart_observed": operation == "cold_restart",
            },
        ))
    return findings


def _severity(operation: str) -> str:
    if operation in {"program_download", "firmware_update", "program_or_firmware_transfer", "file_transfer"}:
        return "high"
    if operation == "cold_restart":
        return "high"
    return "medium"


def _title(protocol: str, operation: str) -> str:
    labels = {
        "program_download": "PLC program/logic download observed",
        "program_upload": "PLC program/logic upload observed",
        "firmware_update": "PLC firmware update activity observed",
        "program_or_firmware_transfer": "PLC program/firmware transfer observed",
        "file_transfer": "DNP3 file-transfer activity observed",
        "cold_restart": "DNP3 cold restart observed",
    }
    return f"{labels.get(operation, 'PLC program/firmware activity observed')} ({protocol.upper()})"


def _allowed(event: _Event, policy: dict[str, Any]) -> bool:
    if not policy:
        return False
    for value in policy.get("allowed_hosts", []) or []:
        if _ip_matches(event.source, value) or _ip_matches(event.destination, value):
            return True
    for item in policy.get("allowed_pairs", []) or []:
        if not isinstance(item, dict):
            continue
        if _ip_matches(event.source, item.get("source")) and _ip_matches(event.destination, item.get("destination")):
            protocols = {_norm(str(x)) for x in item.get("protocols", []) or []}
            operations = {_norm(str(x)) for x in item.get("operations", []) or []}
            if protocols and _norm(event.protocol) not in protocols:
                continue
            if operations and _norm(event.operation) not in operations:
                continue
            return True
    return False


def _flow(event: _Event) -> dict[str, Any]:
    return {
        "timestamp": event.timestamp,
        "source_ip": event.source,
        "source_port": event.source_port,
        "destination_ip": event.destination,
        "destination_port": event.destination_port,
        "protocol": event.protocol,
        "operation": event.operation,
        "function_code": event.function_code,
        "function_name": event.function_name,
    }


def _contains_program_term(value: str) -> bool:
    return any(term in value for term in PROGRAM_TERMS)


def _policy(metadata: dict[str, Any]) -> dict[str, Any]:
    for key in ("plc_program_firmware_policy", "plc_program_logic_firmware_policy", "program_firmware_policy"):
        value = metadata.get(key)
        if isinstance(value, dict):
            return value
    return {}


def _first(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = row.get(key)
        if value not in (None, "", "-"):
            return value
    return None


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _norm(value: str) -> str:
    return " ".join(value.lower().replace("_", " ").replace("-", " ").split())


def _as_int(value: Any) -> int | None:
    if value in (None, "", "-"):
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip(), 0)
    except (TypeError, ValueError):
        try:
            return int(float(str(value).strip()))
        except (TypeError, ValueError):
            return None


def _as_float(value: Any) -> float | None:
    if value in (None, "", "-"):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _int_list(value: Any) -> list[int]:
    result: list[int] = []
    for item in value or []:
        parsed = _as_int(item)
        if parsed is not None:
            result.append(parsed)
    return result


def _ip_matches(ip: str, value: Any) -> bool:
    if not ip or value in (None, "", "-"):
        return False
    try:
        address = ipaddress.ip_address(ip)
        text = str(value).strip()
        if "/" in text:
            return address in ipaddress.ip_network(text, strict=False)
        return address == ipaddress.ip_address(text)
    except ValueError:
        return ip == str(value).strip()
