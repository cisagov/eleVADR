from __future__ import annotations

from pathlib import PurePath
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata


MAX_EVIDENCE_FLOWS = 10

_FIRMWARE_EXTENSIONS = {
    ".bin", ".fw", ".firmware", ".img", ".rom", ".hex", ".dfu", ".upd",
    ".mot", ".s19", ".s28", ".s37", ".srec", ".elf",
}
_CONFIG_EXTENSIONS = {
    ".conf", ".cfg", ".ini", ".cnf", ".config", ".yaml", ".yml", ".toml",
    ".properties", ".env", ".reg", ".plist", ".xml",
}
_FTP_TRANSFER_COMMANDS = {"RETR", "STOR", "APPE", "STOU"}


class EngineeringToolsCleartextModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="engineering_tools_cleartext",
        name="Engineers Tools Over Clear-Text (TFTP/FTP)",
        description=(
            "Detects firmware or configuration material transferred using clear-text FTP or TFTP, "
            "using Zeek FTP/TFTP/file metadata rather than port-only inference."
        ),
        category="Insecure Engineering Transfer",
        required_logs=(),
        required_any_logs=("ftp", "tftp", "files"),
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        policy = _policy(context.metadata)
        findings: list[Finding] = []
        suppressed = 0
        protocol_events = 0

        seen_keys: set[tuple[Any, ...]] = set()

        # files.log gives the strongest evidence because Zeek has identified both
        # the transfer protocol and the file object.
        for row in context.files:
            protocol = _file_protocol(row)
            if protocol not in {"ftp", "tftp"}:
                continue
            protocol_events += 1
            category, basis = _classify_filename(_text(row.get("filename")), policy)
            if not category:
                continue
            if _suppressed(row, policy):
                suppressed += 1
                continue
            key = ("files", _text(row.get("file_uid") or row.get("fuid")), protocol, _text(row.get("filename")))
            if key in seen_keys:
                continue
            seen_keys.add(key)
            findings.append(_file_finding(row, protocol, category, basis))

        # FTP control-log fallback: only explicit transfer commands with a
        # firmware/config-looking argument qualify.
        for row in context.ftp:
            command = _text(row.get("command") or row.get("cmd")).upper()
            if command not in _FTP_TRANSFER_COMMANDS:
                continue
            protocol_events += 1
            filename = _text(row.get("argument") or row.get("arg"))
            category, basis = _classify_filename(filename, policy)
            if not category:
                continue
            if _suppressed(row, policy):
                suppressed += 1
                continue
            key = ("ftp", _text(row.get("uid")), command, filename, row.get("timestamp", row.get("ts")))
            if key in seen_keys:
                continue
            seen_keys.add(key)
            findings.append(_protocol_finding(row, "ftp", category, basis, filename, command=command))

        # TFTP log fallback. Common Zeek/Spicy TFTP logs expose fname and wrq;
        # alternate field spellings are accepted to make the detector portable.
        for row in context.tftp:
            protocol_events += 1
            filename = _text(row.get("filename") or row.get("fname") or row.get("file"))
            category, basis = _classify_filename(filename, policy)
            if not category:
                continue
            if _suppressed(row, policy):
                suppressed += 1
                continue
            operation = _tftp_operation(row)
            key = ("tftp", _text(row.get("uid")), operation, filename, row.get("timestamp", row.get("ts")))
            if key in seen_keys:
                continue
            seen_keys.add(key)
            findings.append(_protocol_finding(row, "tftp", category, basis, filename, command=operation))

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "ftp_records": len(context.ftp),
                "tftp_records": len(context.tftp),
                "files_records": len(context.files),
                "cleartext_transfer_events_evaluated": protocol_events,
                "firmware_config_findings": len(findings),
                "approved_transfer_events_suppressed": suppressed,
            },
            evidence={
                "inspected_logs": [name for name, rows in (("ftp", context.ftp), ("tftp", context.tftp), ("files", context.files)) if rows],
                "policy": policy,
                "notes": [
                    "FTP and TFTP are clear-text transfer protocols; this detector does not infer encryption merely from nonstandard ports.",
                    "A finding requires firmware/configuration filename evidence. Generic FTP/TFTP activity by itself is not reported.",
                    "files.log protocol attribution is preferred. FTP RETR/STOR/APPE/STOU and TFTP filename records provide a fallback when files.log is unavailable.",
                    "The signal establishes an insecure transfer mechanism, not that the transfer was unauthorized or malicious. Correlate with engineering change control and maintenance windows.",
                ],
            },
            warnings=[],
        )


def _file_finding(row: dict[str, Any], protocol: str, category: str, basis: str) -> Finding:
    filename = _text(row.get("filename")) or "(filename unavailable)"
    tx = _host_values(row.get("tx_hosts"))
    rx = _host_values(row.get("rx_hosts"))
    timestamp = row.get("timestamp", row.get("ts"))
    return Finding(
        title=f"{category.title()} transferred over clear-text {protocol.upper()}",
        severity="high" if category == "firmware" else "medium",
        confidence="high",
        detection_basis="protocol_log",
        summary=(
            f"Zeek identified {filename} as a {category} file transferred using clear-text {protocol.upper()}. "
            "Review whether the engineering transfer was expected and approved, and whether a protected transfer method is available."
        ),
        devices=sorted(set(tx + rx)),
        services=[protocol],
        connection_pairs=[{"source": source, "destination": dest} for source in tx for dest in rx][:MAX_EVIDENCE_FLOWS],
        flows=[row],
        timestamps=[timestamp] if timestamp is not None else [],
        tags=["cleartext-transfer", protocol, category],
        metadata={
            "protocol": protocol,
            "filename": None if filename == "(filename unavailable)" else filename,
            "sensitive_category": category,
            "classification_basis": basis,
            "file_uid": _text(row.get("file_uid") or row.get("fuid")) or None,
            "mime_type": _text(row.get("mime_type")) or None,
            "cleartext_confirmed": True,
            "authorization_confirmed": False,
        },
    )


def _protocol_finding(
    row: dict[str, Any],
    protocol: str,
    category: str,
    basis: str,
    filename: str,
    *,
    command: str,
) -> Finding:
    source = _text(row.get("source_ip") or row.get("id.orig_h"))
    destination = _text(row.get("destination_ip") or row.get("id.resp_h"))
    timestamp = row.get("timestamp", row.get("ts"))
    endpoints = [value for value in (source, destination) if value]
    return Finding(
        title=f"{category.title()} transfer over clear-text {protocol.upper()}",
        severity="high" if category == "firmware" else "medium",
        confidence="medium",
        detection_basis="protocol_log",
        summary=(
            f"Zeek observed {protocol.upper()} transfer operation {command or 'transfer'} for {filename} "
            f"whose filename indicates {category} material. The protocol carries transfer content without transport encryption."
        ),
        devices=endpoints,
        services=[protocol],
        ports=[port for port in [_as_int(row.get("destination_port") or row.get("id.resp_p"))] if port is not None],
        connection_pairs=[{"source": source, "destination": destination}] if source and destination else [],
        flows=[row],
        timestamps=[timestamp] if timestamp is not None else [],
        tags=["cleartext-transfer", protocol, category],
        metadata={
            "protocol": protocol,
            "filename": filename,
            "transfer_operation": command or None,
            "sensitive_category": category,
            "classification_basis": basis,
            "cleartext_confirmed": True,
            "authorization_confirmed": False,
        },
    )


def _file_protocol(row: dict[str, Any]) -> str | None:
    source = _text(row.get("source") or row.get("analyzer")).lower()
    if "tftp" in source:
        return "tftp"
    if source == "ftp" or source.startswith("ftp-") or "ftp_data" in source:
        return "ftp"
    return None


def _classify_filename(filename: str, policy: dict[str, Any]) -> tuple[str | None, str | None]:
    if not filename:
        return None, None
    extension = PurePath(filename.lower()).suffix
    firmware = _FIRMWARE_EXTENSIONS | set(policy["additional_firmware_extensions"])
    config = _CONFIG_EXTENSIONS | set(policy["additional_config_extensions"])
    if extension in firmware:
        return "firmware", "filename_extension"
    if extension in config:
        return "configuration", "filename_extension"
    return None, None


def _tftp_operation(row: dict[str, Any]) -> str:
    value = row.get("wrq")
    if isinstance(value, bool):
        return "WRQ" if value else "RRQ"
    text = _text(value).lower()
    if text in {"t", "true", "1", "yes", "wrq", "write"}:
        return "WRQ"
    if text in {"f", "false", "0", "no", "rrq", "read"}:
        return "RRQ"
    opcode = _text(row.get("opcode") or row.get("operation")).upper()
    return opcode


def _policy(metadata: dict[str, Any]) -> dict[str, Any]:
    raw = metadata.get("engineering_cleartext_policy") or metadata.get("ftp_tftp_policy") or {}
    if not isinstance(raw, dict):
        raw = {}
    return {
        "additional_firmware_extensions": _extensions(raw.get("additional_firmware_extensions")),
        "additional_config_extensions": _extensions(raw.get("additional_config_extensions")),
        "approved_hosts": _strings(raw.get("approved_hosts")),
    }


def _suppressed(row: dict[str, Any], policy: dict[str, Any]) -> bool:
    approved = set(policy["approved_hosts"])
    if not approved:
        return False
    hosts = set(_host_values(row.get("tx_hosts")) + _host_values(row.get("rx_hosts")))
    hosts.update(
        value for value in (
            _text(row.get("source_ip") or row.get("id.orig_h")),
            _text(row.get("destination_ip") or row.get("id.resp_h")),
        ) if value
    )
    return bool(hosts) and hosts.issubset(approved)


def _extensions(value: Any) -> list[str]:
    result = []
    for item in _strings(value):
        item = item.lower()
        result.append(item if item.startswith(".") else "." + item)
    return result


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value if str(item).strip()]
    return []


def _host_values(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        text = value.strip()
        if not text or text == "-":
            return []
        for delimiter in (",", ";"):
            if delimiter in text:
                return [part.strip() for part in text.split(delimiter) if part.strip()]
        return [text]
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value if str(item).strip()]
    return [str(value)]


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
