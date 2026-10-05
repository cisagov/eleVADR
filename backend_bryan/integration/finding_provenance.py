"""Attach Zeek-record provenance to detector findings.

Detector modules intentionally remain focused on detection semantics.  This
module resolves each finding's representative flows back to the shared
``AnalysisContext`` after a detector completes and records where those rows came
from.  The result is stable, machine-readable provenance without requiring 75
modules to duplicate source-tracking code.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import fields as dataclass_fields
from typing import Any


MAX_PROVENANCE_SOURCES = 10
SENSITIVE_FIELD_FRAGMENTS = (
    "password",
    "passwd",
    "community",
    "credential",
    "secret",
    "token",
    "authorization",
    "cookie",
)

_CONTEXT_LOG_NAMES = {
    "connections": "conn",
    "dns": "dns",
    "http": "http",
    "quic": "quic",
    "socks": "socks",
    "ftp": "ftp",
    "tftp": "tftp",
    "smtp": "smtp",
    "telnet": "telnet",
    "login": "login",
    "ssl": "ssl",
    "x509": "x509",
    "ssh": "ssh",
    "kerberos": "kerberos",
    "ntlm": "ntlm",
    "ldap": "ldap",
    "ldap_bind": "ldap_bind",
    "ldap_search": "ldap_search",
    "smb": "smb",
    "smb_mapping": "smb_mapping",
    "smb_files": "smb_files",
    "smb_cmd": "smb_cmd",
    "rdp": "rdp",
    "ssdp": "ssdp",
    "upnp": "upnp",
    "upnp_igd": "upnp_igd",
    "vnc": "vnc",
    "modbus": "modbus",
    "dnp3": "dnp3",
    "enip": "enip",
    "bacnet": "bacnet",
    "s7comm": "s7comm",
    "mms": "mms",
    "iec61850": "iec61850",
    "dhcp": "dhcp",
    "ntp": "ntp",
    "snmp": "snmp",
    "arp": "arp",
    "files": "files",
    "weird": "weird",
}


def _safe_value(key: str, value: Any) -> Any:
    lowered = key.lower()
    if any(fragment in lowered for fragment in SENSITIVE_FIELD_FRAGMENTS):
        return "<redacted>"
    return value


def _fields_for_row(row: Mapping[str, Any], *, keys: set[str] | None = None) -> dict[str, Any]:
    selected = row.keys() if keys is None else (key for key in row.keys() if key in keys)
    return {
        str(key): _safe_value(str(key), row[key])
        for key in sorted(selected, key=str)
    }


def _log_rows(context: Any) -> list[tuple[str, int, Mapping[str, Any]]]:
    rows: list[tuple[str, int, Mapping[str, Any]]] = []
    for attr, log_name in _CONTEXT_LOG_NAMES.items():
        value = getattr(context, attr, None)
        if not isinstance(value, list):
            continue
        for index, row in enumerate(value):
            if isinstance(row, Mapping):
                rows.append((log_name, index, row))
    return rows


def _declared_logs(module: Any) -> list[str]:
    metadata = getattr(module, "metadata", None)
    if metadata is None:
        return []
    names: list[str] = []
    for attr in ("required_logs", "required_any_logs"):
        value = getattr(metadata, attr, ())
        if isinstance(value, tuple):
            names.extend(str(name) for name in value)
    # Preserve declaration order while removing duplicates.
    return list(dict.fromkeys("conn" if name == "connections" else name for name in names))


def _row_matches_flow(row: Mapping[str, Any], flow: Mapping[str, Any]) -> tuple[bool, set[str]]:
    if row is flow:
        return True, set(flow.keys())
    common = set(row.keys()).intersection(flow.keys())
    if not common:
        return False, set()
    # A finding flow is frequently the original Zeek row, but some detectors
    # trim it.  Matching every shared field gives a deterministic subset match.
    if all(row[key] == flow[key] for key in common):
        return True, common
    return False, set()


def _finding_values(finding: Any) -> set[Any]:
    values: set[Any] = set()
    for attr in ("devices", "ports", "timestamps", "services"):
        for value in getattr(finding, attr, []) or []:
            try:
                hash(value)
            except TypeError:
                continue
            values.add(value)
    return values


def _fallback_rows(
    finding: Any,
    all_rows: list[tuple[str, int, Mapping[str, Any]]],
    declared_logs: list[str],
) -> list[tuple[str, int, Mapping[str, Any]]]:
    candidates = [item for item in all_rows if not declared_logs or item[0] in declared_logs]
    if not candidates:
        return []
    values = _finding_values(finding)
    if not values:
        return candidates[:1]

    scored: list[tuple[int, str, int, Mapping[str, Any]]] = []
    for log_name, index, row in candidates:
        score = sum(1 for value in row.values() if value in values)
        if score:
            scored.append((score, log_name, index, row))
    scored.sort(key=lambda item: (-item[0], item[1], item[2]))
    return [(log_name, index, row) for _score, log_name, index, row in scored[:MAX_PROVENANCE_SOURCES]]


def attach_finding_provenance(module: Any, result: Any, context: Any) -> Any:
    """Attach deterministic Zeek source references to every finding in ``result``.

    The attached ``finding.provenance`` object contains representative source
    records.  Each source identifies the Zeek log filename, zero-based parsed
    record index, and exact field/value pairs retained as finding evidence.
    Credential-like values are redacted.  Findings derived from absence or
    baseline state fall back to the closest declared-log rows and explicitly
    identify that resolution method.
    """
    findings = getattr(result, "findings", None)
    if not isinstance(findings, list):
        return result

    all_rows = _log_rows(context)
    identity = {id(row): (log_name, index, row) for log_name, index, row in all_rows}
    declared_logs = _declared_logs(module)

    for finding in findings:
        sources: list[dict[str, Any]] = []
        seen: set[tuple[str, int]] = set()
        flows = getattr(finding, "flows", None)
        if isinstance(flows, list):
            for flow in flows:
                if not isinstance(flow, Mapping):
                    continue
                matched: tuple[str, int, Mapping[str, Any]] | None = identity.get(id(flow))
                matched_keys: set[str] = set(flow.keys())
                match_method = "object_identity"
                if matched is None:
                    for log_name, index, row in all_rows:
                        is_match, common = _row_matches_flow(row, flow)
                        if is_match:
                            matched = (log_name, index, row)
                            matched_keys = common
                            match_method = "field_match"
                            break
                if matched is None:
                    continue
                log_name, index, row = matched
                key = (log_name, index)
                if key in seen:
                    continue
                seen.add(key)
                sources.append(
                    {
                        "log_type": f"{log_name}.log",
                        "record_index": index,
                        "fields": _fields_for_row(row, keys=matched_keys),
                        "match_method": match_method,
                    }
                )
                if len(sources) >= MAX_PROVENANCE_SOURCES:
                    break

        resolution = "representative_flow"
        if not sources:
            resolution = "correlated_declared_log"
            for log_name, index, row in _fallback_rows(finding, all_rows, declared_logs):
                key = (log_name, index)
                if key in seen:
                    continue
                seen.add(key)
                sources.append(
                    {
                        "log_type": f"{log_name}.log",
                        "record_index": index,
                        "fields": _fields_for_row(row),
                        "match_method": "finding_correlation",
                    }
                )
                if len(sources) >= MAX_PROVENANCE_SOURCES:
                    break

        # If no concrete row can be correlated (for example, an absence-based
        # finding on an otherwise empty log), retain the detector's declared
        # evidence source so the report still says precisely which Zeek log was
        # evaluated.  There are no fabricated field values in this case.
        if not sources and declared_logs:
            resolution = "declared_log_without_representative_row"
            sources = [
                {
                    "log_type": f"{name}.log",
                    "record_index": None,
                    "fields": {},
                    "match_method": "module_declaration",
                }
                for name in declared_logs[:MAX_PROVENANCE_SOURCES]
            ]

        provenance = {
            "schema_version": 1,
            "resolution": resolution,
            "sources": sources,
        }
        setattr(finding, "provenance", provenance)
        metadata = getattr(finding, "metadata", None)
        if isinstance(metadata, dict):
            metadata["zeek_provenance"] = provenance
    return result
