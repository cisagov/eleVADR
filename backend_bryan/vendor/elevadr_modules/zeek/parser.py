from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from elevadr_modules.models import AnalysisContext


COMMON_FLOW_FIELDS = {
    "ts": "timestamp",
    "uid": "uid",
    "id.orig_h": "source_ip",
    "id.orig_p": "source_port",
    "id.resp_h": "destination_ip",
    "id.resp_p": "destination_port",
}


NORMALIZERS = {
    "conn": {
        **COMMON_FLOW_FIELDS,
        "proto": "protocol",
        "service": "service",
        "duration": "duration",
        "orig_bytes": "source_bytes",
        "resp_bytes": "destination_bytes",
        "conn_state": "zeek_state",
        "history": "history",
        "orig_pkts": "source_packets",
        "resp_pkts": "destination_packets",
    },
    "dns": {**COMMON_FLOW_FIELDS, "query": "query", "qtype_name": "qtype_name", "rcode_name": "rcode_name"},
    "http": {**COMMON_FLOW_FIELDS},
    "quic": {**COMMON_FLOW_FIELDS},
    "socks": {**COMMON_FLOW_FIELDS, "user": "username"},
    "weird": {**COMMON_FLOW_FIELDS, "name": "name", "addl": "additional", "notice": "notice", "source": "weird_source"},
    "ftp": {**COMMON_FLOW_FIELDS, "user": "username", "command": "command", "reply_code": "reply_code"},
    "tftp": {**COMMON_FLOW_FIELDS, "fname": "filename", "wrq": "wrq", "mode": "mode", "size": "size"},
    "smtp": {**COMMON_FLOW_FIELDS},
    "telnet": {**COMMON_FLOW_FIELDS, "user": "username"},
    "login": {**COMMON_FLOW_FIELDS, "user": "username"},
    "ssh": {**COMMON_FLOW_FIELDS},
    "kerberos": {**COMMON_FLOW_FIELDS},
    "ntlm": {**COMMON_FLOW_FIELDS},
    "ldap": {**COMMON_FLOW_FIELDS},
    "ldap_bind": {**COMMON_FLOW_FIELDS},
    "ldap_search": {**COMMON_FLOW_FIELDS},
    "smb": {**COMMON_FLOW_FIELDS},
    "smb_mapping": {**COMMON_FLOW_FIELDS},
    "smb_files": {**COMMON_FLOW_FIELDS},
    "smb_cmd": {**COMMON_FLOW_FIELDS},
    "rdp": {**COMMON_FLOW_FIELDS},
    "ssdp": {**COMMON_FLOW_FIELDS},
    "upnp": {**COMMON_FLOW_FIELDS},
    "upnp_igd": {**COMMON_FLOW_FIELDS},
    "vnc": {**COMMON_FLOW_FIELDS},
    "modbus": {**COMMON_FLOW_FIELDS},
    "dnp3": {**COMMON_FLOW_FIELDS},
    "enip": {**COMMON_FLOW_FIELDS},
    "ntp": {**COMMON_FLOW_FIELDS},
    "snmp": {**COMMON_FLOW_FIELDS, "version": "version", "community": "community", "set_requests": "set_requests"},
    "files": {
        "ts": "timestamp",
        "fuid": "file_uid",
        "tx_hosts": "tx_hosts",
        "rx_hosts": "rx_hosts",
        "conn_uids": "connection_uids",
        "source": "source",
        "mime_type": "mime_type",
        "filename": "filename",
        "seen_bytes": "seen_bytes",
        "total_bytes": "total_bytes",
    },
}


LOG_NAMES = ("conn", "dns", "http", "quic", "socks", "ftp", "tftp", "smtp", "telnet", "login", "ssl", "x509", "ssh", "kerberos", "ntlm", "ldap", "ldap_bind", "ldap_search", "smb", "smb_mapping", "smb_files", "smb_cmd", "rdp", "ssdp", "upnp", "upnp_igd", "vnc", "modbus", "dnp3", "enip", "bacnet", "s7comm", "mms", "iec61850", "dhcp", "ntp", "snmp", "arp", "files", "weird")


def load_zeek_directory(path: str | Path) -> AnalysisContext:
    root = Path(path)
    if not root.exists():
        raise FileNotFoundError(root)

    parsed: dict[str, list[dict[str, Any]]] = {}
    diagnostics: dict[str, dict[str, Any]] = {}
    for log_name in LOG_NAMES:
        log_path = _find_log(root, log_name)
        if not log_path:
            parsed[log_name] = []
            continue
        try:
            rows, diagnostic = _parse_zeek_log_with_diagnostics(log_path, log_name)
        except (OSError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
            rows = []
            diagnostic = {
                "path": str(log_path),
                "format": _log_format(log_path),
                "rows": 0,
                "skipped_rows": 0,
                "short_rows": 0,
                "extra_value_rows": 0,
                "parse_error": f"{type(exc).__name__}: {exc}",
            }
        parsed[log_name] = rows
        diagnostics[log_name] = diagnostic

    metadata = _load_metadata(root)
    metadata["zeek_parse_diagnostics"] = diagnostics
    metadata["zeek_parse_warning_count"] = sum(
        int(item.get("skipped_rows", 0))
        + int(item.get("short_rows", 0))
        + int(item.get("extra_value_rows", 0))
        + (1 if item.get("parse_error") else 0)
        for item in diagnostics.values()
    )

    return AnalysisContext(
        connections=parsed["conn"],
        dns=parsed["dns"],
        http=parsed["http"],
        quic=parsed["quic"],
        socks=parsed["socks"],
        ftp=parsed["ftp"],
        tftp=parsed["tftp"],
        smtp=parsed["smtp"],
        telnet=parsed["telnet"],
        login=parsed["login"],
        ssl=parsed["ssl"],
        x509=parsed["x509"],
        ssh=parsed["ssh"],
        kerberos=parsed["kerberos"],
        ntlm=parsed["ntlm"],
        ldap=parsed["ldap"],
        ldap_bind=parsed["ldap_bind"],
        ldap_search=parsed["ldap_search"],
        smb=parsed["smb"],
        smb_mapping=parsed["smb_mapping"],
        smb_files=parsed["smb_files"],
        smb_cmd=parsed["smb_cmd"],
        rdp=parsed["rdp"],
        ssdp=parsed["ssdp"],
        upnp=parsed["upnp"],
        upnp_igd=parsed["upnp_igd"],
        vnc=parsed["vnc"],
        modbus=parsed["modbus"],
        dnp3=parsed["dnp3"],
        enip=parsed["enip"],
        bacnet=parsed["bacnet"],
        s7comm=parsed["s7comm"],
        mms=parsed["mms"],
        iec61850=parsed["iec61850"],
        dhcp=parsed["dhcp"],
        ntp=parsed["ntp"],
        snmp=parsed["snmp"],
        arp=parsed["arp"],
        files=parsed["files"],
        weird=parsed["weird"],
        metadata=metadata,
    )


def parse_zeek_log(path: str | Path, log_name: str | None = None) -> list[dict[str, Any]]:
    rows, _diagnostic = _parse_zeek_log_with_diagnostics(Path(path), log_name)
    return rows


def _parse_zeek_log_with_diagnostics(
    path: Path, log_name: str | None = None
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if path.suffix == ".json" or path.name.endswith(".log.json"):
        rows, diagnostic = _parse_json_lines(path)
    else:
        rows, diagnostic = _parse_ascii_log(path)
    normalized = [_normalize_row(row, log_name or path.stem.split(".")[0]) for row in rows]
    diagnostic["rows"] = len(normalized)
    return normalized, diagnostic


def _find_log(root: Path, name: str) -> Path | None:
    candidates = [
        root / f"{name}.log",
        root / f"{name}.json",
        root / f"{name}.log.json",
    ]
    return next((candidate for candidate in candidates if candidate.exists()), None)


def _log_format(path: Path) -> str:
    return "json-lines" if path.suffix == ".json" or path.name.endswith(".log.json") else "ascii"


def _base_diagnostic(path: Path) -> dict[str, Any]:
    return {
        "path": str(path),
        "format": _log_format(path),
        "rows": 0,
        "skipped_rows": 0,
        "short_rows": 0,
        "extra_value_rows": 0,
        "parse_error": None,
    }


def _parse_json_lines(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    diagnostic = _base_diagnostic(path)
    malformed_lines: list[int] = []
    non_object_lines: list[int] = []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                diagnostic["skipped_rows"] += 1
                if len(malformed_lines) < 10:
                    malformed_lines.append(line_number)
                continue
            if not isinstance(value, dict):
                diagnostic["skipped_rows"] += 1
                if len(non_object_lines) < 10:
                    non_object_lines.append(line_number)
                continue
            rows.append(value)
    if malformed_lines:
        diagnostic["malformed_json_lines"] = malformed_lines
    if non_object_lines:
        diagnostic["non_object_json_lines"] = non_object_lines
    return rows, diagnostic


def _parse_ascii_log(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    separator = "\t"
    fields: list[str] | None = None
    unset = "-"
    empty = "(empty)"
    rows: list[dict[str, Any]] = []
    diagnostic = _base_diagnostic(path)

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_number, raw in enumerate(handle, start=1):
            line = raw.rstrip("\r\n")
            if line.startswith("#separator "):
                token = line.split(" ", 1)[1]
                if token.startswith("\\x"):
                    try:
                        separator = bytes.fromhex(token[2:]).decode("latin1")
                    except ValueError as exc:
                        raise ValueError(f"Zeek ASCII log {path} has invalid #separator at line {line_number}") from exc
                continue
            if line.startswith("#unset_field "):
                unset = line.split(" ", 1)[1]
                continue
            if line.startswith("#empty_field "):
                empty = line.split(" ", 1)[1]
                continue
            if line.startswith("#fields"):
                parts = line.split(separator)
                fields = parts[1:] if len(parts) > 1 else line.split()[1:]
                if not fields:
                    raise ValueError(f"Zeek ASCII log {path} has an empty #fields header")
                continue
            if not line or line.startswith("#"):
                continue
            if fields is None:
                raise ValueError(f"Zeek ASCII log {path} is missing a #fields header")
            values = line.split(separator)
            if len(values) < len(fields):
                diagnostic["short_rows"] += 1
            elif len(values) > len(fields):
                diagnostic["extra_value_rows"] += 1
            row = {}
            for key, value in zip(fields, values, strict=False):
                row[key] = None if value == unset else "" if value == empty else _coerce(value)
            rows.append(row)
    return rows, diagnostic


def _normalize_row(row: dict[str, Any], log_name: str) -> dict[str, Any]:
    mapping = NORMALIZERS.get(log_name, {})
    normalized = dict(row)
    for source, destination in mapping.items():
        if source in row:
            normalized[destination] = row[source]
    return normalized


def _coerce(value: str) -> Any:
    try:
        if value and all(char not in value for char in ".eE"):
            return int(value)
        return float(value)
    except ValueError:
        return value
def _load_metadata(root: Path) -> dict[str, Any]:
    metadata: dict[str, Any] = {"source": str(root)}
    for filename in ("segments.json", "network_segments.json", "subnets.json"):
        path = root / filename
        if not path.exists():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(payload, list):
            metadata["segments"] = payload
        elif isinstance(payload, dict):
            if isinstance(payload.get("segments"), list):
                metadata["segments"] = payload["segments"]
            if isinstance(payload.get("control_system_subnets"), list):
                metadata["control_system_subnets"] = payload["control_system_subnets"]
            if isinstance(payload.get("non_control_subnets"), list):
                metadata["non_control_subnets"] = payload["non_control_subnets"]
            if isinstance(payload.get("purdue_policy"), dict):
                metadata["purdue_policy"] = payload["purdue_policy"]
            if isinstance(payload.get("outbound_volume_policy"), dict):
                metadata["outbound_volume_policy"] = payload["outbound_volume_policy"]
            elif isinstance(payload.get("data_volume_policy"), dict):
                metadata["outbound_volume_policy"] = payload["data_volume_policy"]
            if isinstance(payload.get("name_resolution_poisoning_policy"), dict):
                metadata["name_resolution_poisoning_policy"] = payload["name_resolution_poisoning_policy"]
            if isinstance(payload.get("proxy_behavior_policy"), dict):
                metadata["proxy_behavior_policy"] = payload["proxy_behavior_policy"]
            if isinstance(payload.get("ja3_outlier_policy"), dict):
                metadata["ja3_outlier_policy"] = payload["ja3_outlier_policy"]
            elif isinstance(payload.get("tls_fingerprint_policy"), dict):
                metadata["ja3_outlier_policy"] = payload["tls_fingerprint_policy"]
            if isinstance(payload.get("http_user_agent_policy"), dict):
                metadata["http_user_agent_policy"] = payload["http_user_agent_policy"]
            if isinstance(payload.get("quic_ot_policy"), dict):
                metadata["quic_ot_policy"] = payload["quic_ot_policy"]
            if isinstance(payload.get("ics_write_policy"), dict):
                metadata["ics_write_policy"] = payload["ics_write_policy"]
            if isinstance(payload.get("ntp_ot_policy"), dict):
                metadata["ntp_ot_policy"] = payload["ntp_ot_policy"]
            elif isinstance(payload.get("ntp_policy"), dict):
                metadata["ntp_ot_policy"] = payload["ntp_policy"]
            if isinstance(payload.get("dhcp_ot_policy"), dict):
                metadata["dhcp_ot_policy"] = payload["dhcp_ot_policy"]
            elif isinstance(payload.get("rogue_dhcp_policy"), dict):
                metadata["dhcp_ot_policy"] = payload["rogue_dhcp_policy"]
            if isinstance(payload.get("vlan_policy"), dict):
                metadata["vlan_policy"] = payload["vlan_policy"]
            elif isinstance(payload.get("vlan_tag_policy"), dict):
                metadata["vlan_policy"] = payload["vlan_tag_policy"]
            if isinstance(payload.get("http_upload_policy"), dict):
                metadata["http_upload_policy"] = payload["http_upload_policy"]
            elif isinstance(payload.get("large_http_upload_policy"), dict):
                metadata["http_upload_policy"] = payload["large_http_upload_policy"]
            if isinstance(payload.get("engineering_cleartext_policy"), dict):
                metadata["engineering_cleartext_policy"] = payload["engineering_cleartext_policy"]
            elif isinstance(payload.get("ftp_tftp_policy"), dict):
                metadata["engineering_cleartext_policy"] = payload["ftp_tftp_policy"]
            if isinstance(payload.get("file_transfer_policy"), dict):
                metadata["file_transfer_policy"] = payload["file_transfer_policy"]
            elif isinstance(payload.get("sensitive_file_policy"), dict):
                metadata["file_transfer_policy"] = payload["sensitive_file_policy"]
            if isinstance(payload.get("service_baseline_policy"), dict):
                metadata["service_baseline_policy"] = payload["service_baseline_policy"]
            elif isinstance(payload.get("new_service_policy"), dict):
                metadata["service_baseline_policy"] = payload["new_service_policy"]
            if isinstance(payload.get("ot_certificate_policy"), dict):
                metadata["ot_certificate_policy"] = payload["ot_certificate_policy"]
            elif isinstance(payload.get("certificate_management_policy"), dict):
                metadata["ot_certificate_policy"] = payload["certificate_management_policy"]
            if isinstance(payload.get("broadcast_multicast_ot_policy"), dict):
                metadata["broadcast_multicast_ot_policy"] = payload["broadcast_multicast_ot_policy"]
            elif isinstance(payload.get("broadcast_multicast_policy"), dict):
                metadata["broadcast_multicast_ot_policy"] = payload["broadcast_multicast_policy"]
            if isinstance(payload.get("internet_exposed_ics_policy"), dict):
                metadata["internet_exposed_ics_policy"] = payload["internet_exposed_ics_policy"]
            elif isinstance(payload.get("external_admin_ics_policy"), dict):
                metadata["internet_exposed_ics_policy"] = payload["external_admin_ics_policy"]
            if isinstance(payload.get("control_system_enterprise_policy"), dict):
                metadata["control_system_enterprise_policy"] = payload["control_system_enterprise_policy"]
            elif isinstance(payload.get("ot_enterprise_policy"), dict):
                metadata["control_system_enterprise_policy"] = payload["ot_enterprise_policy"]
            if isinstance(payload.get("ot_dns_policy"), dict):
                metadata["ot_dns_policy"] = payload["ot_dns_policy"]
            elif isinstance(payload.get("external_dns_policy"), dict):
                metadata["ot_dns_policy"] = payload["external_dns_policy"]
            elif isinstance(payload.get("dns_resolver_policy"), dict):
                metadata["ot_dns_policy"] = payload["dns_resolver_policy"]
            if isinstance(payload.get("ot_outbound_internet_policy"), dict):
                metadata["ot_outbound_internet_policy"] = payload["ot_outbound_internet_policy"]
            elif isinstance(payload.get("ot_egress_policy"), dict):
                metadata["ot_outbound_internet_policy"] = payload["ot_egress_policy"]
            elif isinstance(payload.get("outbound_internet_policy"), dict):
                metadata["ot_outbound_internet_policy"] = payload["outbound_internet_policy"]
            if isinstance(payload.get("snmp_write_policy"), dict):
                metadata["snmp_write_policy"] = payload["snmp_write_policy"]
            elif isinstance(payload.get("snmp_set_policy"), dict):
                metadata["snmp_write_policy"] = payload["snmp_set_policy"]
            if isinstance(payload.get("ot_comm_matrix_policy"), dict):
                metadata["ot_comm_matrix_policy"] = payload["ot_comm_matrix_policy"]
            elif isinstance(payload.get("communication_matrix_policy"), dict):
                metadata["ot_comm_matrix_policy"] = payload["communication_matrix_policy"]
            elif isinstance(payload.get("comm_matrix_policy"), dict):
                metadata["ot_comm_matrix_policy"] = payload["comm_matrix_policy"]
        metadata["segments_source"] = str(path)
        break

    _load_asset_inventory(root, metadata)
    return metadata


def _load_asset_inventory(root: Path, metadata: dict[str, Any]) -> None:
    for filename in ("asset_inventory.json", "assets.json", "inventory.json"):
        path = root / filename
        if not path.exists():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        assets = payload.get("assets") if isinstance(payload, dict) else payload
        if isinstance(assets, list):
            metadata["asset_inventory"] = [item for item in assets if isinstance(item, dict)]
            metadata["asset_inventory_source"] = str(path)
            return

    csv_path = root / "asset_inventory.csv"
    if csv_path.exists():
        try:
            with csv_path.open("r", encoding="utf-8-sig", newline="") as handle:
                rows = [dict(row) for row in csv.DictReader(handle)]
        except OSError:
            return
        metadata["asset_inventory"] = rows
        metadata["asset_inventory_source"] = str(csv_path)
