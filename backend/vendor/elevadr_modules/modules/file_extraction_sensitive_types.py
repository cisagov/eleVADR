from __future__ import annotations

import ipaddress
from pathlib import PurePath
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata


MAX_EVIDENCE_FLOWS = 10

_EXECUTABLE_MIME_TYPES = {
    "application/x-dosexec",
    "application/x-executable",
    "application/x-elf",
    "application/x-msdownload",
    "application/vnd.microsoft.portable-executable",
    "application/x-ms-installer",
    "application/java-archive",
}
_ARCHIVE_MIME_TYPES = {
    "application/zip",
    "application/x-7z-compressed",
    "application/x-rar-compressed",
    "application/vnd.rar",
    "application/x-tar",
    "application/gzip",
    "application/x-gzip",
    "application/x-bzip2",
    "application/x-xz",
    "application/x-iso9660-image",
}
_EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".msi", ".com", ".scr", ".bat", ".cmd", ".ps1",
    ".psm1", ".vbs", ".js", ".jse", ".wsf", ".sh", ".elf", ".jar", ".apk",
}
_CONFIG_EXTENSIONS = {
    ".conf", ".cfg", ".ini", ".cnf", ".config", ".yaml", ".yml", ".toml",
    ".properties", ".env", ".reg", ".plist",
}
_ARCHIVE_EXTENSIONS = {
    ".zip", ".7z", ".rar", ".tar", ".tgz", ".gz", ".bz2", ".xz", ".iso",
}


class FileExtractionSensitiveTypesModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="file_extraction_sensitive_types",
        name="File Extraction on Wire (Sensitive Types)",
        description=(
            "Detects executable, configuration, or archive file types observed by Zeek files.log "
            "when they are transferred to external destinations or across explicitly classified OT/IT boundaries."
        ),
        category="Data Transfer / Boundary Monitoring",
        required_logs=("files",),
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        policy = _policy(context.metadata)
        segments = _segments(context.metadata)
        findings: list[Finding] = []
        sensitive_events = 0
        skipped_not_sensitive = 0
        skipped_no_route = 0
        suppressed_approved_external = 0

        for row in context.files:
            category, type_basis = _classify_sensitive_file(row, policy)
            if not category:
                skipped_not_sensitive += 1
                continue
            sensitive_events += 1

            transmitters = _host_values(row.get("tx_hosts") or row.get("transmitters"))
            receivers = _host_values(row.get("rx_hosts") or row.get("receivers"))
            if not transmitters or not receivers:
                skipped_no_route += 1
                continue

            external_receivers = [
                host for host in receivers
                if _is_external(host, segments)
                and not _address_allowed(host, policy["approved_external_destinations"])
            ]
            approved_external = [
                host for host in receivers
                if _is_external(host, segments)
                and _address_allowed(host, policy["approved_external_destinations"])
            ]
            suppressed_approved_external += len(approved_external)

            boundary_pairs: list[dict[str, Any]] = []
            for source in transmitters:
                source_segment = _segment_for_ip(source, segments)
                source_zone = _zone(source_segment)
                for destination in receivers:
                    destination_segment = _segment_for_ip(destination, segments)
                    destination_zone = _zone(destination_segment)
                    if {source_zone, destination_zone} == {"ot", "it"}:
                        boundary_pairs.append(
                            {
                                "source": source,
                                "destination": destination,
                                "source_segment": _segment_name(source_segment),
                                "destination_segment": _segment_name(destination_segment),
                                "source_zone": source_zone,
                                "destination_zone": destination_zone,
                            }
                        )

            if not external_receivers and not boundary_pairs:
                continue

            findings.append(
                _finding(
                    row=row,
                    category=category,
                    type_basis=type_basis,
                    transmitters=transmitters,
                    receivers=receivers,
                    external_receivers=external_receivers,
                    boundary_pairs=boundary_pairs,
                )
            )

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "files_evaluated": len(context.files),
                "sensitive_file_events": sensitive_events,
                "sensitive_transfer_findings": len(findings),
                "external_destination_findings": sum("external-destination" in f.tags for f in findings),
                "ot_it_boundary_findings": sum("ot-it-boundary" in f.tags for f in findings),
                "approved_external_destinations_suppressed": suppressed_approved_external,
            },
            evidence={
                "inspected_logs": ["files"],
                "skipped_non_sensitive_files": skipped_not_sensitive,
                "skipped_missing_tx_rx_hosts": skipped_no_route,
                "policy": policy,
                "notes": [
                    "The detector uses Zeek files.log transfer metadata. It does not infer file transfer solely from ports or connection byte counts.",
                    "Executable and archive MIME types can classify a file directly. Configuration files require a configuration-like filename extension by default; generic text/plain, JSON, or XML MIME types are not sufficient on their own.",
                    "An external destination must be a globally routable receiver address. Private routed networks are not treated as Internet destinations merely because they are outside the local subnet.",
                    "OT/IT boundary findings require explicit segment metadata that classifies both endpoints; private IP addressing alone does not establish an OT/IT boundary.",
                    "A sensitive file crossing a boundary is a review signal, not proof of unauthorized transfer or exfiltration. Correlate with change control, software distribution, backups, engineering workflows, and approved vendors.",
                ],
            },
            warnings=[],
        )


def _finding(
    *,
    row: dict[str, Any],
    category: str,
    type_basis: str,
    transmitters: list[str],
    receivers: list[str],
    external_receivers: list[str],
    boundary_pairs: list[dict[str, Any]],
) -> Finding:
    filename = _text(row.get("filename")) or "(filename unavailable)"
    mime_type = _text(row.get("mime_type")) or "unknown"
    timestamp = row.get("timestamp", row.get("ts"))
    file_uid = _text(row.get("file_uid", row.get("fuid")))
    size = _as_int(row.get("total_bytes"))
    if size is None:
        size = _as_int(row.get("seen_bytes"))

    external = bool(external_receivers)
    boundary = bool(boundary_pairs)
    executable = category == "executable"
    severity = "high" if executable and (external or boundary) else "medium"
    confidence = "high" if type_basis == "mime_type" else "medium"

    tags = ["sensitive-file", category]
    if external:
        tags.append("external-destination")
    if boundary:
        tags.append("ot-it-boundary")

    reasons: list[str] = []
    if external:
        reasons.append(f"external receiver(s): {', '.join(external_receivers[:5])}")
    if boundary:
        pairs = [f"{p['source']} -> {p['destination']}" for p in boundary_pairs[:5]]
        reasons.append(f"OT/IT boundary path(s): {', '.join(pairs)}")

    hashes = {
        key: _text(row.get(key))
        for key in ("md5", "sha1", "sha256")
        if _text(row.get(key))
    }

    return Finding(
        title=f"Sensitive {category} file observed across monitored boundary",
        severity=severity,
        confidence=confidence,
        detection_basis="protocol_log",
        summary=(
            f"Zeek observed {category} file {filename} (MIME {mime_type}) in transit; "
            + "; ".join(reasons)
            + ". Review whether the transfer is expected and authorized."
        ),
        devices=sorted(set(transmitters + receivers)),
        services=[_text(row.get("source"))] if _text(row.get("source")) else [],
        connection_pairs=[
            {"source": source, "destination": destination}
            for source in transmitters
            for destination in receivers
        ][:MAX_EVIDENCE_FLOWS],
        flows=[row],
        timestamps=[timestamp] if timestamp is not None else [],
        tags=tags,
        metadata={
            "file_uid": file_uid or None,
            "filename": None if filename == "(filename unavailable)" else filename,
            "mime_type": mime_type,
            "sensitive_category": category,
            "classification_basis": type_basis,
            "size_bytes": size,
            "transmitters": transmitters,
            "receivers": receivers,
            "external_receivers": external_receivers,
            "ot_it_boundary_pairs": boundary_pairs[:MAX_EVIDENCE_FLOWS],
            "hashes": hashes,
            "authorization_confirmed": False,
            "exfiltration_confirmed": False,
        },
    )


def _classify_sensitive_file(row: dict[str, Any], policy: dict[str, Any]) -> tuple[str | None, str | None]:
    mime = _text(row.get("mime_type")).lower().split(";", 1)[0].strip()
    filename = _text(row.get("filename"))
    extension = PurePath(filename.lower()).suffix if filename else ""

    executable_mimes = _EXECUTABLE_MIME_TYPES | set(policy["additional_executable_mime_types"])
    archive_mimes = _ARCHIVE_MIME_TYPES | set(policy["additional_archive_mime_types"])
    executable_extensions = _EXECUTABLE_EXTENSIONS | set(policy["additional_executable_extensions"])
    config_extensions = _CONFIG_EXTENSIONS | set(policy["additional_config_extensions"])
    archive_extensions = _ARCHIVE_EXTENSIONS | set(policy["additional_archive_extensions"])

    if mime in executable_mimes:
        return "executable", "mime_type"
    if mime in archive_mimes:
        return "archive", "mime_type"
    if extension in executable_extensions:
        return "executable", "filename_extension"
    if extension in config_extensions:
        return "configuration", "filename_extension"
    if extension in archive_extensions:
        return "archive", "filename_extension"
    return None, None


def _policy(metadata: dict[str, Any]) -> dict[str, Any]:
    raw = metadata.get("file_transfer_policy") or metadata.get("sensitive_file_policy") or {}
    if not isinstance(raw, dict):
        raw = {}
    return {
        "approved_external_destinations": _string_list(raw.get("approved_external_destinations")),
        "additional_executable_mime_types": _lower_list(raw.get("additional_executable_mime_types")),
        "additional_archive_mime_types": _lower_list(raw.get("additional_archive_mime_types")),
        "additional_executable_extensions": _extensions(raw.get("additional_executable_extensions")),
        "additional_config_extensions": _extensions(raw.get("additional_config_extensions")),
        "additional_archive_extensions": _extensions(raw.get("additional_archive_extensions")),
    }


def _segments(metadata: dict[str, Any]) -> list[dict[str, Any]]:
    raw = metadata.get("segments")
    return [item for item in raw if isinstance(item, dict)] if isinstance(raw, list) else []


def _segment_for_ip(value: str, segments: list[dict[str, Any]]) -> dict[str, Any] | None:
    try:
        ip = ipaddress.ip_address(value)
    except (ValueError, TypeError):
        return None
    matches: list[tuple[int, dict[str, Any]]] = []
    for segment in segments:
        cidr = _text(segment.get("cidr") or segment.get("subnet"))
        if not cidr:
            continue
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if ip.version == network.version and ip in network:
            matches.append((network.prefixlen, segment))
    return max(matches, key=lambda item: item[0])[1] if matches else None


def _segment_name(segment: dict[str, Any] | None) -> str | None:
    if not segment:
        return None
    return _text(segment.get("name") or segment.get("label") or segment.get("role") or segment.get("trust_zone")) or None


def _zone(segment: dict[str, Any] | None) -> str | None:
    if not segment:
        return None
    values = " ".join(
        _text(segment.get(key)).lower()
        for key in ("role", "name", "label", "trust_zone", "zone")
        if _text(segment.get(key))
    )
    level = _as_int(segment.get("purdue_level", segment.get("purdue")))
    if level is not None:
        if 0 <= level <= 3:
            return "ot"
        if level >= 4:
            return "it"
    if any(token in values for token in ("non_control", "non-control", "enterprise", "business", "corporate", "office", " it ")):
        return "it"
    if values == "it" or values.startswith("it ") or values.endswith(" it"):
        return "it"
    if any(token in values for token in ("ot", "control", "scada", "ics", "process", "safety", "industrial", "plc")):
        return "ot"
    return None


def _is_external(value: str, segments: list[dict[str, Any]]) -> bool:
    if _segment_for_ip(value, segments):
        return False
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _address_allowed(value: str, entries: list[str]) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return value in entries
    for entry in entries:
        try:
            if "/" in entry and ip in ipaddress.ip_network(entry, strict=False):
                return True
            if ip == ipaddress.ip_address(entry):
                return True
        except ValueError:
            if value == entry:
                return True
    return False


def _host_values(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        items = list(value)
    else:
        text = str(value).strip()
        if not text or text in {"-", "(empty)"}:
            return []
        text = text.strip("[]{}")
        items = text.split(",")
    return sorted({_text(item).strip() for item in items if _text(item).strip()})


def _extensions(value: Any) -> list[str]:
    output = []
    for item in _string_list(value):
        item = item.lower().strip()
        if item and not item.startswith("."):
            item = "." + item
        if item:
            output.append(item)
    return sorted(set(output))


def _lower_list(value: Any) -> list[str]:
    return sorted({_text(item).lower() for item in _string_list(value) if _text(item)})


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value if item is not None]
    return []


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _as_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None
