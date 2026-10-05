from __future__ import annotations

from collections import defaultdict
import ipaddress
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata

MIB = 1024 * 1024
DEFAULT_MIN_UPLOAD_BYTES = 10 * MIB
DEFAULT_HIGH_UPLOAD_BYTES = 100 * MIB
MAX_EVIDENCE_FLOWS = 10


class LargeOutboundHttpUploadsModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="large_outbound_http_uploads",
        name="Large Outbound POST/PUT to Unknown Hosts",
        description=(
            "Identifies substantial HTTP POST/PUT uploads from internal clients to external, "
            "non-approved destinations using explicit request-body length when available and "
            "conn.log orig_bytes only as a conservative fallback."
        ),
        category="security_analysis",
        required_logs=("http",),
        default_enabled=True,
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        policy = _policy(context.metadata)
        conn_by_uid = {
            str(row.get("uid")): row
            for row in context.connections
            if row.get("uid") not in (None, "")
        }
        segments = _segments(context.metadata)

        candidates: list[dict[str, Any]] = []
        skipped_non_upload_method = 0
        skipped_internal_destination = 0
        skipped_approved_destination = 0
        skipped_missing_size = 0

        for row in context.http:
            method = _text(row.get("method")).upper()
            if method not in {"POST", "PUT"}:
                skipped_non_upload_method += 1
                continue

            uid = _text(row.get("uid"))
            conn = conn_by_uid.get(uid, {}) if uid else {}
            source = _first_text(row, "source_ip", "id.orig_h") or _first_text(conn, "source_ip", "id.orig_h")
            destination = _first_text(row, "destination_ip", "id.resp_h") or _first_text(conn, "destination_ip", "id.resp_h")
            port = _first_int(row, "destination_port", "id.resp_p") or _first_int(conn, "destination_port", "id.resp_p")
            host = _first_text(row, "host", "server_name", "hostname")
            uri = _first_text(row, "uri", "path", "request_uri") or ""

            if not source or not destination or not _is_external(destination, conn, segments):
                skipped_internal_destination += 1
                continue
            if _approved_destination(destination, host, policy):
                skipped_approved_destination += 1
                continue

            upload_bytes, byte_source = _upload_bytes(row, conn)
            if upload_bytes is None or upload_bytes < 0:
                skipped_missing_size += 1
                continue

            candidates.append(
                {
                    "row": row,
                    "conn": conn,
                    "uid": uid,
                    "method": method,
                    "source": source,
                    "destination": destination,
                    "port": port,
                    "host": host,
                    "uri": uri,
                    "upload_bytes": upload_bytes,
                    "byte_source": byte_source,
                    "timestamp": _first_non_none(_first_value(row, "timestamp", "ts"), _first_value(conn, "timestamp", "ts")),
                    "source_segment": _segment_name(_segment_for_ip(source, segments)),
                }
            )

        groups: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
        for event in candidates:
            groups[(event["source"], event["destination"], event["host"] or "")].append(event)

        findings: list[Finding] = []
        below_threshold_groups = 0
        for (source, destination, host), events in sorted(groups.items()):
            total_bytes = sum(int(event["upload_bytes"]) for event in events)
            largest = max(int(event["upload_bytes"]) for event in events)
            if total_bytes < policy["minimum_upload_bytes"]:
                below_threshold_groups += 1
                continue

            explicit_count = sum(1 for event in events if event["byte_source"] == "http_request_body_len")
            confidence = "high" if explicit_count == len(events) else "medium"
            severity = "high" if total_bytes >= policy["high_upload_bytes"] else "medium"
            source_segment = next((event["source_segment"] for event in events if event["source_segment"]), None)
            if source_segment and _is_ot_segment(source_segment) and total_bytes >= policy["minimum_upload_bytes"]:
                severity = "high"

            methods = sorted({event["method"] for event in events})
            ports = sorted({event["port"] for event in events if event["port"] is not None})
            display_target = host or destination
            services = ["HTTP"]
            pairs = []
            seen_pairs = set()
            for event in events:
                key = (event["source"], event["destination"], event["port"])
                if key in seen_pairs:
                    continue
                seen_pairs.add(key)
                pairs.append(
                    {
                        "source": event["source"],
                        "destination": event["destination"],
                        "port": event["port"],
                        "protocol": "tcp",
                        "service": "http",
                    }
                )

            evidence = [event["row"] for event in events[:MAX_EVIDENCE_FLOWS]]
            timestamps = [event["timestamp"] for event in events[:MAX_EVIDENCE_FLOWS] if event["timestamp"] is not None]
            tags = ["http", "outbound-upload", "post-put", "external-destination", "unknown-destination"]
            if source_segment and _is_ot_segment(source_segment):
                tags.append("ot-source")

            byte_note = (
                "HTTP request_body_len supplied the upload size for every contributing request."
                if confidence == "high"
                else "At least one request lacked an explicit HTTP body length, so conn.log orig_bytes was used as an approximate upper-bound fallback."
            )
            summary = (
                f"Observed {len(events)} HTTP {'/'.join(methods)} request(s) from {source} to external, non-approved destination "
                f"{display_target} totaling {total_bytes:,} bytes ({_format_bytes(total_bytes)}), with a largest observed request/connection "
                f"of {_format_bytes(largest)}. {byte_note} Large web uploads can be legitimate software, backup, API, or cloud workflows; "
                "this finding indicates a transfer that should be validated, not confirmed data exfiltration."
            )

            findings.append(
                Finding(
                    title=f"Large outbound HTTP upload to {display_target}",
                    severity=severity,
                    confidence=confidence,
                    detection_basis="protocol_log" if confidence == "high" else "derived",
                    summary=summary,
                    devices=sorted({source, destination}),
                    services=services,
                    ports=ports,
                    connection_pairs=pairs[:MAX_EVIDENCE_FLOWS],
                    flows=evidence,
                    subnets=[],
                    timestamps=timestamps,
                    tags=tags,
                    metadata={
                        "source": source,
                        "destination": destination,
                        "host": host or None,
                        "source_segment": source_segment,
                        "request_count": len(events),
                        "methods": methods,
                        "total_upload_bytes": total_bytes,
                        "total_upload_bytes_human": _format_bytes(total_bytes),
                        "largest_upload_bytes": largest,
                        "largest_upload_bytes_human": _format_bytes(largest),
                        "explicit_request_body_length_events": explicit_count,
                        "conn_orig_bytes_fallback_events": len(events) - explicit_count,
                        "external_destination": True,
                        "approved_destination": False,
                        "exfiltration_confirmed": False,
                        "evidence_event_count": len(events),
                        "evidence_truncated": len(events) > MAX_EVIDENCE_FLOWS,
                    },
                )
            )

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "http_events_evaluated": len(context.http),
                "candidate_external_post_put_events": len(candidates),
                "large_outbound_http_upload_findings": len(findings),
                "total_flagged_upload_bytes": sum(int(f.metadata.get("total_upload_bytes") or 0) for f in findings),
                "affected_sources": len({f.metadata.get("source") for f in findings if f.metadata.get("source")}),
                "approved_destination_events_suppressed": skipped_approved_destination,
            },
            evidence={
                "inspected_logs": [name for name, rows in (("http", context.http), ("conn", context.connections)) if rows],
                "skipped_non_post_put_events": skipped_non_upload_method,
                "skipped_non_external_destinations": skipped_internal_destination,
                "skipped_approved_destinations": skipped_approved_destination,
                "skipped_missing_upload_size": skipped_missing_size,
                "groups_below_threshold": below_threshold_groups,
                "policy": {
                    "minimum_upload_bytes": policy["minimum_upload_bytes"],
                    "high_upload_bytes": policy["high_upload_bytes"],
                    "approved_hosts": policy["approved_hosts"],
                    "approved_ips": policy["approved_ips"],
                },
                "notes": [
                    "Only HTTP POST and PUT requests to external destinations are evaluated; internal HTTP uploads are not findings for this module.",
                    "Explicit HTTP request_body_len/request_body_length is preferred. When it is unavailable, correlated conn.log orig_bytes is used only as an approximate fallback and confidence is reduced.",
                    "Configured approved hosts/IPs are suppressed so expected cloud, backup, API, and software-distribution destinations can be excluded.",
                    "A large upload to an unknown external host is an anomaly/review signal; the module does not independently confirm data exfiltration.",
                    "Evidence is capped at 10 representative HTTP events while full request and byte counts remain in metadata.",
                ],
            },
            warnings=[],
        )


def _policy(metadata: dict[str, Any]) -> dict[str, Any]:
    raw = metadata.get("http_upload_policy") or metadata.get("large_http_upload_policy") or {}
    if not isinstance(raw, dict):
        raw = {}
    return {
        "minimum_upload_bytes": _positive_int(raw.get("minimum_upload_bytes"), DEFAULT_MIN_UPLOAD_BYTES),
        "high_upload_bytes": _positive_int(raw.get("high_upload_bytes"), DEFAULT_HIGH_UPLOAD_BYTES),
        "approved_hosts": sorted({_normalize_host(v) for v in _string_list(raw.get("approved_hosts") or raw.get("approved_domains")) if _normalize_host(v)}),
        "approved_ips": sorted({_text(v) for v in _string_list(raw.get("approved_ips")) if _text(v)}),
    }


def _upload_bytes(row: dict[str, Any], conn: dict[str, Any]) -> tuple[int | None, str | None]:
    for key in ("request_body_len", "request_body_length", "request_bytes", "body_length"):
        value = _as_int(row.get(key))
        if value is not None:
            return value, "http_request_body_len"
    value = _as_int(conn.get("source_bytes", conn.get("orig_bytes")))
    if value is not None:
        return value, "conn_orig_bytes"
    return None, None


def _is_external(destination: str, conn: dict[str, Any], segments: list[dict[str, Any]]) -> bool:
    local_resp = _boolish(conn.get("local_resp"))
    if local_resp is True:
        return False
    if local_resp is False:
        return True
    if _segment_for_ip(destination, segments):
        return False
    try:
        ip = ipaddress.ip_address(destination)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified)


def _approved_destination(destination: str, host: str, policy: dict[str, Any]) -> bool:
    if destination in set(policy["approved_ips"]):
        return True
    normalized = _normalize_host(host)
    for approved in policy["approved_hosts"]:
        if normalized == approved or normalized.endswith("." + approved):
            return True
    return False


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


def _is_ot_segment(name: str) -> bool:
    value = name.lower()
    return any(token in value for token in ("ot", "control", "scada", "ics", "process", "safety", "industrial"))


def _normalize_host(value: Any) -> str:
    host = _text(value).lower().rstrip(".")
    if host.startswith("[") and "]" in host:
        host = host[1:host.index("]")]
    if ":" in host and host.count(":") == 1:
        left, right = host.rsplit(":", 1)
        if right.isdigit():
            host = left
    return host


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value if item is not None]
    return []


def _first_text(row: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = _text(row.get(key))
        if value:
            return value
    return ""


def _first_int(row: dict[str, Any], *keys: str) -> int | None:
    for key in keys:
        value = _as_int(row.get(key))
        if value is not None:
            return value
    return None


def _first_non_none(*values: Any) -> Any:
    for value in values:
        if value is not None:
            return value
    return None


def _first_value(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = row.get(key)
        if value not in (None, ""):
            return value
    return None


def _text(value: Any) -> str:
    return str(value).strip() if value not in (None, "") else ""


def _as_int(value: Any) -> int | None:
    if value in (None, "", "-"):
        return None
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def _positive_int(value: Any, default: int) -> int:
    parsed = _as_int(value)
    return parsed if parsed is not None and parsed > 0 else default


def _boolish(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    text = _text(value).lower()
    if text in {"t", "true", "yes", "1"}:
        return True
    if text in {"f", "false", "no", "0"}:
        return False
    return None


def _format_bytes(value: int) -> str:
    if value >= 1024 ** 3:
        return f"{value / (1024 ** 3):.2f} GiB"
    if value >= 1024 ** 2:
        return f"{value / (1024 ** 2):.2f} MiB"
    if value >= 1024:
        return f"{value / 1024:.2f} KiB"
    return f"{value} B"
