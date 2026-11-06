from __future__ import annotations

import ipaddress
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata

MAX_EVIDENCE_FLOWS = 10
LDAP_LOGS = ("ldap", "ldap_bind", "ldap_search")
TLS_TRUE_FIELDS = (
    "tls",
    "ssl",
    "encrypted",
    "is_tls",
    "tls_enabled",
    "starttls",
    "start_tls",
)
BIND_OPERATION_FIELDS = ("operation", "op", "message_type", "request_type", "action")
AUTH_METHOD_FIELDS = ("auth_method", "authentication", "auth_type", "mechanism", "bind_method", "sasl_mechanism")
IDENTITY_FIELDS = ("bind_dn", "dn", "username", "user", "principal", "account", "identity")
ANONYMOUS_FIELDS = ("anonymous", "anonymous_bind", "is_anonymous")
ROLE_FIELDS = ("role", "segment_role", "trust_zone", "security_zone", "zone", "type", "classification")
LEVEL_FIELDS = ("purdue_level", "purdue", "level", "purdueLevel")


@dataclass(frozen=True, slots=True)
class _Segment:
    cidr: str
    name: str
    role: str
    purdue_level: str
    network: ipaddress.IPv4Network | ipaddress.IPv6Network


class LdapCleartextAnonymousCrossSegmentModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="ldap_cleartext_anonymous_cross_segment",
        name="LDAP Cleartext / Anonymous Bind / Cross-Segment",
        description=(
            "Identifies LDAP anonymous or simple binds without TLS, cleartext LDAP on port 389, "
            "and LDAP communications that cross configured network segments, including OT-to-enterprise directory queries."
        ),
        category="security_analysis",
        required_logs=(),
        required_any_logs=(),
        default_enabled=True,
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        conn_by_uid = {
            str(row.get("uid")): row
            for row in context.connections
            if row.get("uid") not in (None, "")
        }
        segments = _load_segments(context.metadata)

        events: list[dict[str, Any]] = []
        inspected_logs: list[str] = []
        for log_name in LDAP_LOGS:
            rows = context.log(log_name)
            if not rows:
                continue
            inspected_logs.append(log_name)
            for row in rows:
                event = _normalize_event(row, log_name, conn_by_uid, segments)
                if event:
                    events.append(event)

        issue_events: dict[str, list[dict[str, Any]]] = defaultdict(list)
        ambiguous_tls = 0
        unclassified_segment_events = 0
        for event in events:
            issues = _issues_for_event(event)
            for issue in issues:
                issue_events[issue].append(event)
            if event["port"] == 389 and event["tls"] is None:
                ambiguous_tls += 1
            if segments and (event["source_segment"] is None or event["destination_segment"] is None):
                unclassified_segment_events += 1

        findings: list[Finding] = []
        for issue, items in issue_events.items():
            grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
            for item in items:
                grouped[(item["source"], item["destination"])].append(item)
            for (_, _), group in sorted(grouped.items()):
                findings.append(_finding(issue, group))

        skipped = [name for name in LDAP_LOGS if not context.log(name)]
        return ModuleResult(
            module_id=self.metadata.id,
            findings=sorted(findings, key=lambda finding: (finding.severity, finding.title)),
            metrics={
                "ldap_security_findings": len(findings),
                "ldap_events_evaluated": len(events),
                "anonymous_cleartext_bind_events": len(issue_events.get("anonymous_cleartext_bind", [])),
                "simple_cleartext_bind_events": len(issue_events.get("simple_cleartext_bind", [])),
                "cleartext_ldap_events": len(issue_events.get("cleartext_ldap", [])),
                "cross_segment_ldap_events": len(issue_events.get("cross_segment_ldap", [])),
                "ot_to_enterprise_ldap_events": len(issue_events.get("ot_to_enterprise_ldap", [])),
                "ambiguous_tls_state_events": ambiguous_tls,
                "unclassified_segment_events": unclassified_segment_events,
                "affected_devices": len({device for finding in findings for device in finding.devices}),
            },
            evidence={
                "inspected_logs": inspected_logs,
                "skipped_optional_logs": skipped,
                "segments_loaded": len(segments),
                "segments_source": context.metadata.get("segments_source"),
                "coverage": {
                    "bind_security": (
                        "Anonymous/simple-bind checks require LDAP protocol-log fields that identify bind operations, "
                        "authentication method, identity, or explicit anonymous state."
                    ),
                    "tls": (
                        "Port 636 or an explicit TLS/encrypted/StartTLS=true field is treated as protected. "
                        "LDAP on port 389 with no explicit TLS field is reported conservatively rather than asserted as cryptographically proven cleartext."
                    ),
                    "segmentation": (
                        "Cross-segment checks require both endpoints to map to configured segments. OT and enterprise roles are derived only from segment metadata."
                    ),
                },
                "notes": [
                    "LDAP protocol identification comes from LDAP logs, not destination port alone.",
                    "Anonymous or simple binds over explicitly non-TLS LDAP are stronger findings than generic LDAP/389 traffic with unknown StartTLS state.",
                    "Any LDAP crossing two configured segments is reported for review; OT-to-enterprise LDAP is called out separately because directory dependencies can weaken OT/IT segmentation.",
                    "The module does not claim that the destination is Active Directory unless site segment metadata identifies the destination as enterprise/directory/AD-related.",
                    "Evidence is capped at 10 representative events per finding while full event counts remain in metadata.",
                ],
            },
            warnings=[],
        )


def _issues_for_event(event: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    tls = event["tls"]
    port = event["port"]
    is_clear_or_ambiguous_389 = port == 389 and tls is not True

    if event["is_bind"] and event["anonymous"] and is_clear_or_ambiguous_389:
        issues.append("anonymous_cleartext_bind")
    elif event["is_bind"] and event["simple_bind"] and is_clear_or_ambiguous_389:
        issues.append("simple_cleartext_bind")
    elif is_clear_or_ambiguous_389:
        issues.append("cleartext_ldap")

    source_segment = event["source_segment"]
    destination_segment = event["destination_segment"]
    if source_segment and destination_segment and source_segment.name != destination_segment.name:
        if _is_ot(source_segment) and _is_enterprise(destination_segment):
            issues.append("ot_to_enterprise_ldap")
        else:
            issues.append("cross_segment_ldap")
    return issues


def _finding(issue: str, items: list[dict[str, Any]]) -> Finding:
    representative = items[:MAX_EVIDENCE_FLOWS]
    source = items[0]["source"]
    destination = items[0]["destination"]
    event_count = len(items)

    if issue == "anonymous_cleartext_bind":
        title = "Anonymous LDAP bind observed without TLS"
        severity = "high"
        confidence = "high" if all(item["tls"] is False for item in items) else "medium"
        basis = "protocol_log"
        summary = (
            f"Observed {event_count} LDAP anonymous-bind event(s) from {source} to {destination} over LDAP/389 "
            "without evidence of an encrypted LDAP session. Anonymous directory binds can expose directory data or enable unauthenticated enumeration."
        )
        tags = ["ldap", "anonymous-bind", "cleartext-authentication"]
    elif issue == "simple_cleartext_bind":
        title = "LDAP simple bind observed without TLS"
        severity = "high"
        confidence = "high" if all(item["tls"] is False for item in items) else "medium"
        basis = "protocol_log"
        summary = (
            f"Observed {event_count} LDAP simple-bind event(s) from {source} to {destination} over LDAP/389 "
            "without evidence of TLS. Simple bind credentials can be exposed when LDAP is not protected by TLS."
        )
        tags = ["ldap", "simple-bind", "cleartext-authentication"]
    elif issue == "cleartext_ldap":
        title = "LDAP observed on cleartext port 389"
        severity = "medium"
        confidence = "high" if all(item["tls"] is False for item in items) else "medium"
        basis = "protocol_log"
        summary = (
            f"Observed {event_count} LDAP event(s) from {source} to {destination} on TCP/389 without positive TLS/StartTLS evidence. "
            "LDAP/389 can be legitimate and may upgrade with StartTLS, so verify the session's encryption policy before treating this as confirmed cleartext exposure."
        )
        tags = ["ldap", "port-389", "cleartext-review"]
    elif issue == "ot_to_enterprise_ldap":
        title = "OT-originated LDAP query crossed into an enterprise directory segment"
        severity = "medium"
        confidence = "high"
        basis = "derived"
        src_seg = items[0]["source_segment"]
        dst_seg = items[0]["destination_segment"]
        summary = (
            f"Observed {event_count} LDAP event(s) from OT/control segment '{src_seg.name}' to enterprise/directory segment '{dst_seg.name}'. "
            "Direct OT dependence on enterprise directory services can create a cross-boundary trust path and should be validated against the site's architecture and allowlist."
        )
        tags = ["ldap", "segmentation", "ot-to-enterprise", "directory-dependency"]
    else:
        title = "LDAP traffic crossed configured network segments"
        severity = "medium"
        confidence = "high"
        basis = "derived"
        src_seg = items[0]["source_segment"]
        dst_seg = items[0]["destination_segment"]
        summary = (
            f"Observed {event_count} LDAP event(s) crossing from segment '{src_seg.name}' to '{dst_seg.name}'. "
            "Cross-segment directory traffic may be expected, but it should be validated against segmentation policy and approved directory-service paths."
        )
        tags = ["ldap", "segmentation", "cross-segment"]

    pairs = []
    seen_pairs: set[tuple[str, str, int | None]] = set()
    for item in representative:
        key = (item["source"], item["destination"], item["port"])
        if key in seen_pairs:
            continue
        seen_pairs.add(key)
        pairs.append(
            {
                "source": item["source"],
                "destination": item["destination"],
                "port": item["port"],
                "protocol": item["protocol"],
                "service": "LDAP",
            }
        )

    subnets: set[str] = set()
    for item in items:
        for segment in (item["source_segment"], item["destination_segment"]):
            if segment:
                subnets.add(segment.cidr)

    auth_methods = sorted({item["auth_method"] for item in items if item["auth_method"]})
    identities = sorted({item["identity"] for item in items if item["identity"]})
    tls_states = sorted({str(item["tls"]).lower() for item in items})
    metadata: dict[str, Any] = {
        "issue": issue,
        "event_count": event_count,
        "evidence_event_count": len(representative),
        "evidence_truncated": event_count > len(representative),
        "auth_methods": auth_methods,
        "identities": identities,
        "tls_states": tls_states,
    }
    src_seg = items[0]["source_segment"]
    dst_seg = items[0]["destination_segment"]
    if src_seg:
        metadata.update(
            {
                "source_segment": src_seg.name,
                "source_segment_role": src_seg.role or None,
                "source_purdue_level": src_seg.purdue_level or None,
            }
        )
    if dst_seg:
        metadata.update(
            {
                "destination_segment": dst_seg.name,
                "destination_segment_role": dst_seg.role or None,
                "destination_purdue_level": dst_seg.purdue_level or None,
            }
        )

    return Finding(
        title=title,
        severity=severity,
        summary=summary,
        confidence=confidence,
        detection_basis=basis,
        devices=sorted({value for item in items for value in (item["source"], item["destination"]) if value}),
        services=["LDAP"],
        ports=sorted({item["port"] for item in items if item["port"] is not None}),
        connection_pairs=pairs,
        flows=[item["row"] for item in representative],
        subnets=sorted(subnets),
        timestamps=[item["timestamp"] for item in representative if item["timestamp"] is not None],
        tags=tags,
        metadata=metadata,
    )


def _normalize_event(
    row: dict[str, Any],
    log_name: str,
    conn_by_uid: dict[str, dict[str, Any]],
    segments: list[_Segment],
) -> dict[str, Any] | None:
    uid = _text(row.get("uid"))
    conn = conn_by_uid.get(uid, {}) if uid else {}
    source = _first_text(row, "source_ip", "id.orig_h") or _first_text(conn, "source_ip", "id.orig_h")
    destination = _first_text(row, "destination_ip", "id.resp_h") or _first_text(conn, "destination_ip", "id.resp_h")
    if not source or not destination:
        return None
    port = _as_int(_first_value(row, "destination_port", "id.resp_p"))
    if port is None:
        port = _as_int(_first_value(conn, "destination_port", "id.resp_p"))
    protocol = _first_text(row, "protocol", "proto") or _first_text(conn, "protocol", "proto") or "tcp"
    timestamp = _first_value(row, "timestamp", "ts")
    if timestamp is None:
        timestamp = _first_value(conn, "timestamp", "ts")

    tls = _tls_state(row, port)
    operation = _first_text(row, *BIND_OPERATION_FIELDS)
    is_bind = log_name == "ldap_bind" or (operation and "bind" in operation.lower())
    auth_method = _first_text(row, *AUTH_METHOD_FIELDS)
    simple_bind = bool(auth_method and "simple" in auth_method.lower())
    identity = _first_text(row, *IDENTITY_FIELDS)
    anonymous = _anonymous_state(row, is_bind, auth_method, identity)

    return {
        "log_name": log_name,
        "uid": uid,
        "source": source,
        "destination": destination,
        "port": port,
        "protocol": protocol,
        "timestamp": timestamp,
        "tls": tls,
        "operation": operation,
        "is_bind": bool(is_bind),
        "auth_method": auth_method,
        "simple_bind": simple_bind,
        "identity": identity,
        "anonymous": anonymous,
        "source_segment": _segment_for_ip(source, segments),
        "destination_segment": _segment_for_ip(destination, segments),
        "row": row,
    }


def _tls_state(row: dict[str, Any], port: int | None) -> bool | None:
    if port == 636:
        return True
    for field in TLS_TRUE_FIELDS:
        if field not in row or row.get(field) is None:
            continue
        value = _bool(row.get(field))
        if value is not None:
            return value
        text = _text(row.get(field)).lower()
        if text in {"tls", "ldaps", "starttls", "start tls", "encrypted", "secure"}:
            return True
        if text in {"none", "plain", "plaintext", "cleartext", "unencrypted"}:
            return False
    return None


def _anonymous_state(
    row: dict[str, Any], is_bind: bool, auth_method: str, identity: str
) -> bool:
    if not is_bind:
        return False
    for field in ANONYMOUS_FIELDS:
        if field in row and row.get(field) is not None:
            value = _bool(row.get(field))
            if value is not None:
                return value
    method = auth_method.lower()
    if "anonymous" in method or method in {"anon", "none"}:
        return True
    # An LDAP bind with an explicitly present but empty identity is an anonymous bind.
    for field in IDENTITY_FIELDS:
        if field in row and row.get(field) in (None, ""):
            return True
    return False


def _load_segments(metadata: dict[str, Any]) -> list[_Segment]:
    raw = metadata.get("segments")
    if not isinstance(raw, list):
        return []
    segments: list[_Segment] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        cidr = _text(item.get("cidr") or item.get("subnet"))
        if not cidr:
            continue
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        role = _first_text(item, *ROLE_FIELDS)
        level = _first_text(item, *LEVEL_FIELDS)
        segments.append(
            _Segment(
                cidr=cidr,
                name=_text(item.get("name")) or cidr,
                role=role,
                purdue_level=level,
                network=network,
            )
        )
    return segments


def _segment_for_ip(value: str, segments: list[_Segment]) -> _Segment | None:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    matches = [segment for segment in segments if address in segment.network]
    return max(matches, key=lambda segment: segment.network.prefixlen) if matches else None


def _is_ot(segment: _Segment) -> bool:
    text = f"{segment.role} {segment.name} {segment.purdue_level}".lower()
    tokens = ("ot", "ics", "scada", "control", "process", "plant", "industrial", "l0", "l1", "l2", "l3")
    return any(token in text for token in tokens)


def _is_enterprise(segment: _Segment) -> bool:
    text = f"{segment.role} {segment.name} {segment.purdue_level}".lower()
    tokens = ("enterprise", "corporate", "business", "directory", "active directory", " ad ", "domain controller", "l4", "l5")
    padded = f" {text} "
    return any(token in padded for token in tokens)


def _bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in (0, 1):
        return bool(value)
    text = _text(value).lower()
    if text in {"true", "t", "yes", "y", "1", "enabled", "on"}:
        return True
    if text in {"false", "f", "no", "n", "0", "disabled", "off"}:
        return False
    return None


def _first_value(row: dict[str, Any], *fields: str) -> Any:
    for field in fields:
        if field in row and row.get(field) is not None:
            return row.get(field)
    return None


def _first_text(row: dict[str, Any], *fields: str) -> str:
    value = _first_value(row, *fields)
    return _text(value)


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _as_int(value: Any) -> int | None:
    try:
        return int(value) if value is not None and value != "" else None
    except (TypeError, ValueError):
        return None
