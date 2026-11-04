from __future__ import annotations

from collections import defaultdict
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata

MAX_EVIDENCE_FLOWS = 10

SESSION_NLA_FIELDS = (
    "nla",
    "nla_enabled",
    "network_level_authentication",
    "network_level_authentication_enabled",
    "credssp",
    "credssp_enabled",
    "using_nla",
    "used_nla",
)
NLA_REQUIRED_FIELDS = (
    "nla_required",
    "require_nla",
    "network_level_authentication_required",
    "requires_nla",
)
SECURITY_PROTOCOL_FIELDS = (
    "security_protocol",
    "selected_protocol",
    "negotiated_protocol",
    "selected_security_protocol",
    "protocol_selected",
)

NLA_PROTOCOLS = {
    "hybrid",
    "hybrid_ex",
    "hybridex",
    "credssp",
    "nla",
    "protocol_hybrid",
    "protocol_hybrid_ex",
}
NON_NLA_PROTOCOLS = {
    "rdp",
    "standard_rdp",
    "rdp_standard",
    "standard",
    "ssl",
    "tls",
    "protocol_rdp",
    "protocol_ssl",
}

TRUE_VALUES = {"1", "true", "t", "yes", "y", "enabled", "enable", "on", "required"}
FALSE_VALUES = {"0", "false", "f", "no", "n", "disabled", "disable", "off", "not_required", "none"}


class RdpNlaDisabledModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="rdp_nla_disabled",
        name="Unexpected RDP with NLA Disabled",
        description=(
            "Identifies RDP sessions where protocol telemetry explicitly shows Network Level Authentication "
            "(NLA/CredSSP) was not used, plus lower-severity cases where NLA is explicitly not required."
        ),
        category="security_analysis",
        required_logs=("rdp",),
        default_enabled=True,
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        if not context.rdp:
            return ModuleResult(
                module_id=self.metadata.id,
                findings=[],
                metrics={
                    "rdp_events_evaluated": 0,
                    "nla_disabled_events": 0,
                    "nla_not_required_events": 0,
                    "nla_protected_events": 0,
                    "nla_state_unknown_events": 0,
                    "rdp_nla_findings": 0,
                    "affected_devices": 0,
                },
                evidence={
                    "inspected_logs": [],
                    "notes": _notes(),
                },
                warnings=[],
            )

        conn_by_uid = {
            str(row.get("uid")): row
            for row in context.connections
            if row.get("uid") not in (None, "")
        }

        events: list[dict[str, Any]] = []
        protected = 0
        unknown = 0
        for row in context.rdp:
            assessment = _assess_nla(row)
            if assessment["state"] == "protected":
                protected += 1
                continue
            if assessment["state"] == "unknown":
                unknown += 1
                continue
            events.append(_event(row, assessment, conn_by_uid))

        findings = _build_findings(events)
        affected = {
            value
            for event in events
            for value in (event["source"], event["destination"])
            if value
        }

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "rdp_events_evaluated": len(context.rdp),
                "nla_disabled_events": sum(1 for event in events if event["state"] == "disabled"),
                "nla_not_required_events": sum(1 for event in events if event["state"] == "not_required"),
                "nla_protected_events": protected,
                "nla_state_unknown_events": unknown,
                "rdp_nla_findings": len(findings),
                "affected_devices": len(affected),
            },
            evidence={
                "inspected_logs": ["rdp"],
                "notes": _notes(),
            },
            warnings=[],
        )


def _assess_nla(row: dict[str, Any]) -> dict[str, Any]:
    # Session-state fields are strongest: an explicit false means NLA/CredSSP
    # was not used for the observed RDP session.
    for field in SESSION_NLA_FIELDS:
        if field not in row or row.get(field) in (None, ""):
            continue
        value = _as_bool(row.get(field))
        if value is False:
            return {"state": "disabled", "field": field, "value": row.get(field), "reason": "explicit_session_state"}
        if value is True:
            return {"state": "protected", "field": field, "value": row.get(field), "reason": "explicit_session_state"}

    # RDP negotiation selects HYBRID/HYBRID_EX when CredSSP/NLA is used.
    # Selecting native RDP or TLS/SSL alone means the session did not use NLA.
    for field in SECURITY_PROTOCOL_FIELDS:
        if field not in row or row.get(field) in (None, ""):
            continue
        token = _norm_token(row.get(field))
        if token in NLA_PROTOCOLS:
            return {"state": "protected", "field": field, "value": row.get(field), "reason": "negotiated_security_protocol"}
        if token in NON_NLA_PROTOCOLS:
            return {"state": "disabled", "field": field, "value": row.get(field), "reason": "negotiated_security_protocol"}

    # A server policy that does not require NLA is weaker than proof that this
    # specific session skipped NLA, so report it separately at lower severity.
    for field in NLA_REQUIRED_FIELDS:
        if field not in row or row.get(field) in (None, ""):
            continue
        value = _as_bool(row.get(field))
        if value is False:
            return {"state": "not_required", "field": field, "value": row.get(field), "reason": "server_policy"}
        if value is True:
            return {"state": "unknown", "field": field, "value": row.get(field), "reason": "server_policy_only"}

    return {"state": "unknown", "field": None, "value": None, "reason": "no_explicit_nla_state"}


def _event(
    row: dict[str, Any],
    assessment: dict[str, Any],
    conn_by_uid: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    uid = _text(row.get("uid"))
    conn = conn_by_uid.get(uid, {}) if uid else {}
    source = _first_text(row, "source_ip", "id.orig_h") or _first_text(conn, "source_ip", "id.orig_h")
    destination = _first_text(row, "destination_ip", "id.resp_h") or _first_text(conn, "destination_ip", "id.resp_h")
    port = _as_int(_first_value(row, "destination_port", "id.resp_p"))
    if port is None:
        port = _as_int(_first_value(conn, "destination_port", "id.resp_p"))
    timestamp = _first_value(row, "timestamp", "ts")
    if timestamp is None:
        timestamp = _first_value(conn, "timestamp", "ts")
    return {
        "state": assessment["state"],
        "field": assessment["field"],
        "field_value": assessment["value"],
        "reason": assessment["reason"],
        "source": source,
        "destination": destination,
        "port": port,
        "timestamp": timestamp,
        "uid": uid,
        "row": row,
        "connection": conn or None,
    }


def _build_findings(events: list[dict[str, Any]]) -> list[Finding]:
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        grouped[(event["state"], event["source"], event["destination"])].append(event)

    findings: list[Finding] = []
    for (state, source, destination), items in sorted(grouped.items()):
        event_count = len(items)
        representative = items[:MAX_EVIDENCE_FLOWS]
        ports = sorted({item["port"] for item in items if item["port"] is not None})
        fields = sorted({item["field"] for item in items if item["field"]})
        values = sorted({str(item["field_value"]) for item in items if item["field_value"] not in (None, "")})
        devices = sorted({value for item in items for value in (item["source"], item["destination"]) if value})

        if state == "disabled":
            severity = "medium"
            title = "RDP session observed without Network Level Authentication"
            summary = (
                f"RDP protocol telemetry shows {event_count} session event(s)"
                + (f" from {source}" if source else "")
                + (f" to {destination}" if destination else "")
                + " where NLA/CredSSP was explicitly absent or the negotiated RDP security protocol was a non-NLA mode. "
                "RDP without NLA exposes more of the remote desktop service before user authentication and is a weaker configuration. "
                "Confirm whether this is an approved legacy exception and correlate with host configuration and authentication activity."
            )
            tags = ["rdp", "nla-disabled", "credssp", "remote-access"]
            nla_disabled_confirmed = True
        else:
            severity = "low"
            title = "RDP endpoint does not require Network Level Authentication"
            summary = (
                f"RDP protocol telemetry shows {event_count} event(s)"
                + (f" from {source}" if source else "")
                + (f" to {destination}" if destination else "")
                + " where the endpoint policy explicitly indicates that NLA is not required. This does not prove that the observed session itself skipped NLA, "
                "but it identifies a weaker RDP configuration that permits non-NLA negotiation and should be reviewed against remote-access policy."
            )
            tags = ["rdp", "nla-not-required", "remote-access", "configuration-review"]
            nla_disabled_confirmed = False

        findings.append(
            Finding(
                title=title,
                severity=severity,
                summary=summary,
                confidence="high",
                detection_basis="protocol_log",
                devices=devices,
                services=["RDP"],
                ports=ports,
                connection_pairs=_pairs(items),
                flows=[_flow(item) for item in representative],
                subnets=[],
                timestamps=[item["timestamp"] for item in representative if item["timestamp"] is not None],
                tags=tags,
                metadata={
                    "nla_state": state,
                    "nla_disabled_confirmed": nla_disabled_confirmed,
                    "source": source or None,
                    "destination": destination or None,
                    "event_count": event_count,
                    "evidence_fields": fields,
                    "evidence_values": values,
                    "evidence_event_count": len(representative),
                    "evidence_truncated": event_count > len(representative),
                },
            )
        )
    return findings


def _pairs(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, int | None]] = set()
    pairs: list[dict[str, Any]] = []
    for item in items:
        source = item["source"]
        destination = item["destination"]
        if not source and not destination:
            continue
        key = (source, destination, item["port"])
        if key in seen:
            continue
        seen.add(key)
        pairs.append(
            {
                "source": source or None,
                "destination": destination or None,
                "port": item["port"],
                "protocol": "tcp",
                "service": "RDP",
            }
        )
    return pairs


def _flow(item: dict[str, Any]) -> dict[str, Any]:
    row = dict(item["row"])
    row["nla_assessment"] = item["state"]
    row["nla_evidence_field"] = item["field"]
    row["nla_evidence_value"] = item["field_value"]
    return row


def _notes() -> list[str]:
    return [
        "The detector requires explicit RDP protocol-log evidence about NLA/CredSSP or the negotiated RDP security protocol; TCP/3389 alone is never sufficient.",
        "HYBRID/HYBRID_EX, CredSSP, or explicit NLA=true evidence is treated as NLA-protected and does not generate a finding.",
        "Native RDP security or TLS/SSL selected without HYBRID/CredSSP is treated as a session without NLA because TLS transport alone is not Network Level Authentication.",
        "A policy field showing NLA is not required is reported separately at lower severity because it does not prove that the observed session actually omitted NLA.",
        "RDP events with no explicit NLA/security-protocol state are left unclassified rather than inferred from destination port or service presence.",
        "Evidence is capped at 10 representative RDP events while full event counts remain in finding metadata.",
    ]


def _as_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in (0, 1):
        return bool(value)
    token = _norm_token(value)
    if token in TRUE_VALUES:
        return True
    if token in FALSE_VALUES:
        return False
    return None


def _norm_token(value: Any) -> str:
    text = str(value).strip().lower()
    for char in (" ", "-", "/", "\\", "."):
        text = text.replace(char, "_")
    while "__" in text:
        text = text.replace("__", "_")
    return text.strip("_")


def _text(value: Any) -> str:
    return "" if value in (None, "") else str(value)


def _first_text(row: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = row.get(key)
        if value not in (None, ""):
            return str(value)
    return ""


def _first_value(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if row.get(key) not in (None, ""):
            return row.get(key)
    return None


def _as_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
