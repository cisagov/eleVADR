from __future__ import annotations

from collections import defaultdict
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata

MAX_EVIDENCE_FLOWS = 10

SMB_LOGS = ("smb", "smb_mapping", "smb_files", "smb_cmd")
SIGNING_DISABLED_FIELDS = (
    "signing_enabled",
    "smb_signing_enabled",
    "message_signing_enabled",
    "security_signing_enabled",
)
SIGNED_FIELDS = (
    "signed",
    "is_signed",
    "message_signed",
    "smb_signed",
)
SIGNING_REQUIRED_FIELDS = (
    "signing_required",
    "smb_signing_required",
    "message_signing_required",
    "security_signing_required",
)
SIGNING_TEXT_FIELDS = (
    "signing",
    "smb_signing",
    "message_signing",
    "security_mode",
    "security_flags",
)
NTLM_VERSION_FIELDS = (
    "ntlm_version",
    "auth_version",
    "authentication_version",
    "protocol_version",
    "ntlmssp_version",
    "version",
)


class SmbSigningNtlmv1Module(AnalysisModule):
    metadata = ModuleMetadata(
        id="smb_signing_disabled_ntlmv1",
        name="SMB Signing Disabled or NTLMv1 Detected",
        description=(
            "Identifies SMB sessions explicitly observed without message signing or with signing disabled/not required, "
            "and NTLM authentication records that explicitly identify NTLMv1."
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

        smb_events: list[dict[str, Any]] = []
        for log_name in SMB_LOGS:
            for row in context.log(log_name):
                event = _smb_signing_event(row, log_name, conn_by_uid)
                if event:
                    smb_events.append(event)

        ntlm_events: list[dict[str, Any]] = []
        for row in context.ntlm:
            version = _explicit_ntlm_version(row)
            if version != 1:
                continue
            ntlm_events.append(_event(row, "ntlm", conn_by_uid, issue="ntlmv1", detail="NTLMv1"))

        findings: list[Finding] = []
        findings.extend(_group_smb_findings(smb_events))
        findings.extend(_group_ntlm_findings(ntlm_events))

        inspected = [name for name in (*SMB_LOGS, "ntlm") if context.log(name)]
        skipped = [name for name in (*SMB_LOGS, "ntlm") if not context.log(name)]

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "smb_ntlm_findings": len(findings),
                "unsigned_or_signing_disabled_sessions": sum(
                    1 for event in smb_events if event["issue"] == "signing_disabled"
                ),
                "signing_not_required_sessions": sum(
                    1 for event in smb_events if event["issue"] == "signing_not_required"
                ),
                "ntlmv1_events": len(ntlm_events),
                "affected_devices": len({device for finding in findings for device in finding.devices}),
            },
            evidence={
                "inspected_logs": inspected,
                "skipped_optional_logs": skipped,
                "coverage": {
                    "smb_signing": (
                        "Requires an SMB protocol log to expose an explicit signed/signing-enabled/signing-required field "
                        "or an equivalent textual security-mode value. TCP/445 alone is never used to infer signing state."
                    ),
                    "ntlmv1": (
                        "Requires ntlm.log to explicitly identify NTLM version 1 in a supported version field. "
                        "The module does not infer NTLMv1 from SMB ports, usernames, or authentication failure alone."
                    ),
                },
                "notes": [
                    "An explicitly unsigned SMB session or disabled signing is stronger evidence than a server merely advertising that signing is not required.",
                    "Signing-not-required findings are therefore lower severity than confirmed unsigned/disabled-signing sessions.",
                    "NTLMv1 is reported only from explicit protocol-log version evidence to avoid misclassifying NTLMv2 traffic.",
                    "Missing SMB/NTLM logs or missing signing/version fields cause the relevant check to skip quietly rather than guess.",
                ],
            },
            warnings=[],
        )


def _smb_signing_event(
    row: dict[str, Any], log_name: str, conn_by_uid: dict[str, dict[str, Any]]
) -> dict[str, Any] | None:
    for field in SIGNED_FIELDS:
        if field in row and row.get(field) is not None:
            value = _bool(row.get(field))
            if value is False:
                return _event(row, log_name, conn_by_uid, "signing_disabled", f"{field}=false")
            if value is True:
                return None

    for field in SIGNING_DISABLED_FIELDS:
        if field in row and row.get(field) is not None:
            value = _bool(row.get(field))
            if value is False:
                return _event(row, log_name, conn_by_uid, "signing_disabled", f"{field}=false")
            if value is True:
                return None

    for field in SIGNING_TEXT_FIELDS:
        text = _text(row.get(field)).lower()
        if not text:
            continue
        compact = text.replace("_", " ").replace("-", " ")
        if any(token in compact for token in ("disabled", "not signed", "unsigned", "signing off", "signing=false")):
            return _event(row, log_name, conn_by_uid, "signing_disabled", f"{field}={text}")
        if any(token in compact for token in ("required", "enabled", "signed")) and "not required" not in compact:
            return None
        if "not required" in compact or "optional" in compact:
            return _event(row, log_name, conn_by_uid, "signing_not_required", f"{field}={text}")

    for field in SIGNING_REQUIRED_FIELDS:
        if field in row and row.get(field) is not None:
            value = _bool(row.get(field))
            if value is False:
                return _event(row, log_name, conn_by_uid, "signing_not_required", f"{field}=false")
            if value is True:
                return None

    return None


def _explicit_ntlm_version(row: dict[str, Any]) -> int | None:
    for field in NTLM_VERSION_FIELDS:
        if field not in row or row.get(field) is None:
            continue
        raw = row.get(field)
        if isinstance(raw, (int, float)) and not isinstance(raw, bool):
            value = int(raw)
            if value in {1, 2}:
                return value
            continue
        text = _text(raw).lower().replace(" ", "").replace("_", "").replace("-", "")
        if text in {"1", "v1", "ntlm1", "ntlmv1", "ntlmssp1", "ntlmsspv1"}:
            return 1
        if text in {"2", "v2", "ntlm2", "ntlmv2", "ntlmssp2", "ntlmsspv2"}:
            return 2
    return None


def _event(
    row: dict[str, Any],
    log_name: str,
    conn_by_uid: dict[str, dict[str, Any]],
    issue: str,
    detail: str,
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
    protocol = _first_text(row, "protocol", "proto") or _first_text(conn, "protocol", "proto") or "tcp"
    return {
        "issue": issue,
        "detail": detail,
        "log_name": log_name,
        "source": source,
        "destination": destination,
        "port": port,
        "timestamp": timestamp,
        "protocol": protocol,
        "uid": uid,
        "row": row,
        "connection": conn or None,
    }


def _group_smb_findings(events: list[dict[str, Any]]) -> list[Finding]:
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        grouped[(event["issue"], event["source"], event["destination"])].append(event)

    findings = []
    for (issue, source, destination), items in sorted(grouped.items()):
        disabled = issue == "signing_disabled"
        title = "SMB session observed without message signing" if disabled else "SMB signing is not required"
        severity = "medium" if disabled else "low"
        summary = (
            "SMB protocol-log evidence indicates that message signing was disabled or the observed session was unsigned. "
            "Unsigned SMB traffic is susceptible to tampering and relay-style attacks when an attacker can position themselves on the communication path."
            if disabled
            else "SMB protocol-log evidence indicates that message signing was not required. This does not prove that the observed session was unsigned, but it permits unsigned SMB sessions and should be reviewed against site policy."
        )
        findings.append(_finding(title, severity, "high", "SMB", items, summary, ["smb", "message-signing", issue]))
    return findings


def _group_ntlm_findings(events: list[dict[str, Any]]) -> list[Finding]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        grouped[(event["source"], event["destination"])].append(event)

    findings = []
    for (_source, _destination), items in sorted(grouped.items()):
        findings.append(
            _finding(
                "Legacy NTLMv1 authentication detected",
                "high",
                "high",
                "NTLMv1",
                items,
                "NTLM protocol-log evidence explicitly identifies NTLM version 1. NTLMv1 is a legacy authentication mechanism with substantially weaker protections than NTLMv2 and should be removed where operationally feasible.",
                ["ntlm", "ntlmv1", "legacy-authentication"],
            )
        )
    return findings


def _finding(
    title: str,
    severity: str,
    confidence: str,
    service: str,
    items: list[dict[str, Any]],
    summary: str,
    tags: list[str],
) -> Finding:
    evidence = items[:MAX_EVIDENCE_FLOWS]
    devices = sorted({value for item in items for value in (item["source"], item["destination"]) if value})
    ports = sorted({item["port"] for item in items if isinstance(item["port"], int)})
    pairs = []
    seen_pairs = set()
    for item in items:
        if not item["source"] or not item["destination"]:
            continue
        key = (item["source"], item["destination"], item["port"], item["protocol"])
        if key in seen_pairs:
            continue
        seen_pairs.add(key)
        pairs.append({
            "source": item["source"],
            "destination": item["destination"],
            "port": item["port"],
            "protocol": item["protocol"],
            "service": service,
        })

    flows = []
    for item in evidence:
        flow = dict(item["row"])
        flow["elevadr_log"] = item["log_name"]
        flow["elevadr_evidence"] = item["detail"]
        flows.append(flow)

    timestamps = [item["timestamp"] for item in evidence if item["timestamp"] is not None]
    details = sorted({item["detail"] for item in items})
    logs = sorted({item["log_name"] for item in items})

    return Finding(
        title=title,
        severity=severity,
        summary=summary,
        confidence=confidence,
        detection_basis="protocol_log",
        devices=devices,
        services=[service],
        ports=ports,
        connection_pairs=pairs,
        flows=flows,
        subnets=[],
        timestamps=timestamps,
        tags=tags,
        metadata={
            "event_count": len(items),
            "evidence_event_count": len(evidence),
            "evidence_truncated": len(items) > len(evidence),
            "evidence_fields": details,
            "source_logs": logs,
            "source": items[0]["source"],
            "destination": items[0]["destination"],
        },
    )


def _bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in {0, 1}:
        return bool(value)
    text = _text(value).lower()
    if text in {"true", "t", "yes", "y", "1", "enabled", "on", "signed", "required"}:
        return True
    if text in {"false", "f", "no", "n", "0", "disabled", "off", "unsigned", "not required"}:
        return False
    return None


def _first_value(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = row.get(key)
        if value not in (None, ""):
            return value
    return None


def _first_text(row: dict[str, Any], *keys: str) -> str:
    value = _first_value(row, *keys)
    return _text(value)


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
