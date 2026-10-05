from __future__ import annotations

from collections import defaultdict
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata


MAX_EVIDENCE_FLOWS = 10

# Fields that explicitly mean pre-authentication is required/enabled when true.
PREAUTH_REQUIRED_FIELDS = (
    "preauth_required",
    "pre_auth_required",
    "preauthentication_required",
    "pre_authentication_required",
    "requires_preauth",
    "requires_pre_auth",
)

# Fields that explicitly mean pre-authentication is disabled/optional when true.
PREAUTH_DISABLED_FIELDS = (
    "preauth_disabled",
    "pre_auth_disabled",
    "preauthentication_disabled",
    "pre_authentication_disabled",
    "dont_require_preauth",
    "do_not_require_preauth",
    "no_preauth_required",
    "no_pre_auth_required",
    "asrep_roastable",
)

# Fields that describe whether pre-authentication was actually present/used.
PREAUTH_PRESENT_FIELDS = (
    "preauth",
    "pre_auth",
    "preauth_present",
    "pre_auth_present",
    "preauthentication_present",
    "pre_authentication_present",
    "has_preauth",
    "has_pre_auth",
    "preauth_used",
    "pre_auth_used",
)

PREAUTH_TYPE_FIELDS = (
    "preauth_type",
    "pre_auth_type",
    "preauthentication_type",
    "pre_authentication_type",
    "pa_type",
)

ACCOUNT_FIELDS = (
    "client",
    "client_name",
    "principal",
    "client_principal",
    "username",
    "user",
    "account",
    "cname",
)


class KerberosAsrepRoastableAccountsModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="kerberos_asrep_roastable_accounts",
        name="Kerberos AS-REP Roastable Accounts",
        description=(
            "Detects Kerberos accounts explicitly observed allowing AS authentication without "
            "pre-authentication, a condition associated with AS-REP roasting."
        ),
        category="security_analysis",
        required_logs=("kerberos",),
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        if not context.kerberos:
            return ModuleResult(
                module_id=self.metadata.id,
                findings=[],
                metrics={
                    "asrep_roastable_findings": 0,
                    "explicit_no_preauth_events": 0,
                    "affected_accounts": 0,
                },
                evidence={
                    "inspected_logs": [],
                    "skipped_logs": ["kerberos"],
                    "notes": [
                        "kerberos.log is required for this module; missing logs are skipped cleanly."
                    ],
                },
                warnings=[],
            )

        conn_by_uid = {
            _text(row.get("uid")): row
            for row in context.connections
            if _text(row.get("uid"))
        }

        events: list[dict[str, Any]] = []
        protected_preauth_events = 0
        ambiguous_as_events = 0
        ignored_non_as_events = 0

        for row in context.kerberos:
            request_type = _request_type(row)
            if request_type not in {"AS", "AS_REQ", "AS-REQ", "AS_REP", "AS-REP"}:
                ignored_non_as_events += 1
                continue

            status, detail = _preauth_status(row)
            if status == "required":
                protected_preauth_events += 1
                continue
            if status != "disabled":
                ambiguous_as_events += 1
                continue

            # Require a positive AS exchange when a success field is available. An explicit
            # account flag such as dont_require_preauth=true is sufficient even if success is
            # omitted, because the field itself states the vulnerable account condition.
            success = _explicit_success(row)
            if success is False:
                continue

            events.append(_event(row, conn_by_uid, detail))

        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for event in events:
            account = event["account"] or "(account not logged)"
            grouped[account].append(event)

        findings = [_finding(account, items) for account, items in sorted(grouped.items())]

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "asrep_roastable_findings": len(findings),
                "explicit_no_preauth_events": len(events),
                "affected_accounts": len(grouped),
                "protected_preauth_events": protected_preauth_events,
                "ambiguous_as_events_skipped": ambiguous_as_events,
                "non_as_events_ignored": ignored_non_as_events,
            },
            evidence={
                "inspected_logs": ["kerberos"],
                "skipped_logs": [],
                "detection_requirements": {
                    "positive": (
                        "An AS exchange must contain an explicit field indicating that Kerberos "
                        "pre-authentication is disabled/not required, absent, or type 'none'."
                    ),
                    "not_sufficient": (
                        "A successful AS request/AS-REP by itself is not sufficient because normal "
                        "Kerberos authentication also produces successful AS exchanges after pre-authentication."
                    ),
                },
                "notes": [
                    "AS-REP roasting applies to Kerberos accounts configured so pre-authentication is not required; it is not limited to service accounts.",
                    "KDC_ERR_PREAUTH_REQUIRED and equivalent error text are treated as evidence that pre-authentication is required, not as a finding.",
                    "Stock Zeek kerberos.log deployments may not expose the pre-authentication fields needed for this determination. In that case the module skips ambiguous AS exchanges rather than guessing.",
                    "This finding identifies an account configuration condition visible in protocol telemetry; it does not prove that credential material was cracked or that an attacker successfully compromised the account.",
                ],
            },
            warnings=[],
        )


def _request_type(row: dict[str, Any]) -> str:
    value = _first_text(row, "request_type", "message_type", "msg_type_name", "type")
    normalized = value.upper().replace(" ", "_")
    if normalized in {"AS", "AS_REQ", "AS-REQ", "AS_REP", "AS-REP"}:
        return normalized

    numeric = _as_int(row.get("msg_type"))
    if numeric == 10:
        return "AS_REQ"
    if numeric == 11:
        return "AS_REP"
    return normalized


def _preauth_status(row: dict[str, Any]) -> tuple[str, str]:
    error_text = " ".join(
        filter(
            None,
            [
                _text(row.get("error_msg")),
                _text(row.get("error_text")),
                _text(row.get("error")),
                _text(row.get("status")),
            ],
        )
    ).lower()
    error_code = _as_int(row.get("error_code"))
    if error_code == 25 or "preauth_required" in error_text or "pre-authentication required" in error_text or "preauthentication required" in error_text:
        return "required", "KDC indicates pre-authentication is required"

    for field in PREAUTH_REQUIRED_FIELDS:
        if field not in row or row.get(field) is None:
            continue
        value = _bool(row.get(field))
        if value is False:
            return "disabled", f"{field}=false"
        if value is True:
            return "required", f"{field}=true"

    for field in PREAUTH_DISABLED_FIELDS:
        if field not in row or row.get(field) is None:
            continue
        value = _bool(row.get(field))
        if value is True:
            return "disabled", f"{field}=true"
        if value is False:
            return "required", f"{field}=false"

    for field in PREAUTH_PRESENT_FIELDS:
        if field not in row or row.get(field) is None:
            continue
        value = _bool(row.get(field))
        if value is False:
            return "disabled", f"{field}=false"
        if value is True:
            return "required", f"{field}=true"

    for field in PREAUTH_TYPE_FIELDS:
        if field not in row or row.get(field) is None:
            continue
        text = _text(row.get(field)).lower().replace("_", " ").replace("-", " ")
        compact = " ".join(text.split())
        if compact in {"none", "no preauth", "no pre auth", "absent", "disabled", "0"}:
            return "disabled", f"{field}={_text(row.get(field))}"
        if compact:
            return "required", f"{field}={_text(row.get(field))}"

    return "unknown", ""


def _explicit_success(row: dict[str, Any]) -> bool | None:
    for field in ("success", "auth_success", "authentication_success"):
        if field in row and row.get(field) is not None:
            return _bool(row.get(field))
    return None


def _event(
    row: dict[str, Any], conn_by_uid: dict[str, dict[str, Any]], detail: str
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
    protocol = _first_text(row, "protocol", "proto") or _first_text(conn, "protocol", "proto") or "tcp/udp"
    account = _first_text(row, *ACCOUNT_FIELDS)
    realm = _first_text(row, "client_realm", "realm", "domain")
    return {
        "account": account,
        "realm": realm,
        "detail": detail,
        "source": source,
        "destination": destination,
        "port": port if port is not None else 88,
        "timestamp": timestamp,
        "protocol": protocol,
        "uid": uid,
        "row": row,
        "connection": conn or None,
    }


def _finding(account: str, items: list[dict[str, Any]]) -> Finding:
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
        pairs.append(
            {
                "source": item["source"],
                "destination": item["destination"],
                "port": item["port"],
                "protocol": item["protocol"],
                "service": "Kerberos",
            }
        )

    flows = []
    for item in evidence:
        flow = dict(item["row"])
        flow["elevadr_evidence"] = item["detail"]
        flows.append(flow)

    timestamps = [item["timestamp"] for item in evidence if item["timestamp"] is not None]
    details = sorted({item["detail"] for item in items})
    realms = sorted({item["realm"] for item in items if item["realm"]})

    label = account if account != "(account not logged)" else "Kerberos account"
    return Finding(
        title=f"Kerberos account allows AS authentication without pre-authentication: {label}",
        severity="high",
        summary=(
            f"Kerberos protocol-log evidence explicitly indicates that {label} can complete or request AS authentication without pre-authentication. "
            "Accounts configured this way can expose an AS-REP encrypted with key material derived from the account password, enabling offline password-guessing attacks. "
            "Review the account configuration and whether pre-authentication can be required."
        ),
        confidence="high",
        detection_basis="protocol_log",
        devices=devices,
        services=["Kerberos"],
        ports=ports or [88],
        connection_pairs=pairs,
        flows=flows,
        subnets=[],
        timestamps=timestamps,
        tags=["kerberos", "as-rep", "asrep-roasting", "preauthentication", "identity-security"],
        metadata={
            "account": None if account == "(account not logged)" else account,
            "realms": realms,
            "event_count": len(items),
            "evidence_event_count": len(evidence),
            "evidence_truncated": len(items) > len(evidence),
            "evidence_fields": details,
            "preauthentication_required": False,
            "attack_condition": "asrep_roastable",
        },
    )


def _bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in {0, 1}:
        return bool(value)
    text = _text(value).lower().replace("_", " ").replace("-", " ")
    text = " ".join(text.split())
    if text in {"true", "t", "yes", "y", "1", "enabled", "on", "required", "present", "used"}:
        return True
    if text in {"false", "f", "no", "n", "0", "disabled", "off", "not required", "absent", "none"}:
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
