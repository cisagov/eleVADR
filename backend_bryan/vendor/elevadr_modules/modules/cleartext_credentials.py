from __future__ import annotations

from collections import Counter, defaultdict
from hashlib import sha256
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata


SUPPORTED_PROTOCOLS = ("ftp", "http", "smtp", "telnet")
SUPPORTED_LOGS = ("ftp", "http", "smtp", "telnet", "login")
_PLACEHOLDERS = {"", "-", "(empty)", "<hidden>", "[redacted]", "redacted", "none", "null"}

# Standard Zeek FTP/HTTP can expose credential fields when password capture is enabled.
# SMTP and Telnet credential fields normally require protocol-specific extraction/enrichment.
_FIELD_ALIASES = {
    "ftp": {
        "username": ("username", "user"),
        "password": ("password", "passwd"),
    },
    "http": {
        "username": ("username", "user"),
        "password": ("password", "passwd"),
    },
    "smtp": {
        "username": ("username", "user", "auth_user", "auth_username"),
        "password": ("password", "passwd", "auth_password"),
    },
    "telnet": {
        "username": ("username", "user", "login_user"),
        "password": ("password", "passwd", "login_password"),
    },
}


class CleartextCredentialsModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="cleartext_credentials",
        name="Cleartext Credentials",
        description=(
            "Identifies cleartext credential exposure in FTP, HTTP, SMTP, and Telnet analysis data. "
            "Password values are redacted from results."
        ),
        category="security_analysis",
        required_logs=(),
        required_any_logs=(),
        default_enabled=True,
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        # Each protocol is optional. The module inspects only the corresponding
        # Zeek logs that are present and silently skips protocols whose logs
        # were not generated for the capture.
        events = _collect_events(context)
        grouped: dict[tuple[str, str, str, str, int | None], list[dict[str, Any]]] = defaultdict(list)
        for event in events:
            key = (
                event["protocol"],
                event["username"],
                event["source_ip"],
                event["destination_ip"],
                event["destination_port"],
            )
            grouped[key].append(event)

        findings: list[Finding] = []
        for key, grouped_events in sorted(grouped.items(), key=lambda item: tuple(str(v) for v in item[0])):
            protocol, username, source, destination, port = key
            raw_rows = [event["sanitized_record"] for event in grouped_events]
            timestamps = [
                event["timestamp"] for event in grouped_events if event.get("timestamp") not in (None, "")
            ]
            destination_text = destination or "an unknown destination"
            source_text = source or "an unknown source"
            findings.append(
                Finding(
                    title=f"Cleartext {protocol.upper()} credentials observed",
                    severity="high",
                    summary=(
                        f"Observed {len(grouped_events)} cleartext credential event(s) for user "
                        f"'{username}' from {source_text} to {destination_text} using {protocol.upper()}. "
                        "Password values are redacted from module output."
                    ),
                    confidence="high",
                    detection_basis="protocol_log",
                    devices=_unique_nonempty([source, destination]),
                    services=[protocol.upper()],
                    ports=[port] if isinstance(port, int) else [],
                    connection_pairs=[
                        {
                            "source": source,
                            "destination": destination,
                            "protocol": protocol,
                            "service": protocol.upper(),
                            "port": port,
                        }
                    ],
                    flows=raw_rows,
                    timestamps=timestamps,
                    tags=["cleartext-credentials", "credential-exposure", protocol],
                    metadata={
                        "username": username,
                        "event_count": len(grouped_events),
                        "password_redacted": True,
                        "password_fingerprints": sorted(
                            {event["password_fingerprint"] for event in grouped_events}
                        ),
                        "confidence": "high",
                        "detection_basis": "protocol_log",
                    },
                )
            )

        protocol_counts = Counter(event["protocol"] for event in events)
        warnings: list[str] = []
        if context.smtp and not any(event["protocol"] == "smtp" for event in events):
            warnings.append(
                "smtp.log was present, but no explicit SMTP username/password fields were available. "
                "Standard Zeek smtp.log does not expose SMTP AUTH credentials; protocol-specific extraction is required."
            )
        if (context.telnet or context.login) and not any(event["protocol"] == "telnet" for event in events):
            warnings.append(
                "Telnet/login analysis data was present, but no explicit username/password pair was available. "
                "Modern Zeek does not enable its legacy Telnet login credential analyzer by default."
            )

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "cleartext_credential_events": len(events),
                "unique_credential_exposures": len(grouped),
                "events_by_protocol": dict(sorted(protocol_counts.items())),
            },
            evidence=_evidence_payload(context),
            warnings=warnings,
        )


def _collect_events(context: AnalysisContext) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()

    sources = (
        ("ftp", "ftp"),
        ("http", "http"),
        ("smtp", "smtp"),
        ("telnet", "telnet"),
        ("login", "telnet"),
    )
    for log_name, protocol in sources:
        aliases = _FIELD_ALIASES[protocol]
        for row in context.log(log_name):
            username = _credential_value(row, *aliases["username"])
            password = _credential_value(row, *aliases["password"])
            if not username or not password:
                continue
            event = _credential_event(protocol, row, username, password)
            dedupe_key = (
                event["protocol"],
                event["username"],
                event["source_ip"],
                event["destination_ip"],
                event["destination_port"],
                event["timestamp"],
                event["password_fingerprint"],
            )
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            events.append(event)
    return events


def _credential_event(protocol: str, row: dict[str, Any], username: str, password: str) -> dict[str, Any]:
    sanitized = dict(row)
    password_fields = {
        "password",
        "passwd",
        "auth_password",
        "login_password",
    }
    for field in password_fields:
        if field in sanitized and sanitized[field] not in (None, ""):
            sanitized[field] = "[REDACTED]"
    if str(sanitized.get("command") or "").upper() == "PASS" and sanitized.get("arg") not in (None, ""):
        sanitized["arg"] = "[REDACTED]"

    return {
        "protocol": protocol,
        "username": username,
        "source_ip": str(row.get("source_ip") or row.get("id.orig_h") or ""),
        "destination_ip": str(row.get("destination_ip") or row.get("id.resp_h") or ""),
        "destination_port": _as_int(row.get("destination_port") or row.get("id.resp_p")),
        "timestamp": row.get("timestamp", row.get("ts")),
        "password_fingerprint": sha256(password.encode("utf-8", errors="replace")).hexdigest()[:12],
        "sanitized_record": sanitized,
    }


def _evidence_payload(context: AnalysisContext) -> dict[str, Any]:
    inspected = [name for name in SUPPORTED_LOGS if context.log(name)]
    skipped = [name for name in SUPPORTED_LOGS if not context.log(name)]
    return {
        "inspected_logs": inspected,
        "skipped_logs": skipped,
        "supported_protocols": list(SUPPORTED_PROTOCOLS),
        "supported_logs": list(SUPPORTED_LOGS),
        "passwords_redacted": True,
        "coverage_notes": {
            "ftp": "Direct username/password detection when Zeek FTP password capture is enabled.",
            "http": "Direct HTTP Basic Authentication detection when Zeek HTTP password capture is enabled.",
            "smtp": "Detects explicit credential fields from enriched/custom SMTP analysis; standard smtp.log alone does not expose AUTH passwords.",
            "telnet": "Detects explicit credential fields from Telnet/login analysis; modern Zeek does not enable the legacy login credential analyzer by default.",
        },
    }


def _credential_value(row: dict[str, Any], *names: str) -> str:
    for name in names:
        value = row.get(name)
        if value is None:
            continue
        text = str(value).strip()
        if text.lower() not in _PLACEHOLDERS:
            return text
    return ""


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _unique_nonempty(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))
