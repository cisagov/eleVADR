from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata


@dataclass(frozen=True, slots=True)
class ServiceRule:
    key: str
    name: str
    ports: tuple[int, ...]
    transports: tuple[str, ...]
    severity: str
    reason: str
    service_names: tuple[str, ...] = ()


SERVICE_RULES: tuple[ServiceRule, ...] = (
    ServiceRule(
        "telnet",
        "Telnet",
        (23,),
        ("tcp",),
        "high",
        "Telnet provides remote terminal access without transport encryption.",
        ("telnet",),
    ),
    ServiceRule(
        "rlogin",
        "rlogin",
        (513,),
        ("tcp",),
        "high",
        "rlogin is a legacy remote-login protocol that does not provide modern transport protection.",
        ("rlogin",),
    ),
    ServiceRule(
        "rsh",
        "rsh",
        (514,),
        ("tcp",),
        "high",
        "rsh is a legacy remote-shell protocol that does not provide modern transport protection.",
        ("rsh",),
    ),
    ServiceRule(
        "rexec",
        "rexec",
        (512,),
        ("tcp",),
        "high",
        "rexec is a legacy remote-execution protocol that can expose authentication and command data.",
        ("rexec",),
    ),
    ServiceRule(
        "ftp",
        "FTP",
        (21,),
        ("tcp",),
        "medium",
        "FTP control traffic is unencrypted and can expose credentials and transferred metadata.",
        ("ftp",),
    ),
    ServiceRule(
        "tftp",
        "TFTP",
        (69,),
        ("udp",),
        "medium",
        "TFTP provides unauthenticated, unencrypted file transfer.",
        ("tftp",),
    ),
    ServiceRule(
        "http",
        "HTTP",
        (80,),
        ("tcp",),
        "medium",
        "HTTP does not provide transport encryption; sensitive application data should use HTTPS/TLS.",
        ("http",),
    ),
    ServiceRule(
        "smtp_plain",
        "SMTP without confirmed TLS",
        (25,),
        ("tcp",),
        "medium",
        "SMTP on a plaintext session can expose message and authentication data. STARTTLS-capable sessions are excluded when Zeek confirms TLS.",
        ("smtp",),
    ),
    ServiceRule(
        "pop3",
        "POP3",
        (110,),
        ("tcp",),
        "medium",
        "POP3 without TLS transmits mail authentication and content without transport encryption.",
        ("pop3",),
    ),
    ServiceRule(
        "imap",
        "IMAP",
        (143,),
        ("tcp",),
        "medium",
        "IMAP without TLS can expose authentication and mailbox data.",
        ("imap",),
    ),
    ServiceRule(
        "finger",
        "Finger",
        (79,),
        ("tcp",),
        "low",
        "Finger is a legacy information-disclosure protocol that can expose user and host details.",
        ("finger",),
    ),
    ServiceRule(
        "snmp_plain",
        "SNMP (version not confirmed)",
        (161, 162),
        ("udp",),
        "low",
        "SNMPv1/v2c use plaintext community strings. conn.log alone cannot confirm the SNMP version, so this is a review indicator.",
        ("snmp",),
    ),
)



class DeprecatedInsecureServicesProtocolsModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="deprecated_insecure_services_protocols",
        name="Deprecated / Insecure Connection Services and Protocols",
        description=(
            "Identifies observed use of legacy, plaintext, or otherwise insecure connection services "
            "and insecure connection protocols."
        ),
        category="security_analysis",
        required_logs=("conn",),
        default_enabled=True,
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        matches: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        rule_by_key = {rule.key: rule for rule in SERVICE_RULES}
        smtp_tls_uids = _smtp_tls_uids(context.smtp)
        protocol_log_uids = _protocol_log_uids(context)

        for row in context.connections:
            matched = _match_service_rule(row)
            if matched is None:
                continue
            rule, basis = matched
            uid = str(row.get("uid") or "")
            if rule.key == "smtp_plain" and uid in smtp_tls_uids:
                continue
            if uid and uid in protocol_log_uids.get(rule.key, set()):
                basis = "protocol_log"
            matches[(rule.key, basis)].append(row)

        findings: list[Finding] = []
        low_confidence_flows = 0
        confirmed_flows = 0
        flow_counts = Counter()
        unique_rule_keys: set[str] = set()

        for key, basis in sorted(matches):
            rule = rule_by_key[key]
            rows = matches[(key, basis)]
            findings.append(_service_finding(rule, rows, basis))
            unique_rule_keys.add(key)
            flow_counts[_finding_service_name(rule, basis)] += len(rows)
            if basis == "port":
                low_confidence_flows += len(rows)
            else:
                confirmed_flows += len(rows)

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "insecure_or_deprecated_flows": sum(len(rows) for rows in matches.values()),
                "unique_insecure_service_types": len(unique_rule_keys),
                "confirmed_insecure_flows": confirmed_flows,
                "low_confidence_port_indicators": low_confidence_flows,
                "flows_by_service": dict(sorted(flow_counts.items())),
            },
            evidence={
                "inspected_logs": [name for name in ("conn", "ftp", "http", "smtp", "telnet", "login", "ssl") if context.log(name)],
                "skipped_optional_logs": [name for name in ("ftp", "http", "smtp", "telnet", "login", "ssl") if not context.log(name)],
                "service_rules": [
                    {
                        "id": rule.key,
                        "name": rule.name,
                        "ports": list(rule.ports),
                        "transports": list(rule.transports),
                        "severity": rule.severity,
                    }
                    for rule in SERVICE_RULES
                ],
                "notes": [
                    "Protocol-log confirmation is high confidence; Zeek service identification is high confidence; well-known-port-only matches are low-confidence review indicators.",
                    "Port-only matches have reduced severity, and SYN-only/failed connection attempts are reported as low-severity connection attempts rather than confirmed insecure sessions.",
                    "SMTP sessions are excluded when smtp.log explicitly confirms TLS for the same Zeek UID.",
                    "SNMP on UDP/161 or UDP/162 is reported as a low-severity review indicator because conn.log does not identify SNMPv1/v2c versus SNMPv3.",
                ],
            },
            warnings=[],
        )


def _match_service_rule(row: dict[str, Any]) -> tuple[ServiceRule, str] | None:
    port = _as_int(row.get("destination_port", row.get("id.resp_p")))
    transport = str(row.get("protocol", row.get("proto")) or "").lower()
    service = str(row.get("service") or "").lower()
    for rule in SERVICE_RULES:
        if service and service in rule.service_names:
            return rule, "zeek_service"
        if port in rule.ports and transport in rule.transports:
            return rule, "port"
    return None


def _service_finding(rule: ServiceRule, rows: list[dict[str, Any]], basis: str) -> Finding:
    devices: list[str] = []
    pairs: list[dict[str, Any]] = []
    timestamps: list[float | str] = []
    ports: list[int] = []
    seen_pairs: set[tuple[str, str, int | None, str]] = set()

    for row in rows:
        source = str(row.get("source_ip", row.get("id.orig_h")) or "")
        destination = str(row.get("destination_ip", row.get("id.resp_h")) or "")
        port = _as_int(row.get("destination_port", row.get("id.resp_p")))
        transport = str(row.get("protocol", row.get("proto")) or "").lower()
        timestamp = row.get("timestamp", row.get("ts"))
        if source:
            devices.append(source)
        if destination:
            devices.append(destination)
        if port is not None:
            ports.append(port)
        if timestamp not in (None, ""):
            timestamps.append(timestamp)
        pair_key = (source, destination, port, transport)
        if pair_key not in seen_pairs:
            seen_pairs.add(pair_key)
            pairs.append(
                {
                    "source": source,
                    "destination": destination,
                    "port": port,
                    "protocol": transport,
                    "service": _finding_service_name(rule, basis),
                }
            )

    confidence = "low" if basis == "port" else "high"
    severity = rule.severity
    title_prefix = "Deprecated or insecure service observed"
    summary_prefix = f"Observed {len(rows)} flow(s) associated with {_finding_service_name(rule, basis)}."

    if basis == "port":
        severity = _downgrade_severity(severity)
        if all(_is_attempt_only(row) for row in rows):
            severity = "low"
            title_prefix = "Connection attempt to insecure service port"
            summary_prefix = (
                f"Observed {len(rows)} connection attempt(s) to the well-known port for "
                f"{_finding_service_name(rule, basis)}. The application protocol was not confirmed by Zeek."
            )
        else:
            title_prefix = "Potential deprecated or insecure service observed"
            summary_prefix = (
                f"Observed {len(rows)} flow(s) to the well-known port for {_finding_service_name(rule, basis)}. "
                "The application protocol was not confirmed by Zeek."
            )

    service_name = _finding_service_name(rule, basis)
    return Finding(
        title=f"{title_prefix}: {service_name}",
        severity=severity,
        summary=f"{summary_prefix} {rule.reason}",
        confidence=confidence,
        detection_basis=basis,
        devices=_unique(devices),
        services=[service_name],
        ports=sorted(set(ports)),
        connection_pairs=pairs,
        flows=[_sanitize_flow(row) for row in rows],
        timestamps=timestamps,
        tags=["deprecated-service", "insecure-protocol", rule.key],
        metadata={
            "rule_id": rule.key,
            "flow_count": len(rows),
            "reason": rule.reason,
            "confidence": confidence,
            "detection_basis": basis,
        },
    )


def _finding_service_name(rule: ServiceRule, basis: str) -> str:
    if rule.key == "smtp_plain" and basis == "port":
        return "SMTP"
    return rule.name


def _downgrade_severity(severity: str) -> str:
    return {"critical": "high", "high": "medium", "medium": "low", "low": "low"}.get(severity.lower(), "low")


def _is_attempt_only(row: dict[str, Any]) -> bool:
    state = str(row.get("zeek_state", row.get("conn_state")) or "").upper()
    return state in {"S0", "REJ", "RSTOS0", "SH", "SHR"}


def _protocol_log_uids(context: AnalysisContext) -> dict[str, set[str]]:
    mapping = {
        "ftp": (context.ftp,),
        "http": (context.http,),
        "smtp_plain": (context.smtp,),
        "telnet": (context.telnet, context.login),
    }
    result: dict[str, set[str]] = {}
    for key, collections in mapping.items():
        uids: set[str] = set()
        for rows in collections:
            for row in rows:
                uid = str(row.get("uid") or "")
                if uid:
                    uids.add(uid)
        result[key] = uids
    return result


def _smtp_tls_uids(rows: list[dict[str, Any]]) -> set[str]:
    tls_uids: set[str] = set()
    for row in rows:
        value = row.get("tls")
        is_tls = value is True or str(value).strip().lower() in {"t", "true", "1", "yes"}
        uid = str(row.get("uid") or "")
        if is_tls and uid:
            tls_uids.add(uid)
    return tls_uids


def _sanitize_flow(row: dict[str, Any]) -> dict[str, Any]:
    # This module does not need payload/authentication material. Keep evidence to
    # flow/protocol metadata and omit obvious secret-bearing fields if present.
    blocked = {"password", "passwd", "auth_password", "authorization", "cookie"}
    return {key: value for key, value in row.items() if key.lower() not in blocked}


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))
