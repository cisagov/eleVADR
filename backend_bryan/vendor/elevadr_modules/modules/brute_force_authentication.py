from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Callable

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata

WINDOW_SECONDS = 60.0
MIN_PROTOCOL_FAILURES = 5
MIN_CONNECTION_ATTEMPTS = 8
MAX_EVIDENCE_FLOWS = 50
FAILED_CONN_STATES = {"S0", "REJ", "RSTO", "RSTR", "SH", "SHR", "OTH"}

# Connection-level fallbacks are deliberately limited to protocols for which the
# default Zeek logs commonly do not expose authentication success/failure.
_CONN_FALLBACKS = {
    "ssh": ({22}, "SSH"),
    "rdp": ({3389}, "RDP"),
    "vnc": (set(range(5900, 5911)), "VNC"),
}


class BruteForceAuthenticationModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="brute_force_authentication",
        name="Brute Force Authentication",
        description=(
            "Identifies repeated authentication failures against SSH, RDP, HTTP, Kerberos, SMB/NTLM, "
            "and VNC that are consistent with automated password guessing or credential spraying."
        ),
        category="security_analysis",
        required_logs=(),
        required_any_logs=(),
        default_enabled=True,
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        events: list[dict[str, Any]] = []
        events.extend(_http_failures(context.http))
        events.extend(_ssh_failures(context.ssh))
        events.extend(_kerberos_failures(context.kerberos))
        events.extend(_ntlm_failures(context.ntlm))
        events.extend(_generic_auth_failures(context.rdp, "rdp", "RDP"))
        events.extend(_generic_auth_failures(context.vnc, "vnc", "VNC"))

        findings: list[Finding] = []
        grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
        for event in events:
            grouped[(event["protocol"], event["source"], event["destination"])].append(event)

        for (protocol, source, destination), items in sorted(grouped.items()):
            window = _best_window(items, MIN_PROTOCOL_FAILURES)
            if window:
                findings.append(_protocol_finding(protocol, source, destination, window))

        # Low-confidence fallback for SSH/RDP/VNC when no protocol-log finding
        # exists. It only considers repeated failed/incomplete connection attempts.
        already = {(f.metadata.get("protocol"), f.metadata.get("source"), f.metadata.get("destination")) for f in findings}
        for protocol, (ports, label) in _CONN_FALLBACKS.items():
            candidates: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
            for row in context.connections:
                port = _as_int(row.get("destination_port", row.get("id.resp_p")))
                state = _text(row.get("zeek_state", row.get("conn_state"))).upper()
                if port not in ports or state not in FAILED_CONN_STATES:
                    continue
                source = _text(row.get("source_ip", row.get("id.orig_h")))
                destination = _text(row.get("destination_ip", row.get("id.resp_h")))
                ts = _as_float(row.get("timestamp", row.get("ts")))
                if not source or not destination or ts is None:
                    continue
                candidates[(source, destination)].append(
                    {
                        "protocol": protocol,
                        "service": label,
                        "source": source,
                        "destination": destination,
                        "port": port,
                        "timestamp": ts,
                        "username": "",
                        "row": row,
                        "basis": "port",
                    }
                )
            for (source, destination), items in sorted(candidates.items()):
                if (protocol, source, destination) in already:
                    continue
                window = _best_window(items, MIN_CONNECTION_ATTEMPTS)
                if window:
                    findings.append(_connection_heuristic_finding(protocol, label, source, destination, window))

        counts = Counter(f.metadata.get("protocol", "unknown") for f in findings)
        inspected = [name for name in ("http", "ssh", "kerberos", "ntlm", "rdp", "vnc", "conn") if context.log(name)]
        skipped = [name for name in ("http", "ssh", "kerberos", "ntlm", "rdp", "vnc") if not context.log(name)]

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "brute_force_findings": len(findings),
                "protocol_log_failure_events": len(events),
                "findings_by_protocol": dict(sorted(counts.items())),
                "affected_sources": len({f.metadata.get("source") for f in findings if f.metadata.get("source")}),
                "affected_destinations": len({f.metadata.get("destination") for f in findings if f.metadata.get("destination")}),
            },
            evidence={
                "inspected_logs": inspected,
                "skipped_optional_logs": skipped,
                "thresholds": {
                    "window_seconds": WINDOW_SECONDS,
                    "minimum_protocol_failures": MIN_PROTOCOL_FAILURES,
                    "minimum_connection_fallback_attempts": MIN_CONNECTION_ATTEMPTS,
                },
                "coverage": {
                    "http": "Repeated HTTP 401/403 responses from http.log.",
                    "ssh": "Repeated explicit SSH authentication failures when ssh.log exposes auth_success/success; otherwise failed connection attempts to TCP/22 are a low-confidence fallback.",
                    "kerberos": "Repeated Kerberos error/failure records from kerberos.log.",
                    "smb": "Repeated NTLM authentication failures from ntlm.log, representing SMB/Windows authentication where available.",
                    "rdp": "Explicit failures from rdp.log when available; otherwise repeated failed connection attempts to TCP/3389 are a low-confidence fallback.",
                    "vnc": "Explicit failures from vnc.log when available; otherwise repeated failed connection attempts to TCP/5900-5910 are a low-confidence fallback.",
                },
                "notes": [
                    "Protocol-log failures are higher confidence than connection-level fallbacks.",
                    "Connection-level RDP/VNC/SSH findings indicate repeated failed connection attempts and cannot prove that an authentication exchange occurred.",
                    "Legitimate password mistakes, health checks, vulnerability scanners, and account-management systems can create similar patterns.",
                ],
            },
            warnings=[],
        )


def _http_failures(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for row in rows:
        status = _as_int(row.get("status_code"))
        if status not in {401, 403}:
            continue
        event = _event_from_row(row, "http", "HTTP", 80, "protocol_log")
        if event:
            event["username"] = _first_text(row, "username", "user")
            event["failure_reason"] = f"HTTP {status}"
            result.append(event)
    return result


def _ssh_failures(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return _boolean_failure_rows(rows, "ssh", "SSH", 22, ("auth_success", "success", "authentication_success"))


def _kerberos_failures(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for row in rows:
        failure = False
        success = _first_value(row, "success", "auth_success")
        if success is not None:
            failure = _is_false(success)
        error = _first_text(row, "error_msg", "error", "failure_reason")
        error_code = _first_value(row, "error_code", "errorCode")
        if error or (error_code not in (None, 0, "0", "")):
            failure = True
        if not failure:
            continue
        event = _event_from_row(row, "kerberos", "Kerberos", 88, "protocol_log")
        if event:
            event["username"] = _first_text(row, "client", "client_name", "username", "user")
            event["failure_reason"] = error or (f"Kerberos error {error_code}" if error_code is not None else "authentication failure")
            result.append(event)
    return result


def _ntlm_failures(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = _boolean_failure_rows(rows, "smb", "SMB/NTLM", 445, ("success", "auth_success", "authenticated"))
    for event in result:
        row = event["row"]
        event["username"] = _first_text(row, "username", "user", "user_name")
        domain = _first_text(row, "domainname", "domain")
        if domain and event["username"]:
            event["username"] = f"{domain}\\{event['username']}"
    return result


def _generic_auth_failures(rows: list[dict[str, Any]], protocol: str, label: str) -> list[dict[str, Any]]:
    return _boolean_failure_rows(rows, protocol, label, None, ("success", "auth_success", "authenticated", "login_success"))


def _boolean_failure_rows(
    rows: list[dict[str, Any]],
    protocol: str,
    label: str,
    default_port: int | None,
    fields: tuple[str, ...],
) -> list[dict[str, Any]]:
    result = []
    for row in rows:
        value = _first_value(row, *fields)
        if value is None or not _is_false(value):
            continue
        event = _event_from_row(row, protocol, label, default_port, "protocol_log")
        if event:
            event["username"] = _first_text(row, "username", "user", "client", "client_name")
            event["failure_reason"] = _first_text(row, "failure_reason", "error", "error_msg", "status") or "authentication failure"
            result.append(event)
    return result


def _event_from_row(
    row: dict[str, Any],
    protocol: str,
    service: str,
    default_port: int | None,
    basis: str,
) -> dict[str, Any] | None:
    source = _first_text(row, "source_ip", "id.orig_h", "client_ip", "src")
    destination = _first_text(row, "destination_ip", "id.resp_h", "server_ip", "dst")
    ts = _as_float(_first_value(row, "timestamp", "ts"))
    if not source or not destination or ts is None:
        return None
    return {
        "protocol": protocol,
        "service": service,
        "source": source,
        "destination": destination,
        "port": _as_int(_first_value(row, "destination_port", "id.resp_p")) or default_port,
        "timestamp": ts,
        "username": "",
        "failure_reason": "authentication failure",
        "row": row,
        "basis": basis,
    }


def _best_window(items: list[dict[str, Any]], minimum: int) -> list[dict[str, Any]] | None:
    ordered = sorted(items, key=lambda item: item["timestamp"])
    left = 0
    best: list[dict[str, Any]] | None = None
    for right, item in enumerate(ordered):
        while item["timestamp"] - ordered[left]["timestamp"] > WINDOW_SECONDS:
            left += 1
        candidate = ordered[left : right + 1]
        if len(candidate) >= minimum and (best is None or len(candidate) > len(best)):
            best = candidate
    return best


def _protocol_finding(protocol: str, source: str, destination: str, items: list[dict[str, Any]]) -> Finding:
    service = items[0]["service"]
    ports = sorted({item["port"] for item in items if isinstance(item["port"], int)})
    usernames = sorted({item["username"] for item in items if item.get("username")})
    span = items[-1]["timestamp"] - items[0]["timestamp"] if len(items) > 1 else 0.0
    distinct_users = len(usernames)
    confidence = "high"
    severity = "high" if len(items) >= 10 or distinct_users >= 5 else "medium"
    tags = ["brute-force", "authentication", protocol]
    if distinct_users >= 5:
        tags.append("password-spraying")

    return Finding(
        title=f"Repeated {service} authentication failures observed",
        severity=severity,
        summary=(
            f"Observed {len(items)} failed {service} authentication attempt(s) from {source} to {destination} "
            f"within {span:.1f} seconds. "
            + (f"The attempts referenced {distinct_users} distinct user identities, which is consistent with password spraying. " if distinct_users >= 5 else "")
            + "The pattern is consistent with automated credential guessing, but legitimate user or application failures should be ruled out."
        ),
        confidence=confidence,
        detection_basis="protocol_log",
        devices=sorted({source, destination}),
        services=[service],
        ports=ports,
        connection_pairs=[{
            "source": source,
            "destination": destination,
            "port": ports[0] if len(ports) == 1 else None,
            "protocol": "tcp" if protocol != "kerberos" else "tcp/udp",
            "service": service,
        }],
        flows=[item["row"] for item in items[:MAX_EVIDENCE_FLOWS]],
        timestamps=[item["timestamp"] for item in items[:MAX_EVIDENCE_FLOWS]],
        tags=tags,
        metadata={
            "protocol": protocol,
            "source": source,
            "destination": destination,
            "failure_count": len(items),
            "window_span_seconds": round(span, 6),
            "distinct_usernames": distinct_users,
            "usernames": usernames[:50],
            "failure_reasons": dict(sorted(Counter(item.get("failure_reason") or "unknown" for item in items).items())),
            "evidence_flow_count": min(len(items), MAX_EVIDENCE_FLOWS),
            "evidence_truncated": len(items) > MAX_EVIDENCE_FLOWS,
        },
    )


def _connection_heuristic_finding(
    protocol: str,
    service: str,
    source: str,
    destination: str,
    items: list[dict[str, Any]],
) -> Finding:
    ports = sorted({item["port"] for item in items if isinstance(item["port"], int)})
    span = items[-1]["timestamp"] - items[0]["timestamp"] if len(items) > 1 else 0.0
    states = Counter(_text(item["row"].get("zeek_state", item["row"].get("conn_state"))).upper() or "UNKNOWN" for item in items)
    return Finding(
        title=f"Possible brute-force activity against {service}",
        severity="low",
        summary=(
            f"Observed {len(items)} failed or incomplete connection attempt(s) from {source} to {destination} on {service} "
            f"within {span:.1f} seconds. Zeek did not provide application-level authentication failures, so this is a low-confidence "
            "indicator of possible automated guessing rather than proof of brute-force authentication."
        ),
        confidence="low",
        detection_basis="port",
        devices=sorted({source, destination}),
        services=[service],
        ports=ports,
        connection_pairs=[{
            "source": source,
            "destination": destination,
            "port": ports[0] if len(ports) == 1 else None,
            "protocol": "tcp",
            "service": service,
        }],
        flows=[item["row"] for item in items[:MAX_EVIDENCE_FLOWS]],
        timestamps=[item["timestamp"] for item in items[:MAX_EVIDENCE_FLOWS]],
        tags=["brute-force", "authentication", protocol, "connection-heuristic"],
        metadata={
            "protocol": protocol,
            "source": source,
            "destination": destination,
            "attempt_count": len(items),
            "window_span_seconds": round(span, 6),
            "zeek_state_counts": dict(sorted(states.items())),
            "authentication_confirmed": False,
            "evidence_flow_count": min(len(items), MAX_EVIDENCE_FLOWS),
            "evidence_truncated": len(items) > MAX_EVIDENCE_FLOWS,
        },
    )


def _first_value(row: dict[str, Any], *names: str) -> Any:
    for name in names:
        if name in row and row[name] is not None:
            return row[name]
    return None


def _first_text(row: dict[str, Any], *names: str) -> str:
    value = _first_value(row, *names)
    return _text(value)


def _is_false(value: Any) -> bool:
    if isinstance(value, bool):
        return not value
    if isinstance(value, (int, float)):
        return value == 0
    return _text(value).lower() in {"f", "false", "no", "n", "0", "failed", "failure", "denied", "reject", "rejected"}


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _as_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
