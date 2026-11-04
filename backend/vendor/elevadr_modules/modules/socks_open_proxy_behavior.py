from __future__ import annotations

from collections import defaultdict
from ipaddress import ip_address
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata

MAX_EVIDENCE_FLOWS = 10

SUCCESS_STATUS_TOKENS = {
    "ok", "success", "succeeded", "granted", "request granted", "connected",
    "established", "accepted", "0", "00",
}
FAILURE_STATUS_TOKENS = {
    "failed", "failure", "denied", "rejected", "refused", "error",
    "not allowed", "connection refused", "network unreachable", "host unreachable",
}
EXPECTED_PROXY_KEYS = ("expected_proxy_ips", "approved_proxy_ips", "known_proxy_ips")


class SocksOpenProxyBehaviorModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="socks_open_proxy_behavior",
        name="SOCKS / Open Proxy Behavior",
        description=(
            "Identifies hosts acting as SOCKS or HTTP CONNECT proxy endpoints using explicit "
            "protocol telemetry, without inferring proxy behavior from common ports alone."
        ),
        category="security_analysis",
        required_logs=(),
        required_any_logs=("socks", "http"),
        default_enabled=True,
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        policy = _policy(context.metadata)
        expected = _expected_proxy_ips(policy)
        conn_by_uid = {
            str(row.get("uid")): row
            for row in context.connections
            if row.get("uid") not in (None, "")
        }

        events: list[dict[str, Any]] = []
        ambiguous_http_connect = 0
        non_proxy_http = 0

        for row in context.socks:
            event = _socks_event(row, conn_by_uid)
            if event["proxy_ip"]:
                events.append(event)

        for row in context.http:
            method = _norm(row.get("method"))
            if method != "connect":
                non_proxy_http += 1
                continue
            event = _http_connect_event(row, conn_by_uid)
            if not event["proxy_ip"]:
                ambiguous_http_connect += 1
                continue
            if event["proxy_response"] is None:
                ambiguous_http_connect += 1
                continue
            events.append(event)

        groups: dict[tuple[str, int | None, str], list[dict[str, Any]]] = defaultdict(list)
        expected_events = 0
        for event in events:
            if event["proxy_ip"] in expected:
                expected_events += 1
                continue
            groups[(event["proxy_ip"], event["proxy_port"], event["proxy_type"])].append(event)

        findings = [_finding(key, rows) for key, rows in sorted(groups.items())]
        affected = {device for finding in findings for device in finding.devices if device}

        inspected = []
        if context.socks:
            inspected.append("socks")
        if context.http:
            inspected.append("http")

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "socks_events_evaluated": len(context.socks),
                "http_events_evaluated": len(context.http),
                "proxy_behavior_events": len(events),
                "successful_proxy_events": sum(1 for event in events if event["proxy_response"] is True),
                "failed_or_denied_proxy_events": sum(1 for event in events if event["proxy_response"] is False),
                "ambiguous_http_connect_events": ambiguous_http_connect,
                "expected_proxy_events_suppressed": expected_events,
                "proxy_endpoint_findings": len(findings),
                "affected_devices": len(affected),
            },
            evidence={
                "inspected_logs": inspected,
                "notes": _notes(),
                "policy": {"expected_proxy_ips": sorted(expected)},
            },
            warnings=[],
        )


def _socks_event(row: dict[str, Any], conn_by_uid: dict[str, dict[str, Any]]) -> dict[str, Any]:
    conn = _conn(row, conn_by_uid)
    proxy_ip = _first_text(row, "destination_ip", "id.resp_h") or _first_text(conn, "destination_ip", "id.resp_h")
    proxy_port = _first_int(row, "destination_port", "id.resp_p") or _first_int(conn, "destination_port", "id.resp_p")
    client_ip = _first_text(row, "source_ip", "id.orig_h") or _first_text(conn, "source_ip", "id.orig_h")
    request_host = _request_host(row.get("request")) or _first_text(
        row, "request_host", "request_name", "target_host", "target", "host"
    )
    request_port = _first_int(row, "request_p", "request_port", "target_port")
    status = _first_text(row, "status", "result", "response_status")
    response = _status_bool(status)
    # A parsed SOCKS record with a request is direct protocol evidence of a SOCKS
    # endpoint even when Zeek did not log a terminal server status.
    explicit_request = bool(request_host or request_port)
    if response is None and explicit_request:
        response = True
    return {
        "proxy_type": "socks",
        "proxy_ip": proxy_ip,
        "proxy_port": proxy_port,
        "client_ip": client_ip,
        "target_host": request_host,
        "target_port": request_port,
        "proxy_response": response,
        "status": status,
        "version": row.get("version"),
        "username_present": bool(_first_text(row, "user", "username")),
        "timestamp": _first_value(row, "timestamp", "ts") or _first_value(conn, "timestamp", "ts"),
        "row": row,
    }


def _http_connect_event(row: dict[str, Any], conn_by_uid: dict[str, dict[str, Any]]) -> dict[str, Any]:
    conn = _conn(row, conn_by_uid)
    proxy_ip = _first_text(row, "destination_ip", "id.resp_h") or _first_text(conn, "destination_ip", "id.resp_h")
    proxy_port = _first_int(row, "destination_port", "id.resp_p") or _first_int(conn, "destination_port", "id.resp_p")
    client_ip = _first_text(row, "source_ip", "id.orig_h") or _first_text(conn, "source_ip", "id.orig_h")
    target_host, target_port = _connect_target(row)
    status_code = _first_int(row, "status_code", "response_code", "code")
    response: bool | None
    if status_code is None:
        response = None
    elif 200 <= status_code < 300:
        response = True
    elif status_code == 407:
        # 407 is explicit evidence that the endpoint is an HTTP proxy, although
        # this particular request was not relayed without authentication.
        response = False
    else:
        # Other HTTP errors do not establish that the server is a proxy.
        response = None
    return {
        "proxy_type": "http_connect",
        "proxy_ip": proxy_ip,
        "proxy_port": proxy_port,
        "client_ip": client_ip,
        "target_host": target_host,
        "target_port": target_port,
        "proxy_response": response,
        "status": status_code,
        "version": None,
        "username_present": bool(_first_text(row, "username", "proxy_user")),
        "timestamp": _first_value(row, "timestamp", "ts") or _first_value(conn, "timestamp", "ts"),
        "row": row,
    }


def _finding(key: tuple[str, int | None, str], events: list[dict[str, Any]]) -> Finding:
    proxy_ip, proxy_port, proxy_type = key
    successful = [event for event in events if event["proxy_response"] is True]
    denied = [event for event in events if event["proxy_response"] is False]
    clients = sorted({event["client_ip"] for event in events if event["client_ip"]})
    targets = sorted({event["target_host"] for event in events if event["target_host"]})
    target_ports = sorted({event["target_port"] for event in events if event["target_port"] is not None})
    external_targets = sorted({target for target in targets if _is_global_ip(target)})

    if proxy_type == "socks":
        service = "SOCKS proxy"
        label = "SOCKS proxy behavior"
    else:
        service = "HTTP proxy"
        label = "HTTP CONNECT proxy behavior"

    # Explicit successful relaying is medium. Authentication-required responses
    # still identify a proxy endpoint, but are lower severity because they do not
    # demonstrate an open/unauthenticated relay.
    if successful:
        severity = "medium"
        confidence = "high"
        disposition = "proxy_relay_observed"
        summary = (
            f"{proxy_ip}{':' + str(proxy_port) if proxy_port else ''} responded as a {service} endpoint "
            f"for {len(events)} observed request(s), including {len(successful)} request(s) with successful or "
            "accepted proxy behavior. This confirms proxy functionality but does not by itself prove the endpoint "
            "is intentionally exposed, unauthorized, or open to arbitrary Internet clients."
        )
    else:
        severity = "low"
        confidence = "high"
        disposition = "proxy_endpoint_auth_or_denial_observed"
        summary = (
            f"{proxy_ip}{':' + str(proxy_port) if proxy_port else ''} responded with proxy-specific behavior for "
            f"{len(events)} request(s), but no successful relay was confirmed. Authentication requirements or denied "
            "requests can still identify a proxy endpoint without demonstrating an open relay."
        )

    representative = events[:MAX_EVIDENCE_FLOWS]
    devices = sorted(set(clients + [proxy_ip] + external_targets))
    ports = sorted({port for port in ([proxy_port] + target_ports) if port is not None})
    pairs = []
    seen_pairs = set()
    for event in events:
        pair = (event["client_ip"], proxy_ip, proxy_port)
        if pair in seen_pairs or not event["client_ip"]:
            continue
        seen_pairs.add(pair)
        pairs.append({
            "source": event["client_ip"],
            "destination": proxy_ip,
            "port": proxy_port,
            "protocol": "tcp",
            "service": service,
        })
        if len(pairs) >= MAX_EVIDENCE_FLOWS:
            break

    return Finding(
        title=f"{label}: {proxy_ip}{':' + str(proxy_port) if proxy_port else ''}",
        severity=severity,
        summary=summary,
        confidence=confidence,
        detection_basis="protocol_log",
        devices=devices,
        services=[service],
        ports=ports,
        connection_pairs=pairs,
        flows=[event["row"] for event in representative],
        subnets=[],
        timestamps=[event["timestamp"] for event in representative if event["timestamp"] is not None],
        tags=["proxy", "socks" if proxy_type == "socks" else "http-connect", "open-proxy-review"],
        metadata={
            "proxy_ip": proxy_ip,
            "proxy_port": proxy_port,
            "proxy_type": proxy_type,
            "event_count": len(events),
            "successful_proxy_event_count": len(successful),
            "denied_or_auth_required_event_count": len(denied),
            "distinct_client_count": len(clients),
            "distinct_target_count": len(targets),
            "clients": clients[:50],
            "targets": targets[:50],
            "target_ports": target_ports[:50],
            "external_targets": external_targets[:50],
            "open_proxy_confirmed": False,
            "proxy_functionality_observed": bool(successful),
            "disposition": disposition,
            "evidence_event_count": len(representative),
            "evidence_truncated": len(events) > len(representative),
        },
    )


def _connect_target(row: dict[str, Any]) -> tuple[str | None, int | None]:
    value = _first_text(row, "host", "uri", "target", "request_target")
    if not value:
        return None, None
    token = value.strip()
    if token.startswith("http://") or token.startswith("https://"):
        token = token.split("://", 1)[1].split("/", 1)[0]
    if token.startswith("[") and "]:" in token:
        host, _, port = token[1:].partition("]:")
        try:
            return host, int(port)
        except ValueError:
            return host, None
    if token.count(":") == 1:
        host, port = token.rsplit(":", 1)
        try:
            return host, int(port)
        except ValueError:
            return token, None
    return token, None


def _request_host(value: Any) -> str | None:
    if value in (None, ""):
        return None
    if isinstance(value, dict):
        for key in ("host", "name", "addr", "address"):
            if value.get(key) not in (None, ""):
                return str(value[key])
        return None
    return str(value)


def _status_bool(value: Any) -> bool | None:
    token = _norm(value)
    if not token:
        return None
    if token in SUCCESS_STATUS_TOKENS or any(part in token for part in ("granted", "success", "connected", "established")):
        return True
    if token in FAILURE_STATUS_TOKENS or any(part in token for part in ("denied", "refused", "reject", "fail", "unreachable")):
        return False
    return None


def _conn(row: dict[str, Any], conn_by_uid: dict[str, dict[str, Any]]) -> dict[str, Any]:
    uid = row.get("uid")
    if uid in (None, ""):
        return {}
    return conn_by_uid.get(str(uid), {})


def _policy(metadata: dict[str, Any]) -> dict[str, Any]:
    value = metadata.get("proxy_behavior_policy")
    return value if isinstance(value, dict) else {}


def _expected_proxy_ips(policy: dict[str, Any]) -> set[str]:
    for key in EXPECTED_PROXY_KEYS:
        value = policy.get(key)
        if isinstance(value, list):
            return {str(item).strip() for item in value if str(item).strip()}
    return set()


def _is_global_ip(value: str) -> bool:
    try:
        return ip_address(value).is_global
    except ValueError:
        return False


def _first_text(row: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = row.get(key)
        if value not in (None, "", "-"):
            return str(value)
    return None


def _first_int(row: dict[str, Any], *keys: str) -> int | None:
    for key in keys:
        value = row.get(key)
        if value in (None, "", "-"):
            continue
        try:
            return int(value)
        except (TypeError, ValueError):
            continue
    return None


def _first_value(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = row.get(key)
        if value not in (None, "", "-"):
            return value
    return None


def _norm(value: Any) -> str:
    if value in (None, ""):
        return ""
    return str(value).strip().lower().replace("_", " ")


def _notes() -> list[str]:
    return [
        "SOCKS findings require socks.log protocol evidence; common ports such as TCP/1080 alone are never treated as proof of a SOCKS proxy.",
        "HTTP proxy findings require the CONNECT method plus a proxy-specific response: a 2xx response confirms successful tunneling, while HTTP 407 identifies an authentication-requiring proxy endpoint.",
        "The detector intentionally does not label an endpoint an 'open proxy' from passive telemetry alone; open_proxy_confirmed remains false unless a future data source explicitly establishes unrestricted access.",
        "Authorized enterprise proxies can produce identical protocol behavior. Configure proxy_behavior_policy.expected_proxy_ips to suppress approved proxy endpoints when desired.",
        "Rendered evidence is capped at 10 representative requests while full event, client, and target counts remain in finding metadata.",
    ]
