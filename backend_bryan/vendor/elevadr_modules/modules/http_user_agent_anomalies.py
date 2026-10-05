from __future__ import annotations

from collections import Counter, defaultdict
from ipaddress import ip_address, ip_network
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata

MAX_EVIDENCE_FLOWS = 10

DEFAULT_POLICY = {
    "minimum_baseline_observations": 50,
    "rare_max_count": 2,
    "rare_max_fraction": 0.02,
}

CLI_AGENT_TOKENS: tuple[tuple[str, str], ...] = (
    ("curl/", "curl"),
    ("wget/", "wget"),
    ("python-requests", "python-requests"),
    ("python-urllib", "python-urllib"),
    ("urllib3/", "urllib3"),
    ("aiohttp/", "aiohttp"),
    ("httpie/", "httpie"),
    ("powershell/", "powershell"),
    ("libwww-perl", "libwww-perl"),
    ("lwp::", "libwww-perl"),
    ("go-http-client/", "go-http-client"),
)

DEFAULT_SENSITIVE_PATH_TOKENS = (
    "/admin",
    "/administrator",
    "/login",
    "/signin",
    "/auth",
    "/oauth",
    "/token",
    "/password",
    "/passwd",
    "/config",
    "/management",
    "/manage",
)

SENSITIVE_SEGMENT_TOKENS = (
    "ot",
    "control",
    "scada",
    "safety",
    "process",
    "ics",
    "industrial",
)


class HttpUserAgentAnomaliesModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="http_user_agent_anomalies",
        name="HTTP User-Agent Anomalies",
        description=(
            "Identifies CLI/scripted HTTP clients and rare or missing User-Agent strings on "
            "sensitive HTTP flows using protocol telemetry and conservative baselines."
        ),
        category="security_analysis",
        required_logs=("http",),
        default_enabled=True,
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        policy = _policy(context.metadata)
        segments = _segments(context.metadata)
        conn_by_uid = {
            str(row.get("uid")): row
            for row in context.connections
            if row.get("uid") not in (None, "")
        }

        events: list[dict[str, Any]] = []
        for row in context.http:
            events.append(_event(row, conn_by_uid, segments, policy))

        baselines: dict[str, Counter[str]] = defaultdict(Counter)
        baseline_totals: Counter[str] = Counter()
        for event in events:
            ua = event["user_agent"]
            if not ua:
                continue
            scope = event["source_scope"]
            baselines[scope][ua] += 1
            baseline_totals[scope] += 1

        approved_suppressed = 0
        cli_events: list[dict[str, Any]] = []
        missing_sensitive_events: list[dict[str, Any]] = []
        rare_sensitive_events: list[dict[str, Any]] = []
        baseline_insufficient_sensitive = 0

        for event in events:
            ua = event["user_agent"]
            if ua and _approved_ua(ua, policy):
                approved_suppressed += 1
                continue

            cli_family = _cli_family(ua)
            if cli_family:
                event["signal"] = "cli_agent"
                event["cli_family"] = cli_family
                cli_events.append(event)
                continue

            if not event["sensitive"]:
                continue

            if not ua:
                event["signal"] = "missing_user_agent"
                missing_sensitive_events.append(event)
                continue

            scope = event["source_scope"]
            total = baseline_totals[scope]
            if total < policy["minimum_baseline_observations"]:
                baseline_insufficient_sensitive += 1
                continue
            count = baselines[scope][ua]
            fraction = count / total if total else 0.0
            if count <= policy["rare_max_count"] and fraction <= policy["rare_max_fraction"]:
                event["signal"] = "rare_user_agent"
                event["baseline_count"] = count
                event["baseline_total"] = total
                event["baseline_fraction"] = fraction
                rare_sensitive_events.append(event)

        findings: list[Finding] = []
        findings.extend(_group_cli(cli_events))
        findings.extend(_group_missing(missing_sensitive_events))
        findings.extend(_group_rare(rare_sensitive_events))

        affected = {device for finding in findings for device in finding.devices if device}
        sensitive_count = sum(1 for event in events if event["sensitive"])
        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "http_events_evaluated": len(events),
                "sensitive_http_events": sensitive_count,
                "cli_user_agent_events": len(cli_events),
                "missing_user_agent_sensitive_events": len(missing_sensitive_events),
                "rare_user_agent_sensitive_events": len(rare_sensitive_events),
                "sensitive_events_with_insufficient_baseline": baseline_insufficient_sensitive,
                "approved_user_agent_events_suppressed": approved_suppressed,
                "user_agent_findings": len(findings),
                "affected_devices": len(affected),
            },
            evidence={
                "inspected_logs": ["http"] if context.http else [],
                "notes": [
                    "CLI/scripted User-Agent strings can be legitimate automation, maintenance, monitoring, or API activity; findings are anomaly/review indicators rather than proof of malicious tooling.",
                    "Missing or rare User-Agent strings are only reported on flows considered sensitive by configured destinations/segments or sensitive request paths.",
                    "Rare User-Agent findings require an established source-scope baseline; rarity alone is not treated as malicious behavior.",
                    "Configured OT/control destination segments are treated as sensitive. The module does not infer OT membership from private IP address ranges alone.",
                    "Rendered evidence is capped at 10 representative HTTP events while full counts remain in metadata.",
                ],
                "policy": {
                    "minimum_baseline_observations": policy["minimum_baseline_observations"],
                    "rare_max_count": policy["rare_max_count"],
                    "rare_max_fraction": policy["rare_max_fraction"],
                },
            },
            warnings=[],
        )


def _event(
    row: dict[str, Any],
    conn_by_uid: dict[str, dict[str, Any]],
    segments: list[dict[str, Any]],
    policy: dict[str, Any],
) -> dict[str, Any]:
    uid = _text(row.get("uid"))
    conn = conn_by_uid.get(uid, {}) if uid else {}
    source_ip = _first_text(row, "source_ip", "id.orig_h") or _first_text(conn, "source_ip", "id.orig_h")
    destination_ip = _first_text(row, "destination_ip", "id.resp_h") or _first_text(conn, "destination_ip", "id.resp_h")
    destination_port = _first_int(row, "destination_port", "id.resp_p") or _first_int(conn, "destination_port", "id.resp_p")
    host = _first_text(row, "host", "server_name", "hostname")
    uri = _first_text(row, "uri", "path", "request_uri") or ""
    method = _first_text(row, "method")
    ua = _first_text(row, "user_agent", "user-agent", "useragent", "http_user_agent")
    destination_segment = _segment_for_ip(destination_ip, segments)
    source_segment = _segment_for_ip(source_ip, segments)
    sensitive, reasons = _is_sensitive(
        destination_ip=destination_ip,
        host=host,
        uri=uri,
        destination_segment=destination_segment,
        policy=policy,
    )
    return {
        "row": row,
        "uid": uid,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "host": host,
        "uri": uri,
        "method": method,
        "user_agent": ua,
        "timestamp": _first_value(row, "timestamp", "ts") or _first_value(conn, "timestamp", "ts"),
        "source_segment": _segment_name(source_segment),
        "destination_segment": _segment_name(destination_segment),
        "source_scope": _segment_name(source_segment) or "__all_http_clients__",
        "sensitive": sensitive,
        "sensitive_reasons": reasons,
    }


def _group_cli(events: list[dict[str, Any]]) -> list[Finding]:
    groups: dict[tuple[str, str, bool], list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        groups[(event["source_ip"] or "unknown-client", event["cli_family"], bool(event["sensitive"]))].append(event)
    return [_cli_finding(key, rows) for key, rows in sorted(groups.items())]


def _group_missing(events: list[dict[str, Any]]) -> list[Finding]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        groups[event["source_ip"] or "unknown-client"].append(event)
    return [_missing_finding(source, rows) for source, rows in sorted(groups.items())]


def _group_rare(events: list[dict[str, Any]]) -> list[Finding]:
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        groups[(event["source_ip"] or "unknown-client", event["user_agent"])].append(event)
    return [_rare_finding(key, rows) for key, rows in sorted(groups.items())]


def _cli_finding(key: tuple[str, str, bool], events: list[dict[str, Any]]) -> Finding:
    source, family, sensitive = key
    severity = "medium" if sensitive else "low"
    destinations = sorted({event["destination_ip"] for event in events if event["destination_ip"]})
    sensitive_reasons = sorted({reason for event in events for reason in event["sensitive_reasons"]})
    qualifier = " on sensitive HTTP flow(s)" if sensitive else ""
    summary = (
        f"HTTP telemetry observed {len(events)} request(s) from {source} using the CLI/scripted User-Agent family "
        f"'{family}'{qualifier}. Command-line and library HTTP clients are common in administration and automation, "
        "so this is a review indicator rather than proof of malicious tooling."
    )
    return _finding(
        title=f"CLI/scripted HTTP User-Agent: {family} from {source}",
        severity=severity,
        confidence="high",
        summary=summary,
        source=source,
        events=events,
        tags=["http", "user-agent", "cli-agent", family],
        metadata={
            "signal": "cli_agent",
            "cli_family": family,
            "sensitive_flow": sensitive,
            "sensitive_reasons": sensitive_reasons,
            "distinct_destination_count": len(destinations),
            "destinations": destinations[:50],
            "malicious_tooling_confirmed": False,
        },
    )


def _missing_finding(source: str, events: list[dict[str, Any]]) -> Finding:
    reasons = sorted({reason for event in events for reason in event["sensitive_reasons"]})
    summary = (
        f"HTTP telemetry observed {len(events)} sensitive request(s) from {source} without a User-Agent string. "
        "Missing User-Agent values can occur with custom clients, embedded devices, health checks, or automation; "
        "review the initiating host and requested resource before assigning security significance."
    )
    return _finding(
        title=f"Missing HTTP User-Agent on sensitive flow from {source}",
        severity="low",
        confidence="medium",
        summary=summary,
        source=source,
        events=events,
        tags=["http", "user-agent", "missing-user-agent", "sensitive-flow"],
        metadata={
            "signal": "missing_user_agent",
            "sensitive_flow": True,
            "sensitive_reasons": reasons,
            "malicious_tooling_confirmed": False,
        },
    )


def _rare_finding(key: tuple[str, str], events: list[dict[str, Any]]) -> Finding:
    source, ua = key
    exemplar = events[0]
    reasons = sorted({reason for event in events for reason in event["sensitive_reasons"]})
    count = exemplar.get("baseline_count", len(events))
    total = exemplar.get("baseline_total", 0)
    fraction = exemplar.get("baseline_fraction", 0.0)
    display_ua = ua if len(ua) <= 120 else ua[:117] + "..."
    summary = (
        f"HTTP telemetry observed a rare User-Agent from {source} on sensitive flow(s). The User-Agent appeared "
        f"{count} time(s) among {total} requests in the established source scope ({fraction:.2%}). Rare clients can "
        "reflect software updates, embedded applications, scanners, or administrative tools and are not inherently malicious."
    )
    return _finding(
        title=f"Rare HTTP User-Agent on sensitive flow from {source}",
        severity="low",
        confidence="medium",
        summary=summary,
        source=source,
        events=events,
        tags=["http", "user-agent", "rare-user-agent", "sensitive-flow"],
        metadata={
            "signal": "rare_user_agent",
            "user_agent": display_ua,
            "baseline_scope": exemplar["source_scope"],
            "baseline_user_agent_count": count,
            "baseline_total_observations": total,
            "baseline_fraction": fraction,
            "sensitive_reasons": reasons,
            "malicious_tooling_confirmed": False,
        },
    )


def _finding(
    *,
    title: str,
    severity: str,
    confidence: str,
    summary: str,
    source: str,
    events: list[dict[str, Any]],
    tags: list[str],
    metadata: dict[str, Any],
) -> Finding:
    representative = events[:MAX_EVIDENCE_FLOWS]
    destinations = sorted({event["destination_ip"] for event in events if event["destination_ip"]})
    ports = sorted({event["destination_port"] for event in events if event["destination_port"] is not None})
    pairs: list[dict[str, Any]] = []
    seen_pairs: set[tuple[str | None, str | None, int | None]] = set()
    for event in events:
        pair_key = (event["source_ip"], event["destination_ip"], event["destination_port"])
        if pair_key in seen_pairs or not event["destination_ip"]:
            continue
        seen_pairs.add(pair_key)
        pairs.append({
            "source": event["source_ip"],
            "destination": event["destination_ip"],
            "port": event["destination_port"],
            "protocol": "tcp",
            "service": "HTTP",
        })
        if len(pairs) >= MAX_EVIDENCE_FLOWS:
            break
    subnets = sorted({event["destination_segment"] for event in events if event["destination_segment"]})
    all_metadata = {
        **metadata,
        "event_count": len(events),
        "evidence_event_count": len(representative),
        "evidence_truncated": len(events) > len(representative),
    }
    devices = sorted({item for item in [source, *destinations] if item and item != "unknown-client"})
    return Finding(
        title=title,
        severity=severity,
        summary=summary,
        confidence=confidence,
        detection_basis="protocol_log" if metadata.get("signal") != "rare_user_agent" else "derived",
        devices=devices,
        services=["HTTP"],
        ports=ports,
        connection_pairs=pairs,
        flows=[event["row"] for event in representative],
        subnets=subnets,
        timestamps=[event["timestamp"] for event in representative if event["timestamp"] is not None],
        tags=tags,
        metadata=all_metadata,
    )


def _is_sensitive(
    *,
    destination_ip: str | None,
    host: str | None,
    uri: str,
    destination_segment: dict[str, Any] | None,
    policy: dict[str, Any],
) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    if destination_ip and destination_ip in policy["sensitive_destination_ips"]:
        reasons.append("configured_sensitive_destination_ip")
    if destination_ip and _in_networks(destination_ip, policy["sensitive_destination_cidrs"]):
        reasons.append("configured_sensitive_destination_cidr")
    if host and _host_matches(host, policy["sensitive_hosts"]):
        reasons.append("configured_sensitive_host")
    if destination_segment and _segment_sensitive(destination_segment):
        reasons.append("ot_or_control_destination_segment")
    uri_lower = uri.lower()
    if any(token in uri_lower for token in policy["sensitive_path_keywords"]):
        reasons.append("sensitive_request_path")
    return bool(reasons), reasons


def _segment_sensitive(segment: dict[str, Any]) -> bool:
    level = _first_text(segment, "purdue_level", "purdue", "level", "purdueLevel")
    if level:
        compact = level.lower().replace("level", "l").replace(" ", "")
        if compact in {"l0", "l1", "l2", "l3", "0", "1", "2", "3"}:
            return True
    text = " ".join(
        str(segment.get(key) or "")
        for key in ("name", "role", "type", "zone", "trust_zone", "segment_type")
    ).lower()
    return any(token in text for token in SENSITIVE_SEGMENT_TOKENS)


def _segments(metadata: dict[str, Any]) -> list[dict[str, Any]]:
    value = metadata.get("segments")
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _segment_for_ip(value: str | None, segments: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not value:
        return None
    try:
        addr = ip_address(value)
    except ValueError:
        return None
    matches: list[tuple[int, dict[str, Any]]] = []
    for segment in segments:
        cidr = _first_text(segment, "cidr", "subnet", "network", "prefix")
        if not cidr:
            continue
        try:
            network = ip_network(cidr, strict=False)
        except ValueError:
            continue
        if addr in network:
            matches.append((network.prefixlen, segment))
    return max(matches, key=lambda item: item[0])[1] if matches else None


def _segment_name(segment: dict[str, Any] | None) -> str | None:
    if not segment:
        return None
    return _first_text(segment, "name", "id", "label", "cidr", "subnet")


def _policy(metadata: dict[str, Any]) -> dict[str, Any]:
    raw = metadata.get("http_user_agent_policy")
    raw = raw if isinstance(raw, dict) else {}
    return {
        "minimum_baseline_observations": _positive_int(raw.get("minimum_baseline_observations"), DEFAULT_POLICY["minimum_baseline_observations"]),
        "rare_max_count": _positive_int(raw.get("rare_max_count"), DEFAULT_POLICY["rare_max_count"]),
        "rare_max_fraction": _fraction(raw.get("rare_max_fraction"), DEFAULT_POLICY["rare_max_fraction"]),
        "approved_user_agent_substrings": _string_list(raw.get("approved_user_agent_substrings") or raw.get("allowed_user_agent_substrings")),
        "sensitive_destination_ips": set(_string_list(raw.get("sensitive_destination_ips"))),
        "sensitive_destination_cidrs": _string_list(raw.get("sensitive_destination_cidrs")),
        "sensitive_hosts": _string_list(raw.get("sensitive_hosts") or raw.get("sensitive_domains")),
        "sensitive_path_keywords": tuple(_string_list(raw.get("sensitive_path_keywords")) or DEFAULT_SENSITIVE_PATH_TOKENS),
    }


def _approved_ua(ua: str, policy: dict[str, Any]) -> bool:
    lower = ua.lower()
    return any(token.lower() in lower for token in policy["approved_user_agent_substrings"])


def _cli_family(ua: str | None) -> str | None:
    if not ua:
        return None
    lower = ua.lower()
    for token, label in CLI_AGENT_TOKENS:
        if token in lower:
            return label
    return None


def _host_matches(host: str, patterns: list[str]) -> bool:
    host = host.lower().rstrip(".")
    for pattern in patterns:
        candidate = pattern.lower().rstrip(".")
        if host == candidate or host.endswith("." + candidate):
            return True
    return False


def _in_networks(value: str, networks: list[str]) -> bool:
    try:
        addr = ip_address(value)
    except ValueError:
        return False
    for cidr in networks:
        try:
            if addr in ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, (list, tuple, set)):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _positive_int(value: Any, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def _fraction(value: Any, default: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default
    return parsed if 0.0 < parsed <= 1.0 else default


def _first_text(row: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = _text(row.get(key))
        if value:
            return value
    return None


def _first_int(row: dict[str, Any], *keys: str) -> int | None:
    for key in keys:
        value = row.get(key)
        if value in (None, ""):
            continue
        try:
            return int(value)
        except (TypeError, ValueError):
            continue
    return None


def _first_value(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = row.get(key)
        if value not in (None, ""):
            return value
    return None


def _text(value: Any) -> str | None:
    if value in (None, ""):
        return None
    text = str(value).strip()
    return text if text else None
