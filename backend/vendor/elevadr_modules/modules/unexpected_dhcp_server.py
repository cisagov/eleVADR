from __future__ import annotations

import ipaddress
import re
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata

SERVER_TYPES = {"offer", "ack", "nak"}
TYPE_MAP = {2: "offer", 5: "ack", 6: "nak"}
MAX_EVIDENCE = 10


class UnexpectedDhcpServerModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="unexpected_dhcp_server",
        name="Unexpected DHCP Server",
        description="Detects DHCP server responses from sources outside the explicitly configured trusted DHCP infrastructure.",
        category="security_analysis",
        required_logs=("dhcp",),
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        policy = _policy(context.metadata)
        expected = [str(x) for x in policy.get("expected_servers", []) if str(x).strip()]
        events = [_event(row) for row in context.dhcp]
        events = [event for event in events if event is not None]
        unexpected = [event for event in events if expected and not _matches_any(event["server_ip"], expected)]

        findings: list[Finding] = []
        by_server: dict[str, list[dict[str, Any]]] = {}
        for event in unexpected:
            by_server.setdefault(event["server_ip"], []).append(event)
        for server in sorted(by_server):
            rows = by_server[server]
            findings.append(Finding(
                title="Unexpected DHCP server response observed",
                severity="high",
                summary=f"DHCP server activity from {server} is outside the configured trusted DHCP infrastructure.",
                confidence="high",
                detection_basis="protocol_log",
                devices=[server],
                services=["dhcp"],
                ports=[67, 68],
                flows=[_evidence(row) for row in rows[:MAX_EVIDENCE]],
                timestamps=[row["timestamp"] for row in rows if row["timestamp"] is not None][:MAX_EVIDENCE],
                tags=["dhcp", "rogue-infrastructure", "identity"],
                metadata={
                    "expected_servers": expected,
                    "server_event_count": len(rows),
                    "message_types": sorted({kind for row in rows for kind in row["message_types"]}),
                },
            ))

        warnings = [] if expected else ["No trusted DHCP servers are configured; server activity is observed but not labeled unexpected."]
        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "dhcp_records_evaluated": len(context.dhcp),
                "server_events_classified": len(events),
                "unexpected_server_events": len(unexpected),
                "unexpected_servers": len(by_server),
            },
            evidence={
                "inspected_logs": ["dhcp"],
                "configured_expected_servers": expected,
                "notes": [
                    "Only explicit DHCP protocol-log server responses are evaluated.",
                    "Trusted server identity comes from Detection Context infrastructure or an explicit module override; observed DHCP never self-authorizes.",
                ],
            },
            warnings=warnings,
        )


def _event(row: dict[str, Any]) -> dict[str, Any] | None:
    message_types = _message_types(row)
    if not message_types & SERVER_TYPES:
        return None
    server_ip = _normalize_ip(_first(row, "server_addr", "server_ip", "dhcp_server", "server_identifier", "siaddr", "source_ip", "id.orig_h", "src"))
    if not server_ip:
        return None
    return {
        "server_ip": server_ip,
        "client_ip": _normalize_ip(_first(row, "client_addr", "client_ip", "requested_addr", "assigned_addr", "id.resp_h")),
        "client_mac": str(_first(row, "client_mac", "chaddr", "client_hardware_addr") or ""),
        "message_types": message_types & SERVER_TYPES,
        "timestamp": _as_float(_first(row, "timestamp", "ts")),
    }


def _message_types(row: dict[str, Any]) -> set[str]:
    raw: list[Any] = []
    for key in ("msg_types", "message_types", "message_type", "msg_type", "server_message", "dhcp_message_type", "type"):
        value = row.get(key)
        if value not in (None, ""):
            raw.extend(value if isinstance(value, (list, tuple, set)) else [value])
    result: set[str] = set()
    for value in raw:
        if isinstance(value, int) and value in TYPE_MAP:
            result.add(TYPE_MAP[value])
            continue
        text = str(value).lower()
        for token in re.split(r"[,;|\s]+", text):
            cleaned = token.strip("[](){}'\"").replace("dhcp", "").strip("_- ")
            if cleaned.isdigit() and int(cleaned) in TYPE_MAP:
                result.add(TYPE_MAP[int(cleaned)])
            elif cleaned in SERVER_TYPES:
                result.add(cleaned)
        for name in SERVER_TYPES:
            if re.search(rf"\b{name}\b", text):
                result.add(name)
    return result


def _matches_any(ip: str, rules: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for rule in rules:
        try:
            if "/" in rule and addr in ipaddress.ip_network(rule, strict=False):
                return True
            if addr == ipaddress.ip_address(rule):
                return True
        except ValueError:
            continue
    return False


def _evidence(row: dict[str, Any]) -> dict[str, Any]:
    return {k: row[k] for k in ("timestamp", "server_ip", "client_ip", "client_mac", "message_types")}


def _policy(metadata: dict[str, Any]) -> dict[str, Any]:
    value = metadata.get("unexpected_dhcp_server_policy")
    return dict(value) if isinstance(value, dict) else {}


def _normalize_ip(value: Any) -> str | None:
    if value in (None, ""):
        return None
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def _first(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if row.get(key) not in (None, ""):
            return row[key]
    return None


def _as_float(value: Any) -> float | None:
    try:
        return float(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None
