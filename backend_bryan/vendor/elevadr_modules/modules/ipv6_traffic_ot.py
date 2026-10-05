from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import ipaddress
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata


MAX_EVIDENCE_FLOWS = 10


@dataclass(slots=True)
class _Event:
    row: dict[str, Any]
    source: str
    destination: str
    source_scope: str
    destination_scope: str
    matched_by: str


class Ipv6TrafficOtModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="ipv6_traffic_ot",
        name="IPv6 Traffic in OT Environment",
        description=(
            "Identifies IPv6 communications observed in an OT/ICS environment that is explicitly documented "
            "as IPv4-only, including link-local, deprecated site-local, unique-local, multicast, and global IPv6."
        ),
        category="security_analysis",
        required_logs=("conn",),
        default_enabled=True,
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        policy = _policy(context.metadata)
        ipv4_only = bool(policy.get("ipv4_only_expected", False))
        scope_all = bool(policy.get("scope_all_connections", False))
        allowed = _networks(policy.get("allowed_ipv6", []), version=6)
        ot_prefixes = _networks(policy.get("ot_ipv6_prefixes", []), version=6)
        ot_hosts = {_text(v) for v in policy.get("ot_ipv6_hosts", []) if _text(v)}

        # Segment-level explicit IPv4-only declarations may also establish policy,
        # but only when an IPv6 prefix/host is supplied for attribution.
        segment_prefixes, segment_hosts, segment_policy_present = _segment_ipv6_scope(context.metadata)
        ot_prefixes.extend(segment_prefixes)
        ot_hosts.update(segment_hosts)
        ipv4_only = ipv4_only or segment_policy_present

        events: list[_Event] = []
        ipv6_rows = 0
        skipped_not_ot_scope = 0
        skipped_allowlisted = 0

        for row in context.connections:
            source = _text(row.get("source_ip", row.get("id.orig_h")))
            destination = _text(row.get("destination_ip", row.get("id.resp_h")))
            src_ip = _ip(source)
            dst_ip = _ip(destination)
            if not ((src_ip and src_ip.version == 6) or (dst_ip and dst_ip.version == 6)):
                continue
            ipv6_rows += 1

            ipv6_addresses = [addr for addr in (src_ip, dst_ip) if addr and addr.version == 6]
            if any(_in_networks(addr, allowed) for addr in ipv6_addresses):
                skipped_allowlisted += 1
                continue

            matched_by = "sensor_scope" if scope_all else ""
            if not scope_all:
                scoped = False
                for addr in ipv6_addresses:
                    if str(addr) in ot_hosts or _in_networks(addr, ot_prefixes):
                        scoped = True
                        matched_by = "configured_ipv6_scope"
                        break
                if not scoped:
                    skipped_not_ot_scope += 1
                    continue

            events.append(
                _Event(
                    row=row,
                    source=source,
                    destination=destination,
                    source_scope=_scope(src_ip) if src_ip and src_ip.version == 6 else "ipv4",
                    destination_scope=_scope(dst_ip) if dst_ip and dst_ip.version == 6 else "ipv4",
                    matched_by=matched_by,
                )
            )

        if not ipv4_only:
            return ModuleResult(
                module_id=self.metadata.id,
                findings=[],
                metrics={
                    "ipv6_connections_observed": ipv6_rows,
                    "ipv6_policy_violation_events": 0,
                    "ipv6_findings": 0,
                    "skipped_no_ipv4_only_policy": ipv6_rows,
                    "skipped_not_ot_scope": 0,
                    "skipped_allowlisted": 0,
                },
                evidence={
                    "inspected_logs": ["conn"],
                    "policy": policy,
                    "notes": [
                        "IPv6 presence is not anomalous by itself. A finding requires explicit metadata documenting the monitored OT scope as IPv4-only.",
                        "Set ipv6_ot_policy.ipv4_only_expected=true and either scope_all_connections=true for a dedicated OT sensor, or configure ot_ipv6_hosts/ot_ipv6_prefixes for endpoint attribution.",
                    ],
                },
                warnings=["IPv4-only expectation is not explicitly configured; IPv6 observations were not treated as policy violations."],
            )

        groups: dict[tuple[str, str], list[_Event]] = defaultdict(list)
        for event in events:
            groups[(event.source, event.destination)].append(event)

        findings = [_finding(rows) for _, rows in sorted(groups.items())]
        scopes = sorted({scope for event in events for scope in (event.source_scope, event.destination_scope) if scope != "ipv4"})

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "ipv6_connections_observed": ipv6_rows,
                "ipv6_policy_violation_events": len(events),
                "ipv6_findings": len(findings),
                "ipv6_scopes_observed": scopes,
                "skipped_no_ipv4_only_policy": 0,
                "skipped_not_ot_scope": skipped_not_ot_scope,
                "skipped_allowlisted": skipped_allowlisted,
            },
            evidence={
                "inspected_logs": ["conn"],
                "policy": policy,
                "notes": [
                    "Findings require an explicit IPv4-only OT expectation; IPv6 is not assumed to be prohibited merely because configured segments use IPv4 CIDRs.",
                    "IPv6 scope labels are derived from the observed addresses: link-local, deprecated site-local, unique-local, multicast, global, loopback, or other reserved/special-use.",
                    "Link-local IPv6 can appear automatically when IPv6 is enabled on an interface, so its presence may indicate configuration drift rather than intentional routed IPv6 use.",
                    "This module reports unexpected IPv6 presence and does not by itself prove malicious activity.",
                ],
            },
            warnings=[],
        )


def _finding(events: list[_Event]) -> Finding:
    first = events[0]
    representative = events[:MAX_EVIDENCE_FLOWS]
    scopes = sorted({scope for event in events for scope in (event.source_scope, event.destination_scope) if scope != "ipv4"})
    global_seen = "global" in scopes
    multicast_seen = "multicast" in scopes
    severity = "medium" if global_seen else "low"
    if multicast_seen and len(events) >= 10:
        severity = "medium"

    return Finding(
        title=f"Unexpected IPv6 traffic in IPv4-only OT: {first.source} -> {first.destination}",
        severity=severity,
        summary=(
            f"Observed {len(events)} IPv6 connection record(s) from {first.source} to {first.destination} within an OT scope "
            f"explicitly documented as IPv4-only. Observed IPv6 scope(s): {', '.join(scopes) or 'unknown'}. "
            "Verify host interface configuration, dual-stack enablement, neighboring/discovery behavior, and OT network policy. "
            "The presence of IPv6 is a configuration/policy drift signal and is not proof of malicious activity."
        ),
        confidence="high",
        detection_basis="derived",
        devices=sorted({v for event in events for v in (event.source, event.destination) if v}),
        services=sorted({_text(event.row.get("service")) for event in events if _text(event.row.get("service"))}),
        ports=sorted({p for event in events for p in (_as_int(event.row.get("source_port", event.row.get("id.orig_p"))), _as_int(event.row.get("destination_port", event.row.get("id.resp_p")))) if p is not None}),
        connection_pairs=[{"source": first.source, "destination": first.destination}],
        flows=[_flow(event) for event in representative],
        timestamps=[ts for event in representative if (ts := event.row.get("timestamp", event.row.get("ts"))) not in (None, "")],
        tags=["ot", "ipv6", "baseline-drift", "network-policy"],
        metadata={
            "finding_type": "unexpected_ipv6_in_ipv4_only_ot",
            "ipv6_scopes": scopes,
            "event_count": len(events),
            "scope_match": first.matched_by,
            "evidence_capped": len(events) > MAX_EVIDENCE_FLOWS,
        },
    )


def _flow(event: _Event) -> dict[str, Any]:
    row = event.row
    return {
        "uid": row.get("uid"),
        "timestamp": row.get("timestamp", row.get("ts")),
        "source": event.source,
        "destination": event.destination,
        "source_port": _as_int(row.get("source_port", row.get("id.orig_p"))),
        "destination_port": _as_int(row.get("destination_port", row.get("id.resp_p"))),
        "protocol": _text(row.get("protocol", row.get("proto"))),
        "service": _text(row.get("service")),
        "source_ipv6_scope": event.source_scope,
        "destination_ipv6_scope": event.destination_scope,
    }


def _policy(metadata: dict[str, Any]) -> dict[str, Any]:
    raw = metadata.get("ipv6_ot_policy", {}) if isinstance(metadata, dict) else {}
    return raw if isinstance(raw, dict) else {}


def _segment_ipv6_scope(metadata: dict[str, Any]) -> tuple[list[ipaddress._BaseNetwork], set[str], bool]:
    prefixes: list[ipaddress._BaseNetwork] = []
    hosts: set[str] = set()
    policy_present = False
    raw = metadata.get("segments", []) if isinstance(metadata, dict) else []
    if not isinstance(raw, list):
        return prefixes, hosts, policy_present
    for segment in raw:
        if not isinstance(segment, dict) or not bool(segment.get("ipv4_only", False)):
            continue
        role = _text(segment.get("role")).lower()
        if role and role not in {"ot", "ics", "control", "scada", "industrial", "process", "operations"}:
            continue
        values: list[Any] = []
        for key in ("ipv6_cidr", "ipv6_prefix"):
            if segment.get(key):
                values.append(segment.get(key))
        for key in ("ipv6_cidrs", "ipv6_prefixes"):
            value = segment.get(key)
            if isinstance(value, list):
                values.extend(value)
        scoped = _networks(values, version=6)
        host_values = segment.get("ipv6_hosts", [])
        scoped_hosts = {_text(v) for v in host_values if _text(v)} if isinstance(host_values, list) else set()
        if scoped or scoped_hosts:
            prefixes.extend(scoped)
            hosts.update(scoped_hosts)
            policy_present = True
    return prefixes, hosts, policy_present


def _networks(values: Any, *, version: int) -> list[ipaddress._BaseNetwork]:
    if not isinstance(values, list):
        return []
    result: list[ipaddress._BaseNetwork] = []
    for value in values:
        try:
            network = ipaddress.ip_network(str(value).strip(), strict=False)
        except (ValueError, TypeError):
            continue
        if network.version == version:
            result.append(network)
    return result


def _ip(value: str) -> ipaddress._BaseAddress | None:
    try:
        return ipaddress.ip_address(value)
    except (ValueError, TypeError):
        return None


def _in_networks(address: ipaddress._BaseAddress, networks: list[ipaddress._BaseNetwork]) -> bool:
    return any(address.version == network.version and address in network for network in networks)


def _scope(address: ipaddress._BaseAddress) -> str:
    if address.version != 6:
        return "ipv4"
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link-local"
    # RFC 3879 deprecated FEC0::/10 site-local space; ipaddress does not expose a direct property.
    if address in ipaddress.ip_network("fec0::/10"):
        return "site-local-deprecated"
    if address in ipaddress.ip_network("fc00::/7"):
        return "unique-local"
    if address.is_multicast:
        return "multicast"
    if address.is_global:
        return "global"
    return "reserved-or-special"


def _text(value: Any) -> str:
    return "" if value in (None, "-") else str(value).strip()


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
