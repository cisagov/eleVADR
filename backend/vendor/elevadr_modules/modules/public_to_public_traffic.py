from __future__ import annotations

from collections import defaultdict
import ipaddress
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata


MAX_EVIDENCE_FLOWS = 20


class PublicToPublicTrafficModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="public_to_public_traffic",
        name="Public-to-Public Traffic in Capture",
        description=(
            "Identifies traffic between two globally routable IP addresses when the monitored capture "
            "is explicitly expected to contain only internal ICS/OT communications."
        ),
        category="security_analysis",
        required_logs=("conn",),
        default_enabled=True,
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        policy = _policy(context.metadata)
        internal_only = _bool(policy.get("internal_ics_only_expected"), False)
        allowed_networks = _networks(policy.get("allowed_public_networks", []))
        allowed_hosts = {_ip(v) for v in _values(policy.get("allowed_public_hosts", []))}
        allowed_hosts.discard(None)
        allowed_pairs = _pair_set(policy.get("allowed_pairs", []))
        min_flows = max(1, _as_int(policy.get("min_flows")) or 1)

        public_rows = 0
        skipped_allowlisted = 0
        groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)

        for row in context.connections:
            source = _ip(_first(row, "source_ip", "id.orig_h"))
            destination = _ip(_first(row, "destination_ip", "id.resp_h"))
            if not source or not destination:
                continue
            if not (_is_public(source) and _is_public(destination)):
                continue
            public_rows += 1

            if source in allowed_hosts or destination in allowed_hosts:
                skipped_allowlisted += 1
                continue
            if _ip_in_networks(source, allowed_networks) or _ip_in_networks(destination, allowed_networks):
                skipped_allowlisted += 1
                continue
            if (source, destination) in allowed_pairs or (destination, source) in allowed_pairs:
                skipped_allowlisted += 1
                continue

            groups[(source, destination)].append(row)

        if not internal_only:
            return ModuleResult(
                module_id=self.metadata.id,
                findings=[],
                metrics={
                    "public_to_public_connections_observed": public_rows,
                    "public_to_public_policy_violations": 0,
                    "public_to_public_findings": 0,
                    "skipped_no_internal_only_policy": public_rows,
                    "skipped_allowlisted": 0,
                },
                evidence={
                    "inspected_logs": ["conn"] if context.connections else [],
                    "policy": policy,
                    "notes": [
                        "Public-to-public traffic is not anomalous on every sensor. Findings require an explicit expectation that this capture contains only internal ICS/OT communications.",
                        "Set public_to_public_policy.internal_ics_only_expected=true for a dedicated internal ICS sensor or equivalent capture scope.",
                    ],
                },
                warnings=[
                    "Internal-ICS-only capture expectation is not explicitly configured; public-to-public observations were not treated as violations."
                ] if public_rows else [],
            )

        findings: list[Finding] = []
        violation_flows = 0
        for pair, rows in sorted(groups.items()):
            if len(rows) < min_flows:
                continue
            violation_flows += len(rows)
            findings.append(_finding(pair, rows))

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "public_to_public_connections_observed": public_rows,
                "public_to_public_policy_violations": violation_flows,
                "public_to_public_findings": len(findings),
                "distinct_public_pairs": len(findings),
                "skipped_no_internal_only_policy": 0,
                "skipped_allowlisted": skipped_allowlisted,
            },
            evidence={
                "inspected_logs": ["conn"],
                "policy": policy,
                "notes": [
                    "Both endpoints must be globally routable according to Python IP address classification; RFC1918/private, loopback, link-local, multicast, documentation, and other special-use addresses are excluded.",
                    "A finding indicates capture-scope or routing-policy drift. It does not by itself prove malicious activity, compromise, or that either public endpoint is an ICS device.",
                    "Possible causes include sensor placement changes, SPAN/TAP misconfiguration, NAT visibility, transit traffic, VPN termination, or unexpected Internet-facing communications.",
                ],
            },
            warnings=[],
        )


def _finding(pair: tuple[str, str], rows: list[dict[str, Any]]) -> Finding:
    source, destination = pair
    representative = rows[:MAX_EVIDENCE_FLOWS]
    services = sorted({_text(row.get("service")) for row in rows if _text(row.get("service"))})
    ports = sorted({
        port
        for row in rows
        if (port := _as_int(_first(row, "destination_port", "id.resp_p"))) is not None
    })
    timestamps = [
        ts for row in representative
        if (ts := _first(row, "timestamp", "ts")) not in (None, "")
    ]

    return Finding(
        title=f"Public-to-public traffic observed in internal ICS capture: {source} -> {destination}",
        severity="medium",
        summary=(
            f"Observed {len(rows)} connection record(s) between globally routable addresses {source} and {destination} "
            "in a capture explicitly configured as internal-ICS-only. Verify sensor/SPAN placement, NAT or VPN termination, "
            "routing changes, and whether Internet/transit traffic is intentionally visible at this collection point."
        ),
        confidence="high",
        detection_basis="derived",
        devices=[source, destination],
        services=services,
        ports=ports,
        connection_pairs=[{"source": source, "destination": destination}],
        flows=representative,
        timestamps=timestamps,
        tags=["ot", "ics", "public-ip", "capture-scope", "network-policy"],
        metadata={
            "finding_type": "public_to_public_in_internal_ics_capture",
            "source_public_ip": source,
            "destination_public_ip": destination,
            "flow_count": len(rows),
            "evidence_capped": len(rows) > MAX_EVIDENCE_FLOWS,
        },
    )


def _policy(metadata: dict[str, Any]) -> dict[str, Any]:
    raw = metadata.get("public_to_public_policy", {}) if isinstance(metadata, dict) else {}
    return raw if isinstance(raw, dict) else {}


def _values(value: Any) -> list[Any]:
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [] if value in (None, "") else [value]


def _networks(value: Any) -> list[ipaddress._BaseNetwork]:
    result: list[ipaddress._BaseNetwork] = []
    for item in _values(value):
        text = _text(item)
        if not text:
            continue
        try:
            result.append(ipaddress.ip_network(text, strict=False))
        except ValueError:
            try:
                address = ipaddress.ip_address(text)
            except ValueError:
                continue
            result.append(ipaddress.ip_network(f"{address}/{address.max_prefixlen}", strict=False))
    return result


def _pair_set(value: Any) -> set[tuple[str, str]]:
    result: set[tuple[str, str]] = set()
    if not isinstance(value, list):
        return result
    for item in value:
        if not isinstance(item, dict):
            continue
        source = _ip(item.get("source"))
        destination = _ip(item.get("destination"))
        if source and destination:
            result.add((source, destination))
    return result


def _is_public(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.is_global and not address.is_multicast


def _ip_in_networks(value: str, networks: list[ipaddress._BaseNetwork]) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(address.version == network.version and address in network for network in networks)


def _ip(value: Any) -> str | None:
    try:
        return str(ipaddress.ip_address(_text(value)))
    except ValueError:
        return None


def _bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "yes", "1", "on"}:
            return True
        if normalized in {"false", "no", "0", "off"}:
            return False
    if isinstance(value, (int, float)):
        return bool(value)
    return default


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _first(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in row and row[key] not in (None, ""):
            return row[key]
    return None
