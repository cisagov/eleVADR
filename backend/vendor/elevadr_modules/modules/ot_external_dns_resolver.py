from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import ipaddress
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata

MAX_EVIDENCE_ROWS = 10
OT_ROLE_TOKENS = {"ot", "control", "ics", "scada", "operations", "industrial", "process", "plc", "hmi", "rtu", "dcs", "bas", "bms"}


@dataclass(slots=True)
class _Segment:
    name: str
    role: str
    network: ipaddress._BaseNetwork


@dataclass(slots=True)
class _DnsEvent:
    row: dict[str, Any]
    timestamp: float | None
    source: str
    resolver: str
    source_port: int | None
    destination_port: int | None
    query: str
    qtype: str
    source_segment: _Segment | None
    resolver_segment: _Segment | None
    resolver_class: str
    trusted: bool


class OtExternalDnsResolverModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="ot_external_dns_resolver",
        name="OT Host Using External / Internet DNS Resolver",
        description=(
            "Detects OT/control-system hosts sending DNS queries to public Internet resolvers or resolvers outside "
            "the configured OT boundary instead of approved internal DNS infrastructure."
        ),
        category="security_analysis",
        required_logs=("dns",),
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        if not context.dns:
            return ModuleResult(
                module_id=self.metadata.id,
                findings=[],
                metrics={
                    "dns_events_evaluated": 0,
                    "ot_dns_queries": 0,
                    "public_resolver_queries": 0,
                    "non_ot_resolver_queries": 0,
                    "unclassified_resolver_queries": 0,
                    "ot_hosts_using_external_resolvers": 0,
                    "dns_resolver_findings": 0,
                },
                evidence={
                    "inspected_logs": [],
                    "notes": ["The detector requires dns.log query evidence and does not infer resolver use from UDP/TCP 53 alone."],
                },
                warnings=[],
            )

        policy = _policy(context.metadata)
        segments = _load_segments(context.metadata)
        inventory_ot = _load_ot_inventory(context.metadata)
        explicit_ot = _ip_set(policy.get("ot_hosts") or policy.get("control_system_hosts"))
        trusted_rules = _rules(policy, "trusted_resolvers", "trusted_dns_resolvers", "internal_resolvers")
        allowed_rules = _rules(policy, "allowed_resolvers", "approved_resolvers")
        treat_unclassified = _as_bool(policy.get("treat_unclassified_private_as_external"), False)
        enforce_trusted_only = _as_bool(policy.get("enforce_trusted_resolvers_only"), False)
        min_queries = max(1, _as_int(policy.get("min_queries")) or 1)

        events: list[_DnsEvent] = []
        skipped_non_ot = 0
        skipped_non_query = 0
        skipped_allowed = 0

        for row in context.dns:
            event = _event(row, segments, inventory_ot, explicit_ot, trusted_rules)
            if event is None:
                skipped_non_query += 1
                continue
            if not _is_ot_source(event.source, event.source_segment, inventory_ot, explicit_ot):
                skipped_non_ot += 1
                continue
            if _matches_any(event.resolver, allowed_rules):
                skipped_allowed += 1
                continue
            events.append(event)

        violations: list[_DnsEvent] = []
        public_queries = 0
        non_ot_queries = 0
        unclassified_queries = 0
        untrusted_ot_queries = 0

        for event in events:
            if event.resolver_class == "public":
                public_queries += 1
                violations.append(event)
            elif event.resolver_class == "non_ot":
                non_ot_queries += 1
                violations.append(event)
            elif event.resolver_class == "unclassified_private":
                unclassified_queries += 1
                if treat_unclassified:
                    violations.append(event)
            elif event.resolver_class == "ot" and enforce_trusted_only and trusted_rules and not event.trusted:
                untrusted_ot_queries += 1
                violations.append(event)

        by_source: dict[str, list[_DnsEvent]] = defaultdict(list)
        for event in violations:
            by_source[event.source].append(event)

        findings: list[Finding] = []
        for source, rows in sorted(by_source.items()):
            if len(rows) < min_queries:
                continue
            findings.append(_finding(source, rows, trusted_rules))

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "dns_events_evaluated": len(context.dns),
                "ot_dns_queries": len(events),
                "public_resolver_queries": public_queries,
                "non_ot_resolver_queries": non_ot_queries,
                "unclassified_resolver_queries": unclassified_queries,
                "untrusted_ot_resolver_queries": untrusted_ot_queries,
                "ot_hosts_using_external_resolvers": len(findings),
                "dns_resolver_findings": len(findings),
                "skipped_non_ot_events": skipped_non_ot,
                "skipped_non_query_events": skipped_non_query,
                "skipped_allowed_resolver_events": skipped_allowed,
            },
            evidence={
                "inspected_logs": ["dns"],
                "trusted_resolvers": trusted_rules,
                "allowed_resolvers": allowed_rules,
                "min_queries": min_queries,
                "treat_unclassified_private_as_external": treat_unclassified,
                "enforce_trusted_resolvers_only": enforce_trusted_only,
                "notes": [
                    "Only explicit dns.log client-query records are evaluated; DNS use is not inferred from port 53 connections alone.",
                    "Globally routable resolver addresses are classified as public Internet resolvers.",
                    "Private resolver addresses are classified as outside OT only when segment metadata maps them to a non-OT role, unless strict unclassified-private handling is explicitly enabled.",
                    "An unmapped private resolver is not considered external by default because the detector cannot safely infer the site's routing or trust boundary.",
                    "Trusted and allowed resolver lists may contain individual IPs or CIDR networks.",
                    "Evidence is capped at 10 representative DNS queries while full counts remain in finding metadata.",
                ],
            },
            warnings=[],
        )


def _finding(source: str, rows: list[_DnsEvent], trusted_rules: list[Any]) -> Finding:
    resolvers = sorted({row.resolver for row in rows})
    public_resolvers = sorted({row.resolver for row in rows if row.resolver_class == "public"})
    non_ot_resolvers = sorted({row.resolver for row in rows if row.resolver_class == "non_ot"})
    unclassified = sorted({row.resolver for row in rows if row.resolver_class == "unclassified_private"})
    untrusted_ot = sorted({row.resolver for row in rows if row.resolver_class == "ot" and not row.trusted})
    trusted_observed = sorted({row.resolver for row in rows if row.trusted})

    if public_resolvers:
        severity = "high"
        title = "OT Host Using Public Internet DNS Resolver"
    elif non_ot_resolvers:
        severity = "medium"
        title = "OT Host Using DNS Resolver Outside OT Boundary"
    else:
        severity = "medium"
        title = "OT Host Using Unapproved DNS Resolver"

    classes: list[str] = []
    if public_resolvers:
        classes.append(f"public: {', '.join(public_resolvers[:5])}")
    if non_ot_resolvers:
        classes.append(f"non-OT: {', '.join(non_ot_resolvers[:5])}")
    if unclassified:
        classes.append(f"unclassified private: {', '.join(unclassified[:5])}")
    if untrusted_ot:
        classes.append(f"untrusted OT: {', '.join(untrusted_ot[:5])}")

    summary = (
        f"OT/control-system host {source} sent {len(rows)} DNS query event(s) to {len(resolvers)} resolver(s) "
        f"outside the expected resolver policy ({'; '.join(classes)}). This bypasses centralized OT DNS controls and can "
        "expose internal naming behavior to infrastructure outside the control-system trust boundary."
    )
    if trusted_rules and not trusted_observed:
        summary += " No configured trusted resolver was observed among the violating DNS queries."

    evidence = sorted(rows, key=lambda row: row.timestamp if row.timestamp is not None else -1.0)
    source_segment = next((row.source_segment for row in rows if row.source_segment is not None), None)

    return Finding(
        title=title,
        severity=severity,
        summary=summary,
        confidence="high",
        detection_basis="protocol_log",
        devices=sorted({source, *resolvers}),
        services=["DNS"],
        ports=[53],
        connection_pairs=[{"source": source, "destination": resolver} for resolver in resolvers[:MAX_EVIDENCE_ROWS]],
        flows=[_flow(row) for row in evidence[:MAX_EVIDENCE_ROWS]],
        subnets=[str(source_segment.network)] if source_segment is not None else [],
        timestamps=[row.timestamp for row in evidence[:MAX_EVIDENCE_ROWS] if row.timestamp is not None],
        tags=["dns", "ot", "external-resolver", "internet", "policy-drift"],
        metadata={
            "source_ip": source,
            "source_segment": source_segment.name if source_segment is not None else "",
            "resolver_count": len(resolvers),
            "resolvers": resolvers,
            "public_resolvers": public_resolvers,
            "non_ot_resolvers": non_ot_resolvers,
            "unclassified_private_resolvers": unclassified,
            "untrusted_ot_resolvers": untrusted_ot,
            "trusted_resolver_policy_configured": bool(trusted_rules),
            "violating_query_count": len(rows),
            "evidence_truncated": len(rows) > MAX_EVIDENCE_ROWS,
        },
    )


def _event(
    row: dict[str, Any],
    segments: list[_Segment],
    inventory_ot: set[str],
    explicit_ot: set[str],
    trusted_rules: list[Any],
) -> _DnsEvent | None:
    source = _ip(_first(row, "source_ip", "id.orig_h", "src"))
    resolver = _ip(_first(row, "destination_ip", "id.resp_h", "dst"))
    if not source or not resolver:
        return None
    destination_port = _as_int(_first(row, "destination_port", "id.resp_p"))
    if destination_port not in (None, 53):
        return None
    query = _text(_first(row, "query", "qname"))
    # dns.log may contain response-only rows in custom pipelines. Require a client query name when present in normal Zeek logs.
    if "query" in row and not query:
        return None
    source_segment = _segment_for_ip(source, segments)
    resolver_segment = _segment_for_ip(resolver, segments)
    trusted = _matches_any(resolver, trusted_rules)
    resolver_class = _resolver_class(resolver, resolver_segment)
    return _DnsEvent(
        row=row,
        timestamp=_as_float(_first(row, "timestamp", "ts")),
        source=source,
        resolver=resolver,
        source_port=_as_int(_first(row, "source_port", "id.orig_p")),
        destination_port=destination_port,
        query=query,
        qtype=_text(_first(row, "qtype_name", "qtype")),
        source_segment=source_segment,
        resolver_segment=resolver_segment,
        resolver_class=resolver_class,
        trusted=trusted,
    )


def _flow(event: _DnsEvent) -> dict[str, Any]:
    return {
        "timestamp": event.timestamp,
        "source_ip": event.source,
        "source_port": event.source_port,
        "resolver_ip": event.resolver,
        "destination_port": event.destination_port,
        "query": event.query,
        "qtype": event.qtype,
        "resolver_class": event.resolver_class,
        "uid": _first(event.row, "uid"),
    }


def _resolver_class(resolver: str, segment: _Segment | None) -> str:
    if _is_public(resolver):
        return "public"
    if segment is not None:
        return "ot" if _segment_is_ot(segment) else "non_ot"
    try:
        address = ipaddress.ip_address(resolver)
    except ValueError:
        return "unknown"
    if address.is_private or address.is_link_local:
        return "unclassified_private"
    return "special"


def _policy(metadata: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(metadata, dict):
        return {}
    for key in ("ot_dns_policy", "external_dns_policy", "dns_resolver_policy"):
        value = metadata.get(key)
        if isinstance(value, dict):
            return value
    return {}


def _load_segments(metadata: dict[str, Any]) -> list[_Segment]:
    raw = metadata.get("segments") if isinstance(metadata, dict) else None
    if not isinstance(raw, list):
        return []
    out: list[_Segment] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        cidr = _text(item.get("cidr") or item.get("subnet") or item.get("network"))
        role = _text(item.get("role") or item.get("zone") or item.get("type") or item.get("purdue_level"))
        name = _text(item.get("name") or cidr)
        if not cidr or not role:
            continue
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        out.append(_Segment(name=name or cidr, role=role, network=network))
    return out


def _load_ot_inventory(metadata: dict[str, Any]) -> set[str]:
    raw = metadata.get("asset_inventory") if isinstance(metadata, dict) else None
    if not isinstance(raw, list):
        return set()
    out: set[str] = set()
    for item in raw:
        if not isinstance(item, dict):
            continue
        ip = _ip(item.get("ip") or item.get("ip_address") or item.get("address"))
        role = _text(item.get("role") or item.get("type") or item.get("asset_type"))
        if ip and _role_is_ot(role):
            out.add(ip)
    return out


def _is_ot_source(source: str, segment: _Segment | None, inventory_ot: set[str], explicit_ot: set[str]) -> bool:
    return source in inventory_ot or source in explicit_ot or _segment_is_ot(segment)


def _segment_for_ip(value: str, segments: list[_Segment]) -> _Segment | None:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    best: _Segment | None = None
    for segment in segments:
        if address.version == segment.network.version and address in segment.network:
            if best is None or segment.network.prefixlen > best.network.prefixlen:
                best = segment
    return best


def _segment_is_ot(segment: _Segment | None) -> bool:
    return segment is not None and _role_is_ot(segment.role)


def _role_is_ot(role: str) -> bool:
    value = role.strip().lower().replace("_", " ")
    return value in OT_ROLE_TOKENS or any(token in value for token in ("plc", "scada", "control", "industrial", "historian", "hmi", "rtu", "dcs", "bas", "bms"))


def _rules(policy: dict[str, Any], *keys: str) -> list[Any]:
    for key in keys:
        value = policy.get(key)
        if isinstance(value, list):
            return value
    return []


def _matches_any(value: str, rules: list[Any]) -> bool:
    if not value:
        return False
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    for rule in rules:
        text = _text(rule)
        if not text:
            continue
        try:
            if "/" in text:
                if address in ipaddress.ip_network(text, strict=False):
                    return True
            elif address == ipaddress.ip_address(text):
                return True
        except ValueError:
            continue
    return False


def _ip_set(value: Any) -> set[str]:
    if not isinstance(value, list):
        return set()
    return {ip for item in value if (ip := _ip(item))}


def _is_public(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.is_global


def _first(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = row.get(key)
        if value not in (None, "", "-"):
            return value
    return None


def _ip(value: Any) -> str:
    text = _text(value)
    if not text:
        return ""
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return ""


def _text(value: Any) -> str:
    return str(value).strip() if value not in (None, "") else ""


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


def _as_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
    return default
