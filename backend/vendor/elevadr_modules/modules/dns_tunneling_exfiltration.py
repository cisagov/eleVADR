from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
import math
import statistics
from typing import Any, Iterable

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata


# Conservative defaults intended to produce review-worthy signals rather than
# flag every long or failed DNS query as tunneling.
MIN_TUNNEL_QUERIES = 8
MIN_TUNNEL_UNIQUE_QUERIES = 6
MIN_MEDIAN_PAYLOAD_CHARS = 20
MIN_MEDIAN_ENTROPY = 3.2
MIN_ENCODED_QUERY_RATIO = 0.60

MIN_HIGH_PAYLOAD_EVENTS = 3
HIGH_PAYLOAD_QUERY_LENGTH = 60
HIGH_PAYLOAD_LABEL_LENGTH = 40
VERY_HIGH_PAYLOAD_QUERY_LENGTH = 120

MIN_NXDOMAIN_QUERIES = 20
MIN_NXDOMAIN_UNIQUE_QUERIES = 15
MIN_NXDOMAIN_RATIO = 0.70
MIN_NXDOMAIN_UNIQUE_RATIO = 0.70

MAX_EVIDENCE_ROWS = 25

_SUSPICIOUS_QTYPE_NAMES = {"TXT", "NULL", "ANY"}
_SUSPICIOUS_QTYPE_NUMBERS = {16: "TXT", 10: "NULL", 255: "ANY"}

# DNS mechanisms that are commonly noisy/periodic and are poor tunneling
# candidates in passive OT captures.  Regular DNS on UDP/TCP 53 is retained.
_EXCLUDED_RESPONDER_PORTS = {5353, 5355}
_EXCLUDED_SUFFIXES = (
    ".local",
    ".local.",
    ".localdomain",
    ".home.arpa",
    ".in-addr.arpa",
    ".ip6.arpa",
)
_EXCLUDED_EXACT = {"wpad", "localhost"}


@dataclass(slots=True)
class _DnsEvent:
    row: dict[str, Any]
    timestamp: float | None
    source: str
    destination: str
    responder_port: int | None
    query: str
    base_domain: str
    payload: str
    payload_length: int
    longest_label_length: int
    entropy: float
    qtype: str
    rcode: str


class DnsTunnelingExfiltrationModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="dns_tunneling_exfiltration",
        name="DNS Tunneling / Exfiltration",
        description=(
            "Identifies DNS behavior consistent with covert tunneling or exfiltration, including "
            "encoded/high-entropy subdomains, high-payload TXT/NULL/ANY queries, and sustained "
            "NXDOMAIN-heavy query patterns."
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
                    "dns_tunneling_findings": 0,
                    "encoded_subdomain_findings": 0,
                    "high_payload_qtype_findings": 0,
                    "nxdomain_anomaly_findings": 0,
                },
                evidence={
                    "inspected_logs": [],
                    "skipped_logs": ["dns"],
                    "notes": ["dns.log is required for DNS tunneling/exfiltration analysis."],
                },
                warnings=[],
            )

        events: list[_DnsEvent] = []
        skipped_discovery = 0
        skipped_invalid = 0
        for row in context.dns:
            event = _normalize_dns_event(row)
            if event is None:
                skipped_invalid += 1
                continue
            if _excluded_query(event):
                skipped_discovery += 1
                continue
            events.append(event)

        findings: list[Finding] = []
        encoded_findings = _detect_encoded_subdomains(events)
        qtype_findings = _detect_high_payload_qtypes(events)
        nxdomain_findings = _detect_nxdomain_anomalies(events)
        findings.extend(encoded_findings)
        findings.extend(qtype_findings)
        findings.extend(nxdomain_findings)

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "dns_tunneling_findings": len(findings),
                "encoded_subdomain_findings": len(encoded_findings),
                "high_payload_qtype_findings": len(qtype_findings),
                "nxdomain_anomaly_findings": len(nxdomain_findings),
                "dns_events_evaluated": len(events),
                "affected_sources": len({d for f in findings for d in f.devices[:1]}),
                "affected_base_domains": len({str(f.metadata.get("base_domain", "")) for f in findings if f.metadata.get("base_domain")}),
            },
            evidence={
                "inspected_logs": ["dns"],
                "skipped_discovery_or_reverse_dns_events": skipped_discovery,
                "skipped_invalid_dns_events": skipped_invalid,
                "thresholds": {
                    "encoded_subdomain": {
                        "minimum_queries": MIN_TUNNEL_QUERIES,
                        "minimum_unique_queries": MIN_TUNNEL_UNIQUE_QUERIES,
                        "minimum_median_payload_chars": MIN_MEDIAN_PAYLOAD_CHARS,
                        "minimum_median_entropy": MIN_MEDIAN_ENTROPY,
                        "minimum_encoded_query_ratio": MIN_ENCODED_QUERY_RATIO,
                    },
                    "high_payload_qtypes": {
                        "minimum_events": MIN_HIGH_PAYLOAD_EVENTS,
                        "query_length": HIGH_PAYLOAD_QUERY_LENGTH,
                        "label_length": HIGH_PAYLOAD_LABEL_LENGTH,
                        "single_event_very_high_query_length": VERY_HIGH_PAYLOAD_QUERY_LENGTH,
                    },
                    "nxdomain": {
                        "minimum_queries": MIN_NXDOMAIN_QUERIES,
                        "minimum_unique_queries": MIN_NXDOMAIN_UNIQUE_QUERIES,
                        "minimum_nxdomain_ratio": MIN_NXDOMAIN_RATIO,
                        "minimum_unique_query_ratio": MIN_NXDOMAIN_UNIQUE_RATIO,
                    },
                },
                "notes": [
                    "DNS tunneling detection is heuristic. Long/high-entropy labels, unusual query types, and NXDOMAIN-heavy behavior can also be produced by legitimate software, telemetry, CDNs, or DGA-like behavior.",
                    "mDNS (5353), LLMNR (5355), reverse-DNS zones, and common local-only names are excluded from these heuristics by default.",
                    "Findings should be correlated with asset role, destination domain reputation, process context, and packet/application evidence before labeling activity as command-and-control or exfiltration.",
                ],
            },
            warnings=[],
        )


def _detect_encoded_subdomains(events: list[_DnsEvent]) -> list[Finding]:
    groups: dict[tuple[str, str], list[_DnsEvent]] = defaultdict(list)
    for event in events:
        if event.payload:
            groups[(event.source, event.base_domain)].append(event)

    findings: list[Finding] = []
    for (source, base_domain), rows in sorted(groups.items()):
        if len(rows) < MIN_TUNNEL_QUERIES:
            continue
        unique_queries = {event.query.lower() for event in rows}
        if len(unique_queries) < MIN_TUNNEL_UNIQUE_QUERIES:
            continue

        payload_lengths = [event.payload_length for event in rows]
        entropies = [event.entropy for event in rows if event.payload_length >= 8]
        if not entropies:
            continue
        median_payload = statistics.median(payload_lengths)
        median_entropy = statistics.median(entropies)
        encoded_count = sum(_looks_encoded(event.payload) for event in rows)
        encoded_ratio = encoded_count / len(rows)
        unique_ratio = len(unique_queries) / len(rows)

        # Require both size/diversity and a content signal.  This helps avoid
        # flagging ordinary CDN-style hostnames solely because they are long.
        if median_payload < MIN_MEDIAN_PAYLOAD_CHARS:
            continue
        if median_entropy < MIN_MEDIAN_ENTROPY and encoded_ratio < MIN_ENCODED_QUERY_RATIO:
            continue
        if unique_ratio < 0.60:
            continue

        confidence = "high" if (
            len(rows) >= 12
            and median_payload >= 28
            and median_entropy >= 3.4
            and unique_ratio >= 0.80
        ) else "medium"
        destinations = sorted({event.destination for event in rows if event.destination})
        ports = sorted({event.responder_port for event in rows if event.responder_port is not None})
        evidence_rows = [event.row for event in rows[:MAX_EVIDENCE_ROWS]]

        findings.append(
            Finding(
                title="DNS queries contain repeated encoded/high-entropy subdomain payloads",
                severity="medium",
                confidence=confidence,
                detection_basis="heuristic",
                summary=(
                    f"Observed {len(rows)} DNS queries from {source} toward {base_domain} with "
                    f"a median encoded-subdomain payload length of {median_payload:.1f} characters, "
                    f"median entropy of {median_entropy:.2f} bits/character, and {unique_ratio * 100:.0f}% unique queries. "
                    "This pattern is consistent with DNS tunneling or data encoding in subdomains, but requires contextual validation."
                ),
                devices=sorted({source, *destinations}),
                services=["DNS"],
                ports=ports,
                connection_pairs=_connection_pairs(rows),
                flows=evidence_rows,
                subnets=[],
                timestamps=_timestamps(rows),
                tags=["dns", "dns-tunneling", "exfiltration", "encoded-subdomain"],
                metadata={
                    "rule_id": "encoded_subdomain",
                    "base_domain": base_domain,
                    "query_count": len(rows),
                    "unique_query_count": len(unique_queries),
                    "unique_query_ratio": round(unique_ratio, 6),
                    "median_payload_length": round(float(median_payload), 3),
                    "median_entropy_bits_per_character": round(float(median_entropy), 6),
                    "encoded_query_ratio": round(encoded_ratio, 6),
                    "maximum_label_length": max(event.longest_label_length for event in rows),
                    "evidence_truncated": len(rows) > MAX_EVIDENCE_ROWS,
                },
            )
        )
    return findings


def _detect_high_payload_qtypes(events: list[_DnsEvent]) -> list[Finding]:
    groups: dict[tuple[str, str, str], list[_DnsEvent]] = defaultdict(list)
    for event in events:
        if event.qtype not in _SUSPICIOUS_QTYPE_NAMES:
            continue
        is_high = (
            len(event.query) >= HIGH_PAYLOAD_QUERY_LENGTH
            or event.longest_label_length >= HIGH_PAYLOAD_LABEL_LENGTH
        )
        if is_high:
            groups[(event.source, event.base_domain, event.qtype)].append(event)

    findings: list[Finding] = []
    for (source, base_domain, qtype), rows in sorted(groups.items()):
        very_large = any(len(event.query) >= VERY_HIGH_PAYLOAD_QUERY_LENGTH for event in rows)
        if len(rows) < MIN_HIGH_PAYLOAD_EVENTS and not very_large:
            continue
        unique_queries = {event.query.lower() for event in rows}
        median_length = statistics.median(len(event.query) for event in rows)
        median_entropy = statistics.median(event.entropy for event in rows)
        confidence = "high" if len(rows) >= 6 and median_length >= 80 else "medium"
        severity = "high" if qtype in {"NULL", "ANY"} and len(rows) >= 6 else "medium"
        destinations = sorted({event.destination for event in rows if event.destination})
        ports = sorted({event.responder_port for event in rows if event.responder_port is not None})

        findings.append(
            Finding(
                title=f"High-payload {qtype} DNS query pattern observed",
                severity=severity,
                confidence=confidence,
                detection_basis="heuristic",
                summary=(
                    f"Observed {len(rows)} unusually large {qtype} DNS query event(s) from {source} "
                    f"toward {base_domain}; median query length was {median_length:.1f} characters. "
                    "Large TXT/NULL/ANY query names can be used to carry encoded data through DNS and warrant investigation."
                ),
                devices=sorted({source, *destinations}),
                services=["DNS"],
                ports=ports,
                connection_pairs=_connection_pairs(rows),
                flows=[event.row for event in rows[:MAX_EVIDENCE_ROWS]],
                subnets=[],
                timestamps=_timestamps(rows),
                tags=["dns", "dns-tunneling", "exfiltration", f"qtype-{qtype.lower()}"],
                metadata={
                    "rule_id": "high_payload_dns_qtype",
                    "base_domain": base_domain,
                    "qtype": qtype,
                    "event_count": len(rows),
                    "unique_query_count": len(unique_queries),
                    "median_query_length": round(float(median_length), 3),
                    "maximum_query_length": max(len(event.query) for event in rows),
                    "median_payload_entropy_bits_per_character": round(float(median_entropy), 6),
                    "evidence_truncated": len(rows) > MAX_EVIDENCE_ROWS,
                },
            )
        )
    return findings


def _detect_nxdomain_anomalies(events: list[_DnsEvent]) -> list[Finding]:
    groups: dict[tuple[str, str], list[_DnsEvent]] = defaultdict(list)
    for event in events:
        groups[(event.source, event.base_domain)].append(event)

    findings: list[Finding] = []
    for (source, base_domain), rows in sorted(groups.items()):
        if len(rows) < MIN_NXDOMAIN_QUERIES:
            continue
        nxdomain_rows = [event for event in rows if event.rcode == "NXDOMAIN"]
        if len(nxdomain_rows) < MIN_NXDOMAIN_QUERIES * MIN_NXDOMAIN_RATIO:
            continue
        unique_queries = {event.query.lower() for event in rows}
        nxdomain_ratio = len(nxdomain_rows) / len(rows)
        unique_ratio = len(unique_queries) / len(rows)
        if len(unique_queries) < MIN_NXDOMAIN_UNIQUE_QUERIES:
            continue
        if nxdomain_ratio < MIN_NXDOMAIN_RATIO or unique_ratio < MIN_NXDOMAIN_UNIQUE_RATIO:
            continue

        payload_lengths = [event.payload_length for event in rows]
        entropies = [event.entropy for event in rows if event.payload_length >= 8]
        median_payload = statistics.median(payload_lengths) if payload_lengths else 0.0
        median_entropy = statistics.median(entropies) if entropies else 0.0
        suspicious_payload = median_payload >= 12 or median_entropy >= 3.0
        if not suspicious_payload:
            continue

        confidence = "high" if nxdomain_ratio >= 0.90 and unique_ratio >= 0.90 and len(rows) >= 30 else "medium"
        destinations = sorted({event.destination for event in rows if event.destination})
        ports = sorted({event.responder_port for event in rows if event.responder_port is not None})

        findings.append(
            Finding(
                title="High NXDOMAIN rate with diverse DNS subdomains",
                severity="medium",
                confidence=confidence,
                detection_basis="heuristic",
                summary=(
                    f"Observed {len(rows)} DNS queries from {source} toward {base_domain}, with "
                    f"{len(nxdomain_rows)} ({nxdomain_ratio * 100:.0f}%) returning NXDOMAIN and "
                    f"{unique_ratio * 100:.0f}% of query names unique. High-failure, high-diversity subdomain patterns "
                    "can be consistent with DNS tunneling, exfiltration, or domain-generation behavior."
                ),
                devices=sorted({source, *destinations}),
                services=["DNS"],
                ports=ports,
                connection_pairs=_connection_pairs(rows),
                flows=[event.row for event in rows[:MAX_EVIDENCE_ROWS]],
                subnets=[],
                timestamps=_timestamps(rows),
                tags=["dns", "dns-tunneling", "nxdomain", "exfiltration"],
                metadata={
                    "rule_id": "nxdomain_anomaly",
                    "base_domain": base_domain,
                    "query_count": len(rows),
                    "nxdomain_count": len(nxdomain_rows),
                    "nxdomain_ratio": round(nxdomain_ratio, 6),
                    "unique_query_count": len(unique_queries),
                    "unique_query_ratio": round(unique_ratio, 6),
                    "median_subdomain_payload_length": round(float(median_payload), 3),
                    "median_payload_entropy_bits_per_character": round(float(median_entropy), 6),
                    "evidence_truncated": len(rows) > MAX_EVIDENCE_ROWS,
                },
            )
        )
    return findings


def _normalize_dns_event(row: dict[str, Any]) -> _DnsEvent | None:
    query = _text(row.get("query")).rstrip(".")
    source = _text(row.get("source_ip", row.get("id.orig_h")))
    destination = _text(row.get("destination_ip", row.get("id.resp_h")))
    if not query or not source:
        return None

    responder_port = _as_int(row.get("destination_port", row.get("id.resp_p")))
    labels = [label for label in query.split(".") if label]
    base_domain = _base_domain(labels)
    payload_labels = labels[:-2] if len(labels) >= 3 else labels[:-1]
    payload = "".join(payload_labels)
    entropy = _shannon_entropy(payload.lower()) if payload else 0.0
    qtype = _qtype_name(row)
    rcode = _rcode_name(row)

    return _DnsEvent(
        row=row,
        timestamp=_as_float(row.get("timestamp", row.get("ts"))),
        source=source,
        destination=destination,
        responder_port=responder_port,
        query=query,
        base_domain=base_domain,
        payload=payload,
        payload_length=len(payload),
        longest_label_length=max((len(label) for label in payload_labels), default=0),
        entropy=entropy,
        qtype=qtype,
        rcode=rcode,
    )


def _base_domain(labels: list[str]) -> str:
    if not labels:
        return ""
    if len(labels) == 1:
        return labels[0].lower()
    return ".".join(labels[-2:]).lower()


def _excluded_query(event: _DnsEvent) -> bool:
    lower = event.query.lower()
    if event.responder_port in _EXCLUDED_RESPONDER_PORTS:
        return True
    if lower in _EXCLUDED_EXACT:
        return True
    return any(lower.endswith(suffix.rstrip(".")) for suffix in _EXCLUDED_SUFFIXES)


def _looks_encoded(payload: str) -> bool:
    if len(payload) < 20:
        return False
    text = payload.replace("-", "").replace("_", "")
    if not text:
        return False
    alnum_ratio = sum(char.isalnum() for char in text) / len(text)
    if alnum_ratio < 0.95:
        return False
    lower = text.lower()
    is_hex = all(char in "0123456789abcdef" for char in lower) and len(text) >= 24
    is_base32ish = all(char in "abcdefghijklmnopqrstuvwxyz234567" for char in lower)
    is_base64urlish = all(char.isalnum() or char in "-_" for char in payload)
    return is_hex or is_base32ish or (is_base64urlish and _shannon_entropy(lower) >= 3.3)


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _qtype_name(row: dict[str, Any]) -> str:
    name = _text(row.get("qtype_name")).upper()
    if name:
        return name
    qtype = _as_int(row.get("qtype"))
    if qtype in _SUSPICIOUS_QTYPE_NUMBERS:
        return _SUSPICIOUS_QTYPE_NUMBERS[qtype]
    return str(qtype) if qtype is not None else "UNKNOWN"


def _rcode_name(row: dict[str, Any]) -> str:
    name = _text(row.get("rcode_name")).upper()
    if name:
        return name
    code = _as_int(row.get("rcode"))
    return "NXDOMAIN" if code == 3 else str(code) if code is not None else "UNKNOWN"


def _connection_pairs(rows: Iterable[_DnsEvent]) -> list[dict[str, Any]]:
    unique: dict[tuple[str, str, int | None], dict[str, Any]] = {}
    for event in rows:
        key = (event.source, event.destination, event.responder_port)
        unique.setdefault(
            key,
            {
                "source": event.source,
                "destination": event.destination,
                "port": event.responder_port,
                "protocol": _text(event.row.get("proto", event.row.get("protocol"))) or "udp",
                "service": "DNS",
            },
        )
    return list(unique.values())[:MAX_EVIDENCE_ROWS]


def _timestamps(rows: Iterable[_DnsEvent]) -> list[float | str]:
    values = [event.timestamp for event in rows if event.timestamp is not None]
    return values[:MAX_EVIDENCE_ROWS]


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _as_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _as_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
