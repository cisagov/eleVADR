from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata


# Zeek weird names vary by analyzer/version.  Classification is therefore based
# on conservative name fragments rather than an exhaustive hard-coded catalog.
CATEGORY_PATTERNS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "checksum",
        (
            "checksum",
            "bad_checksum",
        ),
    ),
    (
        "malformed_header",
        (
            "malformed",
            "bad_header",
            "invalid_header",
            "header_len",
            "header_length",
            "bad_length",
            "invalid_length",
            "truncated",
            "short_packet",
            "bad_option",
            "invalid_option",
        ),
    ),
    (
        "unexpected_state",
        (
            "unexpected",
            "state",
            "sequence",
            "seq",
            "ack",
            "syn_after",
            "data_before",
            "data_after",
            "connection_reuse",
            "partial_connection",
        ),
    ),
    (
        "protocol_violation",
        (
            "violation",
            "invalid",
            "illegal",
            "bad_",
            "unknown_",
            "unrecognized",
        ),
    ),
)

MAX_EVIDENCE_EVENTS = 10

# Weirds that are frequently caused by capture truncation/snaplen, packet loss, or
# capture-interface artifacts.  Keep them visible for data-quality review, but do
# not treat them as security-significant on repetition alone.
CAPTURE_ARTIFACT_WEIRDS = {
    "truncated_ethernet_frame",
    "truncated_packet",
    "packet_too_short",
    "short_packet",
}

MDNS_MULTICAST_DESTINATIONS = {"224.0.0.251", "ff02::fb"}


class WeirdProtocolViolationsModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="weird_protocol_violations",
        name="Weird.log Protocol Violations",
        description=(
            "Analyzes Zeek weird.log for malformed packets, checksum anomalies, unexpected protocol "
            "states, and other protocol-specification violations."
        ),
        category="security_analysis",
        required_logs=("weird",),
        default_enabled=True,
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        weird_rows = context.weird
        conn_by_uid = {
            _text(row.get("uid")): row
            for row in context.connections
            if _text(row.get("uid"))
        }

        grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        unclassified = 0
        for row in weird_rows:
            name = _text(row.get("name")) or "unknown_weird"
            category = _category(name)
            if category == "other":
                unclassified += 1
            grouped[(category, name)].append(row)

        findings: list[Finding] = []
        category_counts: Counter[str] = Counter()
        affected_devices: set[str] = set()

        for (category, name), rows in sorted(grouped.items()):
            devices: set[str] = set()
            pairs: list[dict[str, Any]] = []
            seen_pairs: set[tuple[str, str, int | None, str]] = set()
            ports: set[int] = set()
            timestamps: list[float | str] = []
            associated_conn_rows: list[dict[str, Any]] = []
            associated_conn_uids: set[str] = set()

            for row in rows:
                uid = _text(row.get("uid"))
                conn = conn_by_uid.get(uid) if uid else None
                source = _text(row.get("source_ip", row.get("id.orig_h")))
                destination = _text(row.get("destination_ip", row.get("id.resp_h")))
                port = _as_int(row.get("destination_port", row.get("id.resp_p")))
                protocol = _text(row.get("protocol", row.get("proto")))

                if conn:
                    source = source or _text(conn.get("source_ip", conn.get("id.orig_h")))
                    destination = destination or _text(conn.get("destination_ip", conn.get("id.resp_h")))
                    port = port if port is not None else _as_int(conn.get("destination_port", conn.get("id.resp_p")))
                    protocol = protocol or _text(conn.get("protocol", conn.get("proto")))
                    if uid not in associated_conn_uids:
                        associated_conn_uids.add(uid)
                        associated_conn_rows.append(conn)

                if source:
                    devices.add(source)
                if destination:
                    devices.add(destination)
                if port is not None:
                    ports.add(port)
                ts = row.get("timestamp", row.get("ts"))
                if ts not in (None, ""):
                    timestamps.append(ts)
                if source or destination:
                    key = (source, destination, port, protocol)
                    if key not in seen_pairs:
                        seen_pairs.add(key)
                        pairs.append(
                            {
                                "source": source,
                                "destination": destination,
                                "port": port,
                                "protocol": protocol,
                                "service": "Zeek weird/protocol anomaly",
                            }
                        )

            affected_devices.update(devices)
            category_counts[category] += len(rows)

            policy = _finding_policy(
                category=category,
                name=name,
                rows=rows,
                has_attribution=bool(devices or associated_conn_rows),
            )
            severity = policy["severity"]
            confidence = policy["confidence"]
            disposition = policy["disposition"]
            summary_reason = policy.get("reason") or _reason(category)

            title = _title(category, name, disposition=disposition)
            if len(rows) > 1:
                title += f" ({len(rows)} events)"

            findings.append(
                Finding(
                    title=title,
                    severity=severity,
                    summary=(
                        f"Zeek recorded {len(rows)} '{name}' weird event(s). {summary_reason} "
                        + (
                            "Treat this primarily as capture/data-quality context unless corroborated by other evidence."
                            if disposition == "capture_artifact"
                            else "Correlate with the affected hosts and surrounding connection activity before treating it as malicious."
                        )
                    ),
                    confidence=confidence,
                    detection_basis="protocol_log",
                    devices=sorted(devices),
                    services=["Zeek weird.log"],
                    ports=sorted(ports),
                    connection_pairs=pairs,
                    flows=rows[:MAX_EVIDENCE_EVENTS],
                    subnets=[],
                    timestamps=timestamps[:MAX_EVIDENCE_EVENTS],
                    tags=["zeek-weird", "protocol-violation", category, disposition, name],
                    metadata={
                        "weird_name": name,
                        "category": category,
                        "event_count": len(rows),
                        "associated_connection_count": len(associated_conn_rows),
                        "associated_connections": associated_conn_rows[:MAX_EVIDENCE_EVENTS],
                        "evidence_event_count": min(len(rows), MAX_EVIDENCE_EVENTS),
                        "evidence_truncated": len(rows) > MAX_EVIDENCE_EVENTS,
                        "disposition": disposition,
                        "noise_reason": policy.get("noise_reason"),
                    },
                )
            )

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "weird_findings": len(findings),
                "weird_events": len(weird_rows),
                "unique_weird_names": len({name for _, name in grouped}),
                "affected_devices": len(affected_devices),
                "events_by_category": dict(sorted(category_counts.items())),
            },
            evidence={
                "inspected_logs": ["weird"],
                "unclassified_weird_events": unclassified,
                "notes": [
                    "Zeek weird.log records protocol/analyzer anomalies; not every weird event is malicious.",
                    "Checksum-related weirds are intentionally lower severity because NIC offload, capture location, and truncated captures can create apparent checksum problems.",
                    "Known capture-artifact weirds and unattributed link-layer truncation events remain informational even when repeated.",
                    "mDNS DNS-truncation weirds on 224.0.0.251:5353 or ff02::fb:5353 are downgraded because implementation quirks and capture artifacts are common causes.",
                    "Repetition alone never promotes a malformed-header weird to High; severity depends on anomaly type, attribution, and protocol context.",
                    "Each finding retains full event/connection totals in metadata but includes at most 10 representative weird events and 10 representative correlated conn.log records.",
                    "When a weird event carries a Zeek UID, the module attaches representative matching conn.log context as supporting evidence.",
                ],
            },
            warnings=[],
        )


def _category(name: str) -> str:
    lowered = name.lower()
    for category, patterns in CATEGORY_PATTERNS:
        if any(pattern in lowered for pattern in patterns):
            return category
    return "other"


def _finding_policy(
    *,
    category: str,
    name: str,
    rows: list[dict[str, Any]],
    has_attribution: bool,
) -> dict[str, str | None]:
    lowered = name.lower()

    if lowered in CAPTURE_ARTIFACT_WEIRDS or (
        category == "malformed_header" and not has_attribution and _looks_link_layer(rows)
    ):
        return {
            "severity": "informational",
            "confidence": "low",
            "disposition": "capture_artifact",
            "reason": (
                "This weird is commonly associated with truncated frames, snap-length limits, packet loss, "
                "or other capture-quality artifacts rather than a confirmed protocol attack."
            ),
            "noise_reason": "capture_or_link_layer_truncation",
        }

    if _is_mdns_dns_truncation(lowered, rows):
        return {
            "severity": "low",
            "confidence": "medium",
            "disposition": "mdns_noise",
            "reason": (
                "The malformed/truncated DNS record occurred in mDNS multicast traffic. Repeated mDNS parser "
                "weirds can result from device implementation quirks, packet truncation, or capture artifacts."
            ),
            "noise_reason": "mdns_multicast_truncation",
        }

    if category == "checksum":
        return {
            "severity": "low",
            "confidence": "low",
            "disposition": "review",
            "reason": _reason(category),
            "noise_reason": "checksum_offload_or_capture_artifact_possible",
        }

    if category == "malformed_header":
        return {
            "severity": "medium" if has_attribution else "low",
            "confidence": "medium" if has_attribution else "low",
            "disposition": "review",
            "reason": _reason(category),
            "noise_reason": None,
        }

    if category in {"unexpected_state", "protocol_violation"}:
        repeated = len(rows) >= 3
        return {
            "severity": "medium" if repeated and has_attribution else "low",
            "confidence": "high" if has_attribution else "medium",
            "disposition": "review",
            "reason": _reason(category),
            "noise_reason": None,
        }

    return {
        "severity": "low",
        "confidence": "medium" if has_attribution else "low",
        "disposition": "review",
        "reason": _reason(category),
        "noise_reason": None,
    }


def _is_mdns_dns_truncation(name: str, rows: list[dict[str, Any]]) -> bool:
    if "dns_truncated" not in name:
        return False
    relevant = 0
    mdns = 0
    for row in rows:
        destination = _text(row.get("destination_ip", row.get("id.resp_h"))).lower()
        port = _as_int(row.get("destination_port", row.get("id.resp_p")))
        if destination or port is not None:
            relevant += 1
            if destination in MDNS_MULTICAST_DESTINATIONS and port == 5353:
                mdns += 1
    return relevant > 0 and mdns == relevant


def _looks_link_layer(rows: list[dict[str, Any]]) -> bool:
    sources = {_text(row.get("weird_source", row.get("source"))).upper() for row in rows}
    return any(source in {"ETHERNET", "LINK", "PACKET"} for source in sources if source)


def _reason(category: str) -> str:
    return {
        "checksum": (
            "The packet failed a checksum-related validation. This can indicate corruption or malformed traffic, "
            "but checksum offload and capture artifacts are common benign causes."
        ),
        "malformed_header": (
            "The event indicates malformed, truncated, or internally inconsistent protocol/header data."
        ),
        "unexpected_state": (
            "The event indicates traffic that did not follow the analyzer's expected protocol or connection state progression."
        ),
        "protocol_violation": (
            "The event indicates an invalid, illegal, or otherwise protocol-nonconforming condition."
        ),
        "other": (
            "The event is a Zeek analyzer anomaly that does not match one of the module's higher-level categories."
        ),
    }[category]


def _title(category: str, name: str, *, disposition: str = "review") -> str:
    prefix = {
        "checksum": "Checksum anomaly",
        "malformed_header": "Malformed protocol/header anomaly",
        "unexpected_state": "Unexpected protocol state",
        "protocol_violation": "Protocol violation",
        "other": "Zeek protocol anomaly",
    }[category]
    if disposition == "capture_artifact":
        return f"Capture-quality anomaly: {name}"
    if disposition == "mdns_noise":
        return f"Repeated malformed mDNS record: {name}"
    return f"{prefix}: {name}"


def _as_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()
