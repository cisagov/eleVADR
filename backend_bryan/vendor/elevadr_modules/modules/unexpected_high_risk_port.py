from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata


# Expected service-to-port mappings. These intentionally include common alternate
# deployment ports so the detector focuses on genuinely unusual placements rather
# than flagging routine administration choices such as HTTP/8080 or HTTPS/8443.
EXPECTED_PORTS: dict[str, set[int]] = {
    "http": {80, 8000, 8008, 8080, 8081, 8888},
    "ssl": {443, 8443, 9443},
    "tls": {443, 8443, 9443},
    "https": {443, 8443, 9443},
    "ssh": {22},
    "ftp": {21},
    "smtp": {25, 465, 587},
    "dns": {53},
    "ntp": {123},
    "rdp": {3389},
    "smb": {139, 445},
    "smb_cmd": {139, 445},
    "mysql": {3306},
    "postgresql": {5432},
    "postgres": {5432},
    "redis": {6379},
    "mqtt": {1883, 8883},
    "amqp": {5671, 5672},
    "telnet": {23},
    "snmp": {161, 162},
    "ldap": {389, 636},
    "kerberos": {88},
    "imap": {143, 993},
    "pop3": {110, 995},
    "modbus": {502},
    "dnp3": {20000},
    "enip": {44818, 2222},
    "bacnet": {47808},
}

# Ports with long-standing or repeated use in offensive tooling, backdoors,
# proxies, and C2 frameworks. Use of one of these ports is a review indicator,
# not proof of malware. The module reports the rationale explicitly.
HIGH_RISK_PORTS: dict[int, str] = {
    1337: "commonly associated with backdoors, shells, and offensive tooling",
    31337: "historically associated with backdoors and remote-control malware",
    4444: "commonly used by reverse shells and penetration-testing/C2 tooling",
    5555: "frequently used for remote shells/debug bridges and abused remote access",
    6666: "historically associated with IRC/backdoor command channels",
    6667: "IRC port historically abused for botnet command-and-control",
    6697: "TLS IRC port that can also be used by botnet command channels",
    9001: "commonly used by anonymization/proxy software and sometimes abused for C2",
    9050: "commonly associated with SOCKS proxying/Tor and may warrant review in restricted networks",
}

_SERVICE_ALIASES: dict[str, str] = {
    "http": "http",
    "ssl": "ssl",
    "tls": "tls",
    "https": "https",
    "ssh": "ssh",
    "ftp": "ftp",
    "smtp": "smtp",
    "dns": "dns",
    "ntp": "ntp",
    "rdp": "rdp",
    "smb": "smb",
    "smb_cmd": "smb_cmd",
    "mysql": "mysql",
    "postgresql": "postgresql",
    "postgres": "postgres",
    "redis": "redis",
    "mqtt": "mqtt",
    "amqp": "amqp",
    "telnet": "telnet",
    "snmp": "snmp",
    "ldap": "ldap",
    "kerberos": "kerberos",
    "imap": "imap",
    "pop3": "pop3",
    "modbus": "modbus",
    "dnp3": "dnp3",
    "enip": "enip",
    "bacnet": "bacnet",
}

MAX_EVIDENCE_FLOWS = 100


class UnexpectedHighRiskPortModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="protocol_unexpected_high_risk_port",
        name="Protocol on Unexpected / High-Risk Port",
        description=(
            "Identifies Zeek-recognized application protocols running on unexpected ports and "
            "traffic using ports with a strong historical association with backdoors, reverse shells, "
            "proxies, or command-and-control tooling."
        ),
        category="security_analysis",
        required_logs=("conn",),
        default_enabled=True,
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        groups: dict[tuple[str, int, str, tuple[str, ...]], list[dict[str, Any]]] = defaultdict(list)
        skipped_missing_port = 0
        skipped_no_issue = 0

        for row in context.connections:
            port = _as_int(row.get("destination_port", row.get("id.resp_p")))
            protocol = _text(row.get("protocol", row.get("proto"))).lower()
            services = _services(row.get("service"))
            if port is None:
                skipped_missing_port += 1
                continue

            issue_types: list[str] = []
            identified_services = [service for service in services if service in EXPECTED_PORTS]
            unexpected_services = [
                service for service in identified_services if port not in EXPECTED_PORTS[service]
            ]
            if unexpected_services:
                issue_types.append("unexpected_protocol_port")
            if port in HIGH_RISK_PORTS:
                issue_types.append("high_risk_port")

            if not issue_types:
                skipped_no_issue += 1
                continue

            # If Zeek identified multiple services, preserve the full set in the group key
            # so a flow like ssl,http is not flattened into an arbitrary single label.
            service_key = ",".join(services) if services else "unknown"
            groups[(service_key, port, protocol, tuple(sorted(issue_types)))].append(row)

        findings: list[Finding] = []
        issue_counts = Counter()
        affected_ports: set[int] = set()
        affected_services: set[str] = set()

        for (service_key, port, protocol, issue_types), rows in sorted(groups.items()):
            services = [value for value in service_key.split(",") if value and value != "unknown"]
            identified = [service for service in services if service in EXPECTED_PORTS]
            unexpected = [service for service in identified if port not in EXPECTED_PORTS[service]]
            high_risk = "high_risk_port" in issue_types

            if unexpected:
                confidence = "high"
                detection_basis = "zeek_service"
                severity = "medium" if not high_risk else "high"
            else:
                confidence = "low"
                detection_basis = "port"
                severity = "low"

            service_label = ", ".join(services) if services else f"{protocol or 'unknown'}/{port}"
            if unexpected and high_risk:
                title = f"{service_label} observed on unexpected high-risk port {port}"
            elif unexpected:
                title = f"{service_label} observed on unexpected port {port}"
            else:
                title = f"Traffic observed on high-risk port {port}"

            reason_parts: list[str] = []
            if unexpected:
                expected = sorted({p for service in unexpected for p in EXPECTED_PORTS[service]})
                reason_parts.append(
                    f"Zeek identified {', '.join(unexpected)} on destination port {port}, "
                    f"outside the configured expected port set {expected}."
                )
            if high_risk:
                reason_parts.append(
                    f"Port {port} is a review indicator because it is {HIGH_RISK_PORTS[port]}."
                )
            if not unexpected:
                reason_parts.append(
                    "The application protocol was not confirmed by Zeek, so this port-only indicator is low confidence."
                )

            devices: set[str] = set()
            timestamps: list[float | str] = []
            pairs: list[dict[str, Any]] = []
            seen_pairs: set[tuple[str, str, int, str, str]] = set()
            for row in rows:
                source = _text(row.get("source_ip", row.get("id.orig_h")))
                destination = _text(row.get("destination_ip", row.get("id.resp_h")))
                if source:
                    devices.add(source)
                if destination:
                    devices.add(destination)
                ts = row.get("timestamp", row.get("ts"))
                if ts not in (None, ""):
                    timestamps.append(ts)
                pair_key = (source, destination, port, protocol, service_label)
                if pair_key not in seen_pairs:
                    seen_pairs.add(pair_key)
                    pairs.append(
                        {
                            "source": source,
                            "destination": destination,
                            "port": port,
                            "protocol": protocol,
                            "service": service_label,
                        }
                    )

            findings.append(
                Finding(
                    title=title,
                    severity=severity,
                    summary=(
                        f"Observed {len(rows)} flow(s). " + " ".join(reason_parts) +
                        " Unusual port placement or use of a historically abused port is not by itself proof of malicious activity; review the asset role and expected service configuration."
                    ),
                    confidence=confidence,
                    detection_basis=detection_basis,
                    devices=sorted(devices),
                    services=services or [service_label],
                    ports=[port],
                    connection_pairs=pairs,
                    flows=rows[:MAX_EVIDENCE_FLOWS],
                    subnets=[],
                    timestamps=timestamps[:MAX_EVIDENCE_FLOWS],
                    tags=["unexpected-port" if unexpected else "high-risk-port", *issue_types],
                    metadata={
                        "flow_count": len(rows),
                        "issue_types": list(issue_types),
                        "zeek_identified_services": services,
                        "unexpected_services": unexpected,
                        "expected_ports": {
                            service: sorted(EXPECTED_PORTS[service]) for service in unexpected
                        },
                        "high_risk_port": high_risk,
                        "high_risk_port_reason": HIGH_RISK_PORTS.get(port),
                        "evidence_flow_count": min(len(rows), MAX_EVIDENCE_FLOWS),
                        "evidence_truncated": len(rows) > MAX_EVIDENCE_FLOWS,
                    },
                )
            )

            for issue in issue_types:
                issue_counts[issue] += len(rows)
            affected_ports.add(port)
            affected_services.update(services)

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "unexpected_or_high_risk_port_findings": len(findings),
                "unexpected_protocol_port_flows": issue_counts["unexpected_protocol_port"],
                "high_risk_port_flows": issue_counts["high_risk_port"],
                "affected_ports": len(affected_ports),
                "affected_services": len(affected_services),
            },
            evidence={
                "inspected_logs": ["conn"],
                "expected_service_ports": {
                    service: sorted(ports) for service, ports in sorted(EXPECTED_PORTS.items())
                },
                "high_risk_ports": dict(sorted(HIGH_RISK_PORTS.items())),
                "skipped_missing_destination_port": skipped_missing_port,
                "skipped_no_issue": skipped_no_issue,
                "notes": [
                    "Zeek application identification is used when available; the module does not infer a protocol solely from its destination port.",
                    "Common alternate service ports are included in the expected-port map to reduce false positives.",
                    "High-risk port associations are contextual review indicators, not proof of malware or command-and-control.",
                    "Port-only high-risk matches are low confidence; a Zeek-identified protocol on an unexpected port is high confidence that the unusual protocol/port pairing was observed.",
                ],
            },
            warnings=[],
        )


def _services(value: Any) -> list[str]:
    text = _text(value).lower()
    if not text or text in {"-", "(empty)"}:
        return []
    # Zeek can render service as comma-separated application analyzers.
    raw = text.replace(";", ",").split(",")
    result: list[str] = []
    for item in raw:
        service = item.strip()
        if not service:
            continue
        service = _SERVICE_ALIASES.get(service, service)
        if service not in result:
            result.append(service)
    return result


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
