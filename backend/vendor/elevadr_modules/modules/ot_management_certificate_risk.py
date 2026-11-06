from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata


DEFAULT_LONG_VALIDITY_DAYS = 1095.0
DEFAULT_MANAGEMENT_PORTS = (443, 8443, 9443, 10443)
MAX_EVIDENCE_SESSIONS = 10
OT_ROLE_TOKENS = {"ot", "control", "ics", "scada", "operations", "industrial", "process"}


@dataclass(slots=True)
class _Segment:
    cidr: str
    name: str
    role: str
    network: ipaddress._BaseNetwork


class OtManagementCertificateRiskModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="ot_management_certificate_risk",
        name="Certificate Long Validity / Self-Issued in OT Mgmt",
        description=(
            "Identifies long-validity and self-issued TLS certificates presented by configured OT management endpoints."
        ),
        category="security_analysis",
        required_logs=(),
        required_any_logs=("ssl", "x509"),
        default_enabled=True,
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        policy = _policy(context.metadata)
        segments = _load_segments(context.metadata)
        ot_segments = [segment for segment in segments if _is_ot_role(segment.role)]

        if not ot_segments and not policy["management_hosts"]:
            return _empty_result(
                self.metadata.id,
                policy,
                segments,
                note=(
                    "No configured OT/control segments or explicit management hosts were found; "
                    "OT management endpoints are not inferred from private addressing alone."
                ),
            )

        ssl_by_uid = {str(row.get("uid") or ""): row for row in context.ssl if row.get("uid")}
        cert_by_fuid = {_cert_id(row): row for row in context.x509 if _cert_id(row)}

        sessions_evaluated = 0
        certs_evaluated = 0
        findings: list[Finding] = []
        seen_cert_host: set[tuple[str, str]] = set()

        for session in context.ssl:
            host = _text(session.get("destination_ip", session.get("id.resp_h")))
            port = _as_int(session.get("destination_port", session.get("id.resp_p")))
            if not host or not _is_management_endpoint(host, port, ot_segments, policy):
                continue
            sessions_evaluated += 1
            leaf = _leaf_fuid(session)
            cert = cert_by_fuid.get(leaf)
            if cert is None:
                continue
            key = (host, leaf or _cert_id(cert))
            if key in seen_cert_host:
                continue
            seen_cert_host.add(key)
            certs_evaluated += 1
            issues = _certificate_issues(cert, policy)
            if not issues:
                continue
            related_sessions = [
                row
                for row in context.ssl
                if _text(row.get("destination_ip", row.get("id.resp_h"))) == host
                and _leaf_fuid(row) == leaf
            ]
            findings.append(_finding(host, cert, related_sessions or [session], issues, policy, ot_segments))

        # If only x509.log exists, endpoint attribution is not reliable because
        # standard x509.log rows do not carry the server IP/port. Do not guess.
        skipped_x509_without_ssl = bool(context.x509 and not context.ssl)

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "certificate_risk_findings": len(findings),
                "management_tls_sessions_evaluated": sessions_evaluated,
                "management_certificates_evaluated": certs_evaluated,
                "self_issued_findings": sum("self_issued" in f.metadata.get("issue_types", []) for f in findings),
                "long_validity_findings": sum("long_validity" in f.metadata.get("issue_types", []) for f in findings),
            },
            evidence={
                "inspected_logs": [name for name in ("ssl", "x509") if context.log(name)],
                "segments_loaded": len(segments),
                "ot_segments_loaded": len(ot_segments),
                "thresholds": {
                    "long_validity_days": policy["long_validity_days"],
                    "management_ports": policy["management_ports"],
                },
                "explicit_management_hosts": policy["management_hosts"],
                "skipped_x509_without_ssl": skipped_x509_without_ssl,
                "notes": [
                    "The detector requires TLS session attribution to an OT management endpoint; x509.log alone is not enough to identify the serving host.",
                    "Self-issued means the certificate subject and issuer distinguished names are identical after normalization.",
                    "Long validity is calculated from certificate.not_valid_before to certificate.not_valid_after and defaults to more than three years.",
                    "An OT management endpoint is an explicit management host, or an OT responder on a configured management HTTPS port.",
                ],
            },
            warnings=[],
        )


def _certificate_issues(cert: dict[str, Any], policy: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    subject = _canonical_dn(cert.get("certificate.subject") or cert.get("subject"))
    issuer = _canonical_dn(cert.get("certificate.issuer") or cert.get("issuer"))
    if subject and issuer and subject == issuer:
        issues.append("self_issued")

    not_before = _as_float(cert.get("certificate.not_valid_before", cert.get("not_valid_before")))
    not_after = _as_float(cert.get("certificate.not_valid_after", cert.get("not_valid_after")))
    if not_before is not None and not_after is not None and not_after >= not_before:
        validity_days = (not_after - not_before) / 86400.0
        if validity_days > policy["long_validity_days"]:
            issues.append("long_validity")
    return issues


def _finding(
    host: str,
    cert: dict[str, Any],
    sessions: list[dict[str, Any]],
    issues: list[str],
    policy: dict[str, Any],
    ot_segments: list[_Segment],
) -> Finding:
    subject = _text(cert.get("certificate.subject") or cert.get("subject"))
    issuer = _text(cert.get("certificate.issuer") or cert.get("issuer"))
    not_before = _as_float(cert.get("certificate.not_valid_before", cert.get("not_valid_before")))
    not_after = _as_float(cert.get("certificate.not_valid_after", cert.get("not_valid_after")))
    validity_days = None
    if not_before is not None and not_after is not None and not_after >= not_before:
        validity_days = round((not_after - not_before) / 86400.0, 2)

    ports = sorted({p for row in sessions if (p := _as_int(row.get("destination_port", row.get("id.resp_p")))) is not None})
    peers = sorted({_text(row.get("source_ip", row.get("id.orig_h"))) for row in sessions if _text(row.get("source_ip", row.get("id.orig_h")))})
    timestamps = [t for row in sessions[:MAX_EVIDENCE_SESSIONS] if (t := row.get("timestamp", row.get("ts"))) is not None]
    segment = _segment_for_ip(host, ot_segments)

    if set(issues) == {"self_issued", "long_validity"}:
        severity = "high"
        title = f"Self-issued, long-validity certificate on OT management endpoint {host}"
    elif "self_issued" in issues:
        severity = "medium"
        title = f"Self-issued certificate on OT management endpoint {host}"
    else:
        severity = "medium"
        title = f"Long-validity certificate on OT management endpoint {host}"

    explicit_host = host in policy["management_hosts"]
    confidence = "high" if explicit_host else "medium"
    issue_text = " and ".join(issue.replace("_", " ") for issue in issues)
    validity_text = f" with a validity period of {validity_days} days" if validity_days is not None else ""

    return Finding(
        title=title,
        severity=severity,
        confidence=confidence,
        detection_basis="protocol_log",
        summary=(
            f"OT management endpoint {host} presented a TLS certificate with {issue_text}{validity_text}. "
            "This certificate characteristic can indicate weak certificate lifecycle controls on management interfaces."
        ),
        devices=[host] + peers[:25],
        services=["tls", "https"],
        ports=ports,
        connection_pairs=[{"source": peer, "destination": host, "port": ports[0] if ports else None, "protocol": "tcp"} for peer in peers[:25]],
        flows=sessions[:MAX_EVIDENCE_SESSIONS],
        subnets=[segment.cidr] if segment else [],
        timestamps=timestamps,
        tags=["ot", "management", "tls-certificate"] + [issue.replace("_", "-") for issue in issues],
        metadata={
            "issue_types": issues,
            "certificate_id": _cert_id(cert),
            "subject": subject,
            "issuer": issuer,
            "not_valid_before": not_before,
            "not_valid_after": not_after,
            "validity_days": validity_days,
            "long_validity_threshold_days": policy["long_validity_days"],
            "management_host_explicitly_configured": explicit_host,
            "ot_segment": segment.name if segment else None,
            "session_count": len(sessions),
            "evidence_truncated": len(sessions) > MAX_EVIDENCE_SESSIONS,
        },
    )


def _policy(metadata: dict[str, Any]) -> dict[str, Any]:
    raw = metadata.get("ot_certificate_policy") or metadata.get("certificate_management_policy") or {}
    if not isinstance(raw, dict):
        raw = {}
    threshold = _as_float(raw.get("long_validity_days"))
    if threshold is None or threshold <= 0:
        threshold = DEFAULT_LONG_VALIDITY_DAYS
    ports_raw = raw.get("management_ports", DEFAULT_MANAGEMENT_PORTS)
    ports = sorted({p for item in _as_list(ports_raw) if (p := _as_int(item)) is not None and 1 <= p <= 65535})
    if not ports:
        ports = list(DEFAULT_MANAGEMENT_PORTS)
    hosts = sorted({_text(item) for item in _as_list(raw.get("management_hosts")) if _text(item)})
    return {
        "long_validity_days": float(threshold),
        "management_ports": ports,
        "management_hosts": hosts,
    }


def _is_management_endpoint(host: str, port: int | None, ot_segments: list[_Segment], policy: dict[str, Any]) -> bool:
    if host in policy["management_hosts"]:
        return port is None or port in policy["management_ports"]
    return _segment_for_ip(host, ot_segments) is not None and port in policy["management_ports"]


def _load_segments(metadata: dict[str, Any]) -> list[_Segment]:
    raw = metadata.get("segments")
    if not isinstance(raw, list):
        return []
    segments: list[_Segment] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        cidr = _text(item.get("cidr") or item.get("subnet") or item.get("network"))
        if not cidr:
            continue
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        segments.append(
            _Segment(
                cidr=str(network),
                name=_text(item.get("name")) or str(network),
                role=_text(item.get("role") or item.get("zone") or item.get("type")),
                network=network,
            )
        )
    return segments


def _segment_for_ip(value: str, segments: list[_Segment]) -> _Segment | None:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    matches = [segment for segment in segments if address in segment.network]
    return max(matches, key=lambda segment: segment.network.prefixlen) if matches else None


def _is_ot_role(role: str) -> bool:
    text = role.lower().replace("_", " ").replace("-", " ")
    tokens = set(text.split())
    return bool(tokens & OT_ROLE_TOKENS)


def _leaf_fuid(row: dict[str, Any]) -> str:
    value = row.get("cert_chain_fuids")
    values = _as_list(value)
    return _text(values[0]) if values else ""


def _cert_id(cert: dict[str, Any]) -> str:
    return _text(cert.get("id") or cert.get("fuid"))


def _canonical_dn(value: Any) -> str:
    text = _text(value)
    return "".join(text.lower().split())


def _as_list(value: Any) -> list[Any]:
    if value is None or value == "":
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    if isinstance(value, str):
        if "," in value:
            return [part.strip() for part in value.split(",") if part.strip()]
        return [value]
    return [value]


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _as_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _empty_result(module_id: str, policy: dict[str, Any], segments: list[_Segment], *, note: str) -> ModuleResult:
    return ModuleResult(
        module_id=module_id,
        findings=[],
        metrics={
            "certificate_risk_findings": 0,
            "management_tls_sessions_evaluated": 0,
            "management_certificates_evaluated": 0,
            "self_issued_findings": 0,
            "long_validity_findings": 0,
        },
        evidence={
            "inspected_logs": [],
            "segments_loaded": len(segments),
            "thresholds": {
                "long_validity_days": policy["long_validity_days"],
                "management_ports": policy["management_ports"],
            },
            "notes": [note],
        },
        warnings=[],
    )
