from __future__ import annotations

from collections import defaultdict
import ipaddress
import re
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata


_UNKNOWN_CA_MARKERS = (
    "unknown ca",
    "unknown issuer",
    "unable to get issuer certificate",
    "unable to get local issuer certificate",
    "unable to verify first certificate",
    "unable to verify the first certificate",
    "certificate verify failed",
    "untrusted",
    "not trusted",
)
_SELF_SIGNED_MARKERS = (
    "self signed certificate",
    "self-signed certificate",
    "self signed certificate in certificate chain",
)
_VALID_STATUSES = {"ok", "valid", "success", "successful"}
_CN_RE = re.compile(r"(?:^|,)\s*CN\s*=\s*([^,]+)", re.IGNORECASE)


class TlsCertificateAnomaliesModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="tls_certificate_anomalies",
        name="TLS Certificate Anomalies",
        description=(
            "Identifies self-signed, expired, hostname-mismatched, weak-key, and unknown/untrusted-CA "
            "TLS certificates using Zeek ssl.log and x509.log when available."
        ),
        category="security_analysis",
        required_logs=(),
        default_enabled=True,
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        ssl_rows = context.ssl
        x509_rows = context.x509
        findings: list[Finding] = []

        sessions_by_fuid = _ssl_rows_by_certificate_fuid(ssl_rows)
        leaf_fuid_by_uid = _leaf_certificate_fuid_by_uid(ssl_rows)

        findings.extend(_self_signed_findings(x509_rows, sessions_by_fuid, ssl_rows))
        findings.extend(_expired_findings(x509_rows, sessions_by_fuid))
        findings.extend(_weak_rsa_key_findings(x509_rows, sessions_by_fuid))
        findings.extend(_name_mismatch_findings(x509_rows, ssl_rows, leaf_fuid_by_uid))
        findings.extend(_unknown_ca_findings(ssl_rows))

        issue_counts: dict[str, int] = defaultdict(int)
        for finding in findings:
            issue_type = str(finding.metadata.get("issue_type") or "other")
            issue_counts[issue_type] += int(
                finding.metadata.get("event_count")
                or finding.metadata.get("certificate_count")
                or 1
            )

        inspected = [name for name in ("ssl", "x509") if context.log(name)]
        skipped = [name for name in ("ssl", "x509") if not context.log(name)]

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "certificate_anomaly_findings": len(findings),
                "affected_tls_sessions": len(
                    {uid for finding in findings for uid in _finding_uids(finding)}
                ),
                "issues_by_type": dict(sorted(issue_counts.items())),
            },
            evidence={
                "inspected_logs": inspected,
                "skipped_logs": skipped,
                "checks": [
                    "self_signed_certificates",
                    "expired_certificates",
                    "certificate_name_mismatch",
                    "weak_rsa_keys_under_2048_bits",
                    "unknown_or_untrusted_ca",
                ],
                "notes": [
                    "Checks are only performed when the relevant Zeek log and fields are present.",
                    "Certificate expiration is evaluated at the certificate observation time, not the current wall clock.",
                    "Hostname validation uses SAN DNS/IP identities when available and falls back to the subject CN only when SAN identities are absent.",
                    "Unknown CA findings require an explicit Zeek validation_status indicating an unknown or untrusted issuer; missing validation status is not treated as an unknown CA.",
                    "Self-signed certificates are identified from matching subject/issuer names or an explicit Zeek validation status.",
                ],
            },
            warnings=[],
        )


def _self_signed_findings(
    x509_rows: list[dict[str, Any]],
    sessions_by_fuid: dict[str, list[dict[str, Any]]],
    ssl_rows: list[dict[str, Any]],
) -> list[Finding]:
    cert_records: list[tuple[dict[str, Any], list[dict[str, Any]]]] = []
    seen_cert_ids: set[str] = set()

    for cert in x509_rows:
        subject = _canonical_dn(cert.get("certificate.subject") or cert.get("subject"))
        issuer = _canonical_dn(cert.get("certificate.issuer") or cert.get("issuer"))
        if subject and issuer and subject == issuer:
            cert_id = _cert_id(cert)
            if cert_id not in seen_cert_ids:
                seen_cert_ids.add(cert_id)
                cert_records.append((cert, sessions_by_fuid.get(cert_id, [])))

    # An explicit validation_status is useful even when the corresponding x509
    # record is not present in the supplied log directory.
    status_rows = [
        row
        for row in ssl_rows
        if any(marker in _validation_status(row) for marker in _SELF_SIGNED_MARKERS)
    ]

    findings: list[Finding] = []
    if cert_records:
        certs = [cert for cert, _ in cert_records]
        sessions = [row for _, rows in cert_records for row in rows]
        findings.append(
            _certificate_finding(
                certs,
                sessions,
                title="Self-signed TLS certificate observed",
                severity="medium",
                summary=f"Observed {len(certs)} self-signed TLS certificate(s).",
                issue_type="self_signed_certificate",
                tags=["tls-certificate", "self-signed"],
            )
        )

    # Avoid a second finding when the same session is already linked to a
    # subject==issuer certificate record.
    covered_uids = {str(row.get("uid")) for _, rows in cert_records for row in rows if row.get("uid")}
    status_only = [row for row in status_rows if str(row.get("uid") or "") not in covered_uids]
    if status_only:
        findings.append(
            _ssl_rows_finding(
                status_only,
                title="Self-signed TLS certificate reported by Zeek",
                severity="medium",
                summary=f"Zeek reported a self-signed certificate for {len(status_only)} TLS session(s).",
                issue_type="self_signed_certificate",
                tags=["tls-certificate", "self-signed"],
                extra={"validation_statuses": sorted({_raw_validation_status(row) for row in status_only})},
            )
        )
    return findings


def _expired_findings(
    x509_rows: list[dict[str, Any]],
    sessions_by_fuid: dict[str, list[dict[str, Any]]],
) -> list[Finding]:
    expired: list[tuple[dict[str, Any], list[dict[str, Any]]]] = []
    for cert in x509_rows:
        observed = _as_float(cert.get("timestamp", cert.get("ts")))
        not_after = _as_float(cert.get("certificate.not_valid_after", cert.get("not_valid_after")))
        if observed is not None and not_after is not None and observed > not_after:
            cert_id = _cert_id(cert)
            expired.append((cert, sessions_by_fuid.get(cert_id, [])))
    if not expired:
        return []
    certs = [cert for cert, _ in expired]
    sessions = [row for _, rows in expired for row in rows]
    return [
        _certificate_finding(
            certs,
            sessions,
            title="Expired TLS certificate observed",
            severity="medium",
            summary=f"Observed {len(certs)} TLS certificate(s) that were expired at the time of observation.",
            issue_type="expired_certificate",
            tags=["tls-certificate", "expired-certificate"],
        )
    ]


def _weak_rsa_key_findings(
    x509_rows: list[dict[str, Any]],
    sessions_by_fuid: dict[str, list[dict[str, Any]]],
) -> list[Finding]:
    weak: list[tuple[dict[str, Any], list[dict[str, Any]]]] = []
    for cert in x509_rows:
        key_alg = str(
            cert.get("certificate.key_alg")
            or cert.get("key_alg")
            or cert.get("certificate.key_type")
            or ""
        ).upper()
        key_length = _as_int(cert.get("certificate.key_length", cert.get("key_length")))
        if "RSA" in key_alg and key_length is not None and key_length < 2048:
            cert_id = _cert_id(cert)
            weak.append((cert, sessions_by_fuid.get(cert_id, [])))
    if not weak:
        return []
    certs = [cert for cert, _ in weak]
    sessions = [row for _, rows in weak for row in rows]
    key_lengths = sorted(
        {
            length
            for cert in certs
            if (length := _as_int(cert.get("certificate.key_length", cert.get("key_length")))) is not None
        }
    )
    return [
        _certificate_finding(
            certs,
            sessions,
            title="TLS certificate uses an undersized RSA key",
            severity="medium",
            summary=f"Observed {len(certs)} TLS certificate(s) using RSA keys smaller than 2048 bits.",
            issue_type="weak_rsa_key",
            tags=["tls-certificate", "weak-key", "rsa"],
            extra={"observed_key_lengths": key_lengths, "minimum_recommended_rsa_bits": 2048},
        )
    ]


def _name_mismatch_findings(
    x509_rows: list[dict[str, Any]],
    ssl_rows: list[dict[str, Any]],
    leaf_fuid_by_uid: dict[str, str],
) -> list[Finding]:
    cert_by_id = {_cert_id(cert): cert for cert in x509_rows if _cert_id(cert)}
    mismatches: list[tuple[dict[str, Any], dict[str, Any], list[str]]] = []

    for session in ssl_rows:
        server_name = str(session.get("server_name") or session.get("sni") or "").strip().rstrip(".")
        uid = str(session.get("uid") or "")
        cert = cert_by_id.get(leaf_fuid_by_uid.get(uid, ""))
        if not server_name or cert is None:
            continue
        identities = _certificate_identities(cert)
        if not identities:
            continue
        if not any(_identity_matches(server_name, identity) for identity in identities):
            mismatches.append((session, cert, identities))

    if not mismatches:
        return []

    sessions = [session for session, _, _ in mismatches]
    certificate_ids = sorted({_cert_id(cert) for _, cert, _ in mismatches if _cert_id(cert)})
    requested_names = sorted({str(session.get("server_name") or session.get("sni")) for session, _, _ in mismatches})
    presented_identities = sorted({identity for _, _, identities in mismatches for identity in identities})
    finding = _ssl_rows_finding(
        sessions,
        title="TLS certificate name mismatch observed",
        severity="medium",
        summary=(
            f"Observed {len(mismatches)} TLS session(s) where the requested server name did not match "
            "the certificate SAN/CN identity."
        ),
        issue_type="certificate_name_mismatch",
        tags=["tls-certificate", "name-mismatch"],
        extra={
            "certificate_ids": certificate_ids,
            "requested_server_names": requested_names,
            "presented_identities": presented_identities,
            "certificates": [_certificate_evidence(cert) for _, cert, _ in mismatches],
        },
    )
    return [finding]


def _unknown_ca_findings(ssl_rows: list[dict[str, Any]]) -> list[Finding]:
    rows: list[dict[str, Any]] = []
    for row in ssl_rows:
        status = _validation_status(row)
        if not status or any(marker in status for marker in _SELF_SIGNED_MARKERS):
            continue
        if any(marker in status for marker in _UNKNOWN_CA_MARKERS):
            rows.append(row)
    if not rows:
        return []
    return [
        _ssl_rows_finding(
            rows,
            title="TLS certificate issued by an unknown or untrusted CA",
            severity="medium",
            summary=f"Zeek reported an unknown or untrusted certificate issuer for {len(rows)} TLS session(s).",
            issue_type="unknown_ca",
            tags=["tls-certificate", "unknown-ca", "untrusted-ca"],
            extra={"validation_statuses": sorted({_raw_validation_status(row) for row in rows})},
        )
    ]


def _certificate_finding(
    certs: list[dict[str, Any]],
    sessions: list[dict[str, Any]],
    *,
    title: str,
    severity: str,
    summary: str,
    issue_type: str,
    tags: list[str],
    extra: dict[str, Any] | None = None,
) -> Finding:
    devices, ports, pairs, timestamps = _tls_provenance(sessions)
    cert_timestamps = [
        value
        for cert in certs
        if (value := cert.get("timestamp", cert.get("ts"))) not in (None, "")
    ]
    metadata: dict[str, Any] = {
        "issue_type": issue_type,
        "certificate_count": len(certs),
        "certificate_ids": sorted({_cert_id(cert) for cert in certs if _cert_id(cert)}),
        "certificates": [_certificate_evidence(cert) for cert in certs],
    }
    if extra:
        metadata.update(extra)
    return Finding(
        title=title,
        severity=severity,
        summary=summary,
        confidence="high",
        detection_basis="protocol_log",
        devices=devices,
        services=["TLS/SSL"],
        ports=ports,
        connection_pairs=pairs,
        flows=[_sanitize(row) for row in sessions],
        timestamps=timestamps or cert_timestamps,
        tags=tags,
        metadata=metadata,
    )


def _ssl_rows_finding(
    rows: list[dict[str, Any]],
    *,
    title: str,
    severity: str,
    summary: str,
    issue_type: str,
    tags: list[str],
    extra: dict[str, Any] | None = None,
) -> Finding:
    devices, ports, pairs, timestamps = _tls_provenance(rows)
    metadata: dict[str, Any] = {"issue_type": issue_type, "event_count": len(rows)}
    if extra:
        metadata.update(extra)
    return Finding(
        title=title,
        severity=severity,
        summary=summary,
        confidence="high",
        detection_basis="protocol_log",
        devices=devices,
        services=["TLS/SSL"],
        ports=ports,
        connection_pairs=pairs,
        flows=[_sanitize(row) for row in rows],
        timestamps=timestamps,
        tags=tags,
        metadata=metadata,
    )


def _ssl_rows_by_certificate_fuid(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    mapping: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        for fuid in _split_zeek_collection(row.get("cert_chain_fuids")):
            mapping[fuid].append(row)
        for fuid in _split_zeek_collection(row.get("client_cert_chain_fuids")):
            mapping[fuid].append(row)
    return mapping


def _leaf_certificate_fuid_by_uid(rows: list[dict[str, Any]]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for row in rows:
        uid = str(row.get("uid") or "")
        fuids = _split_zeek_collection(row.get("cert_chain_fuids"))
        if uid and fuids:
            mapping[uid] = fuids[0]
    return mapping


def _certificate_identities(cert: dict[str, Any]) -> list[str]:
    dns_names = _split_zeek_collection(
        cert.get("san.dns")
        or cert.get("certificate.san.dns")
        or cert.get("san_dns")
    )
    ip_names = _split_zeek_collection(
        cert.get("san.ip")
        or cert.get("certificate.san.ip")
        or cert.get("san_ip")
    )
    san_identities = [value.strip().rstrip(".") for value in dns_names + ip_names if value]
    if san_identities:
        return _unique(san_identities)
    subject = str(cert.get("certificate.subject") or cert.get("subject") or "")
    match = _CN_RE.search(subject)
    return [match.group(1).strip().rstrip(".")] if match else []


def _identity_matches(server_name: str, identity: str) -> bool:
    server = server_name.lower().strip().rstrip(".")
    candidate = identity.lower().strip().rstrip(".")
    if not server or not candidate:
        return False

    try:
        server_ip = ipaddress.ip_address(server)
    except ValueError:
        server_ip = None
    try:
        candidate_ip = ipaddress.ip_address(candidate)
    except ValueError:
        candidate_ip = None
    if server_ip is not None or candidate_ip is not None:
        return server_ip is not None and candidate_ip is not None and server_ip == candidate_ip

    if candidate.startswith("*."):
        suffix = candidate[2:]
        server_labels = server.split(".")
        suffix_labels = suffix.split(".")
        return len(server_labels) == len(suffix_labels) + 1 and server_labels[1:] == suffix_labels
    return server == candidate


def _canonical_dn(value: Any) -> str:
    return re.sub(r"\s+", "", str(value or "")).lower()


def _raw_validation_status(row: dict[str, Any]) -> str:
    return str(row.get("validation_status") or "").strip()


def _validation_status(row: dict[str, Any]) -> str:
    return _raw_validation_status(row).lower()


def _cert_id(cert: dict[str, Any]) -> str:
    return str(cert.get("id") or cert.get("fuid") or "")


def _tls_provenance(rows: list[dict[str, Any]]) -> tuple[list[str], list[int], list[dict[str, Any]], list[float | str]]:
    devices: list[str] = []
    ports: list[int] = []
    pairs: list[dict[str, Any]] = []
    timestamps: list[float | str] = []
    seen_pairs: set[tuple[str, str, int | None]] = set()
    for row in rows:
        source = str(row.get("source_ip", row.get("id.orig_h")) or "")
        destination = str(row.get("destination_ip", row.get("id.resp_h")) or "")
        port = _as_int(row.get("destination_port", row.get("id.resp_p")))
        if source:
            devices.append(source)
        if destination:
            devices.append(destination)
        if port is not None:
            ports.append(port)
        key = (source, destination, port)
        if key not in seen_pairs:
            seen_pairs.add(key)
            pairs.append(
                {
                    "source": source,
                    "destination": destination,
                    "port": port,
                    "protocol": "tcp",
                    "service": "TLS/SSL",
                }
            )
        ts = row.get("timestamp", row.get("ts"))
        if ts not in (None, ""):
            timestamps.append(ts)
    return _unique(devices), sorted(set(ports)), pairs, timestamps


def _split_zeek_collection(value: Any) -> list[str]:
    if value in (None, "", "-"):
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value if item not in (None, "")]
    text = str(value).strip()
    if not text:
        return []
    return [part.strip() for part in text.split(",") if part.strip()]


def _certificate_evidence(cert: dict[str, Any]) -> dict[str, Any]:
    wanted = (
        "id",
        "fuid",
        "certificate.subject",
        "certificate.issuer",
        "certificate.not_valid_before",
        "certificate.not_valid_after",
        "certificate.key_alg",
        "certificate.key_type",
        "certificate.key_length",
        "certificate.sig_alg",
        "san.dns",
        "san.ip",
        "certificate.san.dns",
        "certificate.san.ip",
    )
    return {key: cert.get(key) for key in wanted if key in cert}


def _finding_uids(finding: Finding) -> set[str]:
    return {str(flow.get("uid")) for flow in finding.flows if flow.get("uid")}


def _sanitize(row: dict[str, Any]) -> dict[str, Any]:
    blocked = {"password", "passwd", "auth_password", "authorization", "cookie"}
    return {key: value for key, value in row.items() if key.lower() not in blocked}


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


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))
