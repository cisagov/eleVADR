from __future__ import annotations

from collections import defaultdict
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata


_DEPRECATED_VERSIONS: dict[str, tuple[str, str]] = {
    "sslv2": ("SSLv2", "high"),
    "sslv3": ("SSLv3", "high"),
    "tlsv1": ("TLS 1.0", "medium"),
    "tlsv10": ("TLS 1.0", "medium"),
    "tlsv1.0": ("TLS 1.0", "medium"),
    "tlsv11": ("TLS 1.1", "medium"),
    "tlsv1.1": ("TLS 1.1", "medium"),
}

# These patterns intentionally focus on clearly obsolete/broken choices. Modern
# suites such as AES-GCM/ChaCha20 are not flagged.
_WEAK_CIPHER_PATTERNS: tuple[tuple[str, str, str], ...] = (
    ("NULL", "NULL encryption", "high"),
    ("EXPORT", "export-grade cipher", "high"),
    ("RC4", "RC4", "high"),
    ("3DES", "3DES", "medium"),
    ("DES_", "DES", "medium"),
    ("_DES", "DES", "medium"),
    ("IDEA", "IDEA", "medium"),
    ("SEED", "SEED", "medium"),
    ("_ADH_", "anonymous Diffie-Hellman", "high"),
    ("_AECDH_", "anonymous ECDH", "high"),
    ("ANON", "anonymous key exchange", "high"),
)


class WeakBrokenTlsSslModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="weak_broken_tls_ssl",
        name="Weak or Broken TLS/SSL",
        description=(
            "Identifies deprecated SSL/TLS versions, weak cipher suites, and weak certificate signature algorithms "
            "when the relevant Zeek logs are present."
        ),
        category="security_analysis",
        required_logs=(),
        default_enabled=True,
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        ssl_rows = context.ssl
        x509_rows = context.x509
        findings: list[Finding] = []

        findings.extend(_version_findings(ssl_rows))
        findings.extend(_cipher_findings(ssl_rows))
        findings.extend(_weak_signature_findings(x509_rows, ssl_rows))

        issue_counts: dict[str, int] = defaultdict(int)
        for finding in findings:
            issue_counts[str(finding.metadata.get("issue_type") or "other")] += int(
                finding.metadata.get("event_count") or finding.metadata.get("certificate_count") or 1
            )

        inspected = [name for name in ("ssl", "x509") if context.log(name)]
        skipped = [name for name in ("ssl", "x509") if not context.log(name)]

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "weak_or_broken_tls_findings": len(findings),
                "affected_tls_sessions": len({uid for finding in findings for uid in _finding_uids(finding)}),
                "issues_by_type": dict(sorted(issue_counts.items())),
            },
            evidence={
                "inspected_logs": inspected,
                "skipped_logs": skipped,
                "checks": [
                    "deprecated_protocol_versions",
                    "weak_cipher_suites",
                    "weak_certificate_signature_algorithms",
                ],
                "notes": [
                    "Checks are only performed when the relevant Zeek log is present.",
                    "Certificate trust, validity, hostname, and key-size anomalies are handled by the tls_certificate_anomalies module to avoid duplicate findings.",
                ],
            },
            warnings=[],
        )


def _version_findings(rows: list[dict[str, Any]]) -> list[Finding]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    meta: dict[str, tuple[str, str]] = {}
    for row in rows:
        raw = str(row.get("version") or row.get("ssl_version") or "").strip()
        key = raw.lower().replace(" ", "").replace("_", "")
        match = _DEPRECATED_VERSIONS.get(key)
        if match:
            label, severity = match
            grouped[label].append(row)
            meta[label] = (label, severity)

    findings: list[Finding] = []
    for label, matched in sorted(grouped.items()):
        severity = meta[label][1]
        findings.append(
            _tls_rows_finding(
                matched,
                title=f"Deprecated TLS/SSL protocol observed: {label}",
                severity=severity,
                summary=(
                    f"Observed {len(matched)} TLS/SSL session(s) using {label}. "
                    "This protocol version is deprecated and should be replaced with a currently supported TLS version."
                ),
                services=[label],
                tags=["weak-tls", "deprecated-protocol", label.lower().replace(" ", "-")],
                metadata={"issue_type": "deprecated_protocol_version", "protocol_version": label, "event_count": len(matched)},
            )
        )
    return findings


def _cipher_findings(rows: list[dict[str, Any]]) -> list[Finding]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        cipher = str(row.get("cipher") or row.get("cipher_suite") or "").strip()
        if not cipher:
            continue
        upper = cipher.upper()
        match = next(((label, sev) for pattern, label, sev in _WEAK_CIPHER_PATTERNS if pattern in upper), None)
        if match:
            label, severity = match
            grouped[(label, severity)].append(row)

    findings: list[Finding] = []
    for (label, severity), matched in sorted(grouped.items()):
        ciphers = sorted({str(row.get("cipher") or row.get("cipher_suite") or "") for row in matched})
        findings.append(
            _tls_rows_finding(
                matched,
                title=f"Weak TLS/SSL cipher observed: {label}",
                severity=severity,
                summary=f"Observed {len(matched)} TLS/SSL session(s) negotiating a weak or obsolete cipher family: {label}.",
                services=["TLS/SSL"],
                tags=["weak-tls", "weak-cipher"],
                metadata={"issue_type": "weak_cipher", "cipher_family": label, "ciphers": ciphers, "event_count": len(matched)},
            )
        )
    return findings


def _weak_signature_findings(x509_rows: list[dict[str, Any]], ssl_rows: list[dict[str, Any]]) -> list[Finding]:
    if not x509_rows:
        return []
    ssl_by_fuid = _ssl_rows_by_certificate_fuid(ssl_rows)
    issue_rows: dict[tuple[str, str], list[tuple[dict[str, Any], list[dict[str, Any]]]]] = defaultdict(list)

    for cert in x509_rows:
        cert_id = str(cert.get("id") or cert.get("fuid") or "")
        sessions = ssl_by_fuid.get(cert_id, [])
        sig_alg = str(cert.get("certificate.sig_alg") or cert.get("sig_alg") or "").lower()
        if "md5" in sig_alg:
            issue_rows[("weak_signature_md5", "high")].append((cert, sessions))
        elif "sha1" in sig_alg or "sha-1" in sig_alg:
            issue_rows[("weak_signature_sha1", "medium")].append((cert, sessions))

    labels = {
        "weak_signature_md5": "Certificate signed with MD5",
        "weak_signature_sha1": "Certificate signed with SHA-1",
    }
    findings: list[Finding] = []
    for (issue_type, severity), records in sorted(issue_rows.items()):
        certs = [cert for cert, _ in records]
        sessions = [row for _, session_rows in records for row in session_rows]
        devices, ports, pairs, timestamps = _tls_provenance(sessions)
        cert_ids = sorted({str(cert.get("id") or cert.get("fuid") or "") for cert in certs if cert.get("id") or cert.get("fuid")})
        findings.append(
            Finding(
                title=labels[issue_type],
                severity=severity,
                summary=f"Observed {len(certs)} certificate(s) using a weak signature algorithm.",
                confidence="high",
                detection_basis="protocol_log",
                devices=devices,
                services=["TLS/SSL"],
                ports=ports,
                connection_pairs=pairs,
                flows=[_sanitize(row) for row in sessions] if sessions else [],
                timestamps=timestamps or [value for cert in certs if (value := cert.get("timestamp", cert.get("ts"))) not in (None, "")],
                tags=["weak-tls", "certificate-signature", issue_type.replace("_", "-")],
                metadata={
                    "issue_type": issue_type,
                    "certificate_count": len(certs),
                    "certificate_ids": cert_ids,
                    "certificates": [_certificate_evidence(cert) for cert in certs],
                },
            )
        )
    return findings


def _tls_rows_finding(
    rows: list[dict[str, Any]],
    *,
    title: str,
    severity: str,
    summary: str,
    services: list[str],
    tags: list[str],
    metadata: dict[str, Any],
) -> Finding:
    devices, ports, pairs, timestamps = _tls_provenance(rows)
    return Finding(
        title=title,
        severity=severity,
        summary=summary,
        confidence="high",
        detection_basis="protocol_log",
        devices=devices,
        services=services,
        ports=ports,
        connection_pairs=pairs,
        flows=[_sanitize(row) for row in rows],
        timestamps=timestamps,
        tags=tags,
        metadata=metadata,
    )


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
            pairs.append({"source": source, "destination": destination, "port": port, "protocol": "tcp", "service": "TLS/SSL"})
        ts = row.get("timestamp", row.get("ts"))
        if ts not in (None, ""):
            timestamps.append(ts)
    return _unique(devices), sorted(set(ports)), pairs, timestamps


def _ssl_rows_by_certificate_fuid(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    mapping: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        for field in ("cert_chain_fuids", "client_cert_chain_fuids"):
            value = row.get(field)
            for fuid in _split_zeek_collection(value):
                mapping[fuid].append(row)
    return mapping


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
