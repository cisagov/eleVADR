from __future__ import annotations

from collections import defaultdict
import ipaddress
import re
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata


_CN_RE = re.compile(r"(?:^|,)\s*CN\s*=\s*([^,]+)", re.IGNORECASE)
_MAX_EVIDENCE = 10


class TlsSniCertificateReuseModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="tls_sni_certificate_reuse",
        name="TLS SNI Mismatch / Certificate Reuse Across Hosts",
        description=(
            "Detects TLS sessions whose SNI/server identity does not match the presented certificate "
            "and certificates reused broadly across unrelated server hosts/domains."
        ),
        category="security_analysis",
        required_logs=(),
        required_any_logs=("ssl", "x509"),
        default_enabled=True,
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        ssl_rows = context.ssl
        x509_rows = context.x509
        cert_by_fuid = {_cert_fuid(row): row for row in x509_rows if _cert_fuid(row)}
        leaf_by_uid = _leaf_cert_by_uid(ssl_rows)
        findings: list[Finding] = []

        mismatch_rows: list[tuple[dict[str, Any], dict[str, Any], list[str], str]] = []
        for session in ssl_rows:
            uid = str(session.get("uid") or "")
            cert = cert_by_fuid.get(leaf_by_uid.get(uid, ""))
            if cert is None:
                continue
            identities = _certificate_identities(cert)
            if not identities:
                continue

            sni = str(session.get("server_name") or session.get("sni") or "").strip().rstrip(".")
            server_ip = str(session.get("destination_ip") or session.get("id.resp_h") or "").strip()
            if sni:
                if not any(_identity_matches(sni, identity) for identity in identities):
                    mismatch_rows.append((session, cert, identities, "sni_certificate_mismatch"))
            else:
                # Only compare an IP destination to the certificate when the certificate actually
                # contains IP SAN identities. A DNS-only certificate routinely terminates at an IP.
                ip_identities = [identity for identity in identities if _is_ip(identity)]
                if server_ip and ip_identities and not any(_identity_matches(server_ip, identity) for identity in ip_identities):
                    mismatch_rows.append((session, cert, ip_identities, "server_ip_certificate_mismatch"))

        if mismatch_rows:
            findings.append(_mismatch_finding(mismatch_rows))

        reuse_groups: dict[str, list[tuple[dict[str, Any], dict[str, Any]]]] = defaultdict(list)
        for session in ssl_rows:
            uid = str(session.get("uid") or "")
            cert = cert_by_fuid.get(leaf_by_uid.get(uid, ""))
            if cert is None:
                continue
            reuse_groups[_certificate_key(cert)].append((session, cert))

        for cert_key, records in reuse_groups.items():
            servers = {
                str(row.get("destination_ip") or row.get("id.resp_h") or "").strip()
                for row, _ in records
                if str(row.get("destination_ip") or row.get("id.resp_h") or "").strip()
            }
            snis = {
                str(row.get("server_name") or row.get("sni") or "").strip().lower().rstrip(".")
                for row, _ in records
                if str(row.get("server_name") or row.get("sni") or "").strip()
            }
            domains = {_base_domain(name) for name in snis if _base_domain(name)}
            if len(servers) < 5 or len(domains) < 3:
                continue
            findings.append(_reuse_finding(cert_key, records, servers, snis, domains))

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "tls_sessions_evaluated": len(ssl_rows),
                "certificate_records_evaluated": len(x509_rows),
                "identity_mismatch_events": len(mismatch_rows),
                "certificate_reuse_findings": sum(1 for f in findings if f.metadata.get("issue_type") == "certificate_reuse_across_unrelated_hosts"),
                "tls_identity_findings": len(findings),
                "affected_devices": len({device for finding in findings for device in finding.devices}),
            },
            evidence={
                "inspected_logs": [name for name in ("ssl", "x509") if context.log(name)],
                "skipped_logs": [name for name in ("ssl", "x509") if not context.log(name)],
                "notes": [
                    "SNI mismatch findings require a presented certificate linked from ssl.log to x509.log; the detector does not infer certificate identity from port 443.",
                    "When SNI is absent, server-IP comparison is only performed if the certificate explicitly contains IP SAN values; DNS certificates are not expected to match a numeric server IP.",
                    "Wildcard DNS SAN/CN identities are matched for exactly one label, consistent with normal TLS hostname matching expectations.",
                    "Certificate-reuse findings require at least five distinct server IPs and three distinct approximate base domains using the same observed certificate.",
                    "Broad certificate reuse can be legitimate for CDNs, reverse proxies, load balancers, shared hosting, or enterprise TLS inspection; reuse findings are anomaly indicators rather than proof of interception.",
                    "Rendered evidence is capped at 10 representative TLS sessions while full counts remain in finding metadata.",
                ],
                "reuse_policy": {
                    "minimum_distinct_server_ips": 5,
                    "minimum_distinct_base_domains": 3,
                },
            },
            warnings=[],
        )


def _mismatch_finding(records: list[tuple[dict[str, Any], dict[str, Any], list[str], str]]) -> Finding:
    rows = [row for row, _, _, _ in records]
    devices, ports, pairs, timestamps = _provenance(rows[:_MAX_EVIDENCE])
    requested = sorted({str(row.get("server_name") or row.get("sni") or row.get("destination_ip") or row.get("id.resp_h") or "") for row in rows})
    identities = sorted({identity for _, _, ids, _ in records for identity in ids})
    reasons = sorted({reason for _, _, _, reason in records})
    return Finding(
        title=f"TLS SNI/certificate identity mismatch ({len(records)} session{'s' if len(records) != 1 else ''})",
        severity="medium",
        summary=(
            f"Observed {len(records)} TLS session(s) where the requested SNI or explicit server-IP identity did not match the presented certificate SAN/CN. "
            "This can indicate misconfiguration, interception, a stale certificate, or traffic reaching an unexpected TLS endpoint."
        ),
        confidence="high",
        detection_basis="protocol_log",
        devices=devices,
        services=["TLS/SSL"],
        ports=ports,
        connection_pairs=pairs,
        flows=[_sanitize(row) for row in rows[:_MAX_EVIDENCE]],
        timestamps=timestamps,
        tags=["tls", "sni-mismatch", "certificate-identity"],
        metadata={
            "issue_type": "tls_sni_certificate_mismatch",
            "event_count": len(records),
            "requested_identities": requested,
            "presented_identities": identities,
            "mismatch_reasons": reasons,
            "certificate_ids": sorted({_certificate_key(cert) for _, cert, _, _ in records}),
            "evidence_event_count": min(len(records), _MAX_EVIDENCE),
            "evidence_truncated": len(records) > _MAX_EVIDENCE,
        },
    )


def _reuse_finding(
    cert_key: str,
    records: list[tuple[dict[str, Any], dict[str, Any]]],
    servers: set[str],
    snis: set[str],
    domains: set[str],
) -> Finding:
    rows = [row for row, _ in records]
    devices, ports, pairs, timestamps = _provenance(rows[:_MAX_EVIDENCE])
    cert = records[0][1]
    return Finding(
        title=f"TLS certificate reused across unrelated hosts ({len(servers)} server IPs)",
        severity="low",
        summary=(
            f"The same observed TLS certificate was presented by {len(servers)} distinct server IPs for {len(domains)} unrelated requested domain groups. "
            "This may be legitimate shared infrastructure, but unusually broad reuse can also be consistent with TLS interception, cloned appliances, or certificate deployment errors."
        ),
        confidence="medium",
        detection_basis="derived",
        devices=devices,
        services=["TLS/SSL"],
        ports=ports,
        connection_pairs=pairs,
        flows=[_sanitize(row) for row in rows[:_MAX_EVIDENCE]],
        timestamps=timestamps,
        tags=["tls", "certificate-reuse", "shared-certificate"],
        metadata={
            "issue_type": "certificate_reuse_across_unrelated_hosts",
            "event_count": len(records),
            "certificate_id": cert_key,
            "certificate_subject": cert.get("certificate.subject") or cert.get("subject"),
            "certificate_issuer": cert.get("certificate.issuer") or cert.get("issuer"),
            "distinct_server_ip_count": len(servers),
            "server_ips": sorted(servers),
            "distinct_sni_count": len(snis),
            "server_names": sorted(snis),
            "distinct_base_domain_count": len(domains),
            "base_domains": sorted(domains),
            "interception_confirmed": False,
            "evidence_event_count": min(len(records), _MAX_EVIDENCE),
            "evidence_truncated": len(records) > _MAX_EVIDENCE,
        },
    )


def _leaf_cert_by_uid(rows: list[dict[str, Any]]) -> dict[str, str]:
    result: dict[str, str] = {}
    for row in rows:
        uid = str(row.get("uid") or "")
        fuids = _split_collection(row.get("cert_chain_fuids"))
        if uid and fuids:
            result[uid] = fuids[0]
    return result


def _certificate_identities(cert: dict[str, Any]) -> list[str]:
    dns_names = _split_collection(cert.get("san.dns") or cert.get("certificate.san.dns") or cert.get("san_dns"))
    ip_names = _split_collection(cert.get("san.ip") or cert.get("certificate.san.ip") or cert.get("san_ip"))
    sans = [value.strip().rstrip(".") for value in dns_names + ip_names if value]
    if sans:
        return _unique(sans)
    subject = str(cert.get("certificate.subject") or cert.get("subject") or "")
    match = _CN_RE.search(subject)
    return [match.group(1).strip().rstrip(".")] if match else []


def _certificate_key(cert: dict[str, Any]) -> str:
    for key in ("fingerprint", "certificate.fingerprint", "sha256", "certificate.sha256", "sha1", "certificate.sha1"):
        value = str(cert.get(key) or "").strip()
        if value:
            return f"fingerprint:{value.lower()}"
    serial = str(cert.get("certificate.serial") or cert.get("serial") or "").strip()
    issuer = str(cert.get("certificate.issuer") or cert.get("issuer") or "").strip()
    subject = str(cert.get("certificate.subject") or cert.get("subject") or "").strip()
    if serial and issuer:
        return f"serial:{serial}|issuer:{issuer.lower()}"
    if subject and issuer:
        return f"subject:{subject.lower()}|issuer:{issuer.lower()}"
    return f"fuid:{_cert_fuid(cert)}"


def _cert_fuid(cert: dict[str, Any]) -> str:
    return str(cert.get("id") or cert.get("fuid") or "")


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
        suffix = candidate[2:].split(".")
        labels = server.split(".")
        return len(labels) == len(suffix) + 1 and labels[1:] == suffix
    return server == candidate


def _base_domain(name: str) -> str:
    if not name or _is_ip(name):
        return ""
    labels = name.lower().rstrip(".").split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else name.lower()


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _provenance(rows: list[dict[str, Any]]) -> tuple[list[str], list[int], list[dict[str, Any]], list[float | str]]:
    devices: list[str] = []
    ports: set[int] = set()
    pairs: list[dict[str, Any]] = []
    timestamps: list[float | str] = []
    seen: set[tuple[str, str, int | None]] = set()
    for row in rows:
        source = str(row.get("source_ip") or row.get("id.orig_h") or "")
        destination = str(row.get("destination_ip") or row.get("id.resp_h") or "")
        port = _as_int(row.get("destination_port") or row.get("id.resp_p"))
        if source:
            devices.append(source)
        if destination:
            devices.append(destination)
        if port is not None:
            ports.add(port)
        key = (source, destination, port)
        if key not in seen:
            seen.add(key)
            pairs.append({"source": source, "destination": destination, "port": port, "protocol": "tcp", "service": "TLS/SSL"})
        ts = row.get("timestamp", row.get("ts"))
        if ts not in (None, ""):
            timestamps.append(ts)
    return _unique(devices), sorted(ports), pairs, timestamps


def _split_collection(value: Any) -> list[str]:
    if value in (None, "", "-"):
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value if item not in (None, "")]
    return [part.strip() for part in str(value).split(",") if part.strip()]


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _sanitize(row: dict[str, Any]) -> dict[str, Any]:
    return dict(row)
