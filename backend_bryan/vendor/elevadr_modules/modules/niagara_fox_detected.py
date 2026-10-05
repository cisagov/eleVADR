from __future__ import annotations

from collections import defaultdict
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata

FOX_PORT = 1911
FOX_SSL_PORT = 4911
MAX_EVIDENCE_FLOWS = 25


class NiagaraFoxDetectedModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="niagara_fox_detected",
        name="Niagara Fox Protocol Detected",
        description=(
            "Identifies Tridium Niagara Fox communications on TCP/1911 and Fox-over-SSL on TCP/4911, "
            "commonly used between JACE controllers and supervisory stations in building automation systems."
        ),
        category="security_analysis",
        required_logs=("conn",),
        default_enabled=True,
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        policy = _policy(context.metadata)
        allowed_hosts = {_text(v) for v in policy.get("allowed_hosts", []) if _text(v)}
        allowed_pairs = {
            (_text(item.get("source")), _text(item.get("destination")))
            for item in policy.get("allowed_pairs", [])
            if isinstance(item, dict) and _text(item.get("source")) and _text(item.get("destination"))
        }

        ssl_uids = {_text(row.get("uid")) for row in context.ssl if _text(row.get("uid"))}
        groups: dict[tuple[int, bool], list[dict[str, Any]]] = defaultdict(list)
        skipped_allowlisted = 0
        skipped_non_tcp = 0

        for row in context.connections:
            if _text(row.get("protocol", row.get("proto"))).lower() != "tcp":
                skipped_non_tcp += 1
                continue
            port = _as_int(row.get("destination_port", row.get("id.resp_p")))
            if port not in {FOX_PORT, FOX_SSL_PORT}:
                continue

            source = _text(row.get("source_ip", row.get("id.orig_h")))
            destination = _text(row.get("destination_ip", row.get("id.resp_h")))
            if source in allowed_hosts or destination in allowed_hosts or (source, destination) in allowed_pairs:
                skipped_allowlisted += 1
                continue

            uid = _text(row.get("uid"))
            tls_confirmed = port == FOX_SSL_PORT and bool(uid and uid in ssl_uids)
            groups[(port, tls_confirmed)].append(row)

        findings = [
            _finding(port, tls_confirmed, rows)
            for (port, tls_confirmed), rows in sorted(groups.items())
            if rows
        ]

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "fox_findings": len(findings),
                "fox_cleartext_flows": sum(len(rows) for (port, _), rows in groups.items() if port == FOX_PORT),
                "fox_ssl_flows": sum(len(rows) for (port, tls), rows in groups.items() if port == FOX_SSL_PORT and tls),
                "fox_4911_unconfirmed_tls_flows": sum(
                    len(rows) for (port, tls), rows in groups.items() if port == FOX_SSL_PORT and not tls
                ),
                "skipped_allowlisted": skipped_allowlisted,
                "skipped_non_tcp": skipped_non_tcp,
            },
            evidence={
                "inspected_logs": ["conn"] + (["ssl"] if context.ssl else []),
                "notes": [
                    "TCP/1911 is treated as Niagara Fox port evidence; TCP/4911 is treated as the Niagara Fox SSL port.",
                    "An ssl.log record with the same UID confirms TLS on TCP/4911 and increases confidence.",
                    "Port evidence identifies traffic consistent with Niagara Fox but does not prove the application payload without a dedicated Fox protocol analyzer.",
                    "Niagara Fox is legitimate building-automation traffic in many environments; findings are intended for asset/protocol visibility and policy review, not automatic malicious classification.",
                ],
                "policy": policy,
            },
            warnings=[],
        )


def _finding(port: int, tls_confirmed: bool, rows: list[dict[str, Any]]) -> Finding:
    devices: set[str] = set()
    pairs: list[dict[str, Any]] = []
    timestamps: list[Any] = []
    seen_pairs: set[tuple[str, str]] = set()

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
        pair = (source, destination)
        if pair not in seen_pairs and len(pairs) < MAX_EVIDENCE_FLOWS:
            seen_pairs.add(pair)
            pairs.append({"source": source, "destination": destination, "destination_port": port})

    if port == FOX_PORT:
        title = "Niagara Fox clear-text traffic detected on TCP/1911"
        summary = (
            f"Observed {len(rows)} TCP flow(s) to destination port 1911, the standard Niagara Fox port used by "
            "Tridium Niagara building-automation systems. This is port-based identification and should be "
            "validated against expected JACE/supervisory communications."
        )
        confidence = "medium"
        severity = "low"
        label = "fox"
    elif tls_confirmed:
        title = "Niagara Fox-over-SSL traffic detected on TCP/4911"
        summary = (
            f"Observed {len(rows)} TCP flow(s) to destination port 4911 with matching Zeek TLS session evidence, "
            "consistent with Niagara Fox-over-SSL communications. Validate the communicating endpoints against "
            "approved building-automation controllers and supervisory stations."
        )
        confidence = "high"
        severity = "low"
        label = "fox_ssl"
    else:
        title = "Traffic on Niagara Fox SSL port TCP/4911"
        summary = (
            f"Observed {len(rows)} TCP flow(s) to destination port 4911, commonly used for Niagara Fox-over-SSL, "
            "but no matching Zeek TLS record was available. Treat this as port-based Niagara Fox evidence rather "
            "than confirmed encrypted Fox traffic."
        )
        confidence = "medium"
        severity = "low"
        label = "fox_ssl_port"

    return Finding(
        title=title,
        severity=severity,
        summary=summary,
        confidence=confidence,
        detection_basis="derived" if tls_confirmed else "port",
        devices=sorted(devices),
        timestamps=timestamps[:MAX_EVIDENCE_FLOWS],
        metadata={
            "protocol": label,
            "destination_port": port,
            "tls_confirmed": tls_confirmed,
            "flow_count": len(rows),
            "sample_pairs": pairs,
        },
    )


def _policy(metadata: dict[str, Any]) -> dict[str, Any]:
    value = metadata.get("niagara_fox_policy", {}) if isinstance(metadata, dict) else {}
    return value if isinstance(value, dict) else {}


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
