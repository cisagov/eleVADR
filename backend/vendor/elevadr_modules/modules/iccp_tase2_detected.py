from __future__ import annotations

from collections import defaultdict
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata

ISO_ON_TCP_PORT = 102
MAX_EVIDENCE_FLOWS = 25
ICCP_SERVICE_TOKENS = {"iccp", "tase2", "tase.2", "tase_2", "iec60870-6", "iec_60870_6"}
OSI_SERVICE_TOKENS = {"iso_cotp", "cotp", "tpkt", "iso-on-tcp", "iso_on_tcp"}


class IccpTase2DetectedModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="iccp_tase2_detected",
        name="ICCP / Inter-Control-Center Protocol",
        description=(
            "Identifies traffic consistent with ICCP/TASE.2, used for real-time data exchange between electric "
            "utility SCADA control centers. Explicit ICCP/TASE.2 service labels are preferred; TCP/102/OSI-on-TCP "
            "is treated conservatively because other industrial protocols also use ISO-on-TCP."
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
        expected_peers = {
            (_text(item.get("source")), _text(item.get("destination")))
            for item in policy.get("expected_control_center_pairs", [])
            if isinstance(item, dict) and _text(item.get("source")) and _text(item.get("destination"))
        }

        mms_uids = {_text(row.get("uid")) for row in context.mms if _text(row.get("uid"))}
        groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        skipped_allowlisted = 0
        skipped_non_tcp = 0

        for row in context.connections:
            if _text(row.get("protocol", row.get("proto"))).lower() != "tcp":
                skipped_non_tcp += 1
                continue

            source = _text(row.get("source_ip", row.get("id.orig_h")))
            destination = _text(row.get("destination_ip", row.get("id.resp_h")))
            if source in allowed_hosts or destination in allowed_hosts or (source, destination) in allowed_pairs:
                skipped_allowlisted += 1
                continue

            service_tokens = _service_tokens(row.get("service"))
            port = _as_int(row.get("destination_port", row.get("id.resp_p")))
            uid = _text(row.get("uid"))

            if service_tokens & ICCP_SERVICE_TOKENS:
                groups["explicit_iccp"].append(row)
                continue

            if port != ISO_ON_TCP_PORT:
                continue

            # TCP/102 carries several OT protocols (notably S7 and MMS). Do not
            # claim ICCP from the port alone when Zeek already identified a
            # different application service.
            known_non_iccp = service_tokens - OSI_SERVICE_TOKENS - {"unknown", "-"}
            if known_non_iccp:
                continue

            if expected_peers and (source, destination) in expected_peers:
                groups["expected_pair_port102"].append(row)
            elif service_tokens & OSI_SERVICE_TOKENS or (uid and uid in mms_uids):
                groups["osi_port102"].append(row)
            else:
                groups["port102_only"].append(row)

        findings = []
        for basis in ("explicit_iccp", "expected_pair_port102", "osi_port102", "port102_only"):
            rows = groups.get(basis, [])
            if rows:
                findings.append(_finding(basis, rows))

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "iccp_findings": len(findings),
                "explicit_iccp_flows": len(groups.get("explicit_iccp", [])),
                "expected_pair_port102_flows": len(groups.get("expected_pair_port102", [])),
                "osi_port102_flows": len(groups.get("osi_port102", [])),
                "port102_only_flows": len(groups.get("port102_only", [])),
                "skipped_allowlisted": skipped_allowlisted,
                "skipped_non_tcp": skipped_non_tcp,
            },
            evidence={
                "inspected_logs": ["conn"] + (["mms"] if context.mms else []),
                "notes": [
                    "ICCP/TASE.2 commonly runs over the OSI stack transported by RFC 1006 on TCP/102.",
                    "TCP/102 is not unique to ICCP; Siemens S7 and MMS/IEC 61850 traffic can also use this port.",
                    "Explicit ICCP/TASE.2 service identification is high-confidence. Port-only evidence is intentionally low-confidence.",
                    "expected_control_center_pairs can raise confidence for known utility control-center peers without treating all TCP/102 as ICCP.",
                ],
                "policy": policy,
            },
            warnings=[],
        )


def _finding(basis: str, rows: list[dict[str, Any]]) -> Finding:
    devices: set[str] = set()
    services: set[str] = set()
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
        services.update(_service_tokens(row.get("service")))
        ts = row.get("timestamp", row.get("ts"))
        if ts not in (None, ""):
            timestamps.append(ts)
        pair = (source, destination)
        if pair not in seen_pairs and len(pairs) < MAX_EVIDENCE_FLOWS:
            seen_pairs.add(pair)
            pairs.append({"source": source, "destination": destination, "destination_port": ISO_ON_TCP_PORT})

    if basis == "explicit_iccp":
        title = "ICCP/TASE.2 service detected"
        summary = (
            f"Observed {len(rows)} TCP flow(s) with an explicit Zeek service label consistent with ICCP/TASE.2, "
            "the IEC 60870-6 inter-control-center protocol used for utility SCADA data exchange."
        )
        confidence = "high"
        detection_basis = "zeek_service"
    elif basis == "expected_pair_port102":
        title = "ICCP/TASE.2 traffic consistent with configured control-center peers"
        summary = (
            f"Observed {len(rows)} TCP/102 flow(s) between endpoints configured as expected control-center peers. "
            "The peer policy makes ICCP/TASE.2 plausible, but TCP/102 alone is not application-specific."
        )
        confidence = "medium"
        detection_basis = "derived"
    elif basis == "osi_port102":
        title = "OSI-on-TCP traffic consistent with ICCP/TASE.2"
        summary = (
            f"Observed {len(rows)} TCP/102 flow(s) with OSI/COTP-style or MMS-correlated evidence. This is "
            "consistent with ICCP/TASE.2 transport, but can also represent other MMS/ISO-on-TCP industrial protocols."
        )
        confidence = "medium"
        detection_basis = "derived"
    else:
        title = "TCP/102 traffic potentially consistent with ICCP/TASE.2"
        summary = (
            f"Observed {len(rows)} TCP flow(s) to port 102 without a conflicting application service label. "
            "Because TCP/102 is shared by multiple industrial protocols, this is only low-confidence ICCP/TASE.2 evidence."
        )
        confidence = "low"
        detection_basis = "port"

    return Finding(
        title=title,
        severity="low",
        summary=summary,
        confidence=confidence,
        detection_basis=detection_basis,
        devices=sorted(devices),
        services=sorted(services),
        ports=[ISO_ON_TCP_PORT],
        timestamps=timestamps[:MAX_EVIDENCE_FLOWS],
        metadata={
            "protocol": "iccp_tase2",
            "iec_standard": "IEC 60870-6 / TASE.2",
            "destination_port": ISO_ON_TCP_PORT,
            "evidence_class": basis,
            "flow_count": len(rows),
            "sample_pairs": pairs,
        },
    )


def _policy(metadata: dict[str, Any]) -> dict[str, Any]:
    value = metadata.get("iccp_tase2_policy", {}) if isinstance(metadata, dict) else {}
    return value if isinstance(value, dict) else {}


def _service_tokens(value: Any) -> set[str]:
    text = _text(value).lower()
    if not text:
        return set()
    for separator in (",", ";", "|"):
        text = text.replace(separator, " ")
    return {token.strip() for token in text.split() if token.strip()}


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
