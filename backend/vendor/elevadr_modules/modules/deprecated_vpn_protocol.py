from __future__ import annotations

from collections import defaultdict
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata

MAX_EVIDENCE_ROWS = 50
PPTP_PORT = 1723
L2TP_PORT = 1701
IKE_PORTS = {500, 4500}
IPSEC_PROTOCOLS = {50, 51}  # ESP, AH
GRE_PROTOCOL = 47


class DeprecatedVpnProtocolModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="deprecated_vpn_protocol",
        name="PPTP / Deprecated VPN Protocol",
        description=(
            "Identifies PPTP using TCP/1723 with GRE when available, and L2TP sessions on UDP/1701 "
            "that lack correlated IKE/IPsec evidence."
        ),
        category="security_analysis",
        required_logs=("conn",),
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        policy = _policy(context.metadata)
        correlation_window = _as_float(policy.get("correlation_window_seconds"), 120.0)
        allowed_hosts = _string_set(policy.get("allowed_hosts"))
        allowed_pairs = _pair_set(policy.get("allowed_pairs"))
        report_pptp_control_only = _bool(policy.get("report_pptp_control_only"), True)
        report_l2tp_without_ipsec = _bool(policy.get("report_l2tp_without_ipsec"), True)

        pptp_controls: list[dict[str, Any]] = []
        gre_rows: list[dict[str, Any]] = []
        l2tp_rows: list[dict[str, Any]] = []
        ipsec_rows: list[dict[str, Any]] = []

        for row in context.connections:
            src = _ip(_first(row, "source_ip", "id.orig_h"))
            dst = _ip(_first(row, "destination_ip", "id.resp_h"))
            if not src or not dst:
                continue
            proto = _text(_first(row, "protocol", "proto")).lower()
            dport = _as_int(_first(row, "destination_port", "id.resp_p"))
            sport = _as_int(_first(row, "source_port", "id.orig_p"))
            ip_proto = _ip_protocol_number(row, proto)

            if proto == "tcp" and (dport == PPTP_PORT or sport == PPTP_PORT):
                pptp_controls.append(_event(row, src, dst, "pptp_control"))
            if ip_proto == GRE_PROTOCOL or proto == "gre":
                gre_rows.append(_event(row, src, dst, "gre"))
            if proto == "udp" and (dport == L2TP_PORT or sport == L2TP_PORT):
                l2tp_rows.append(_event(row, src, dst, "l2tp"))
            if (proto == "udp" and (dport in IKE_PORTS or sport in IKE_PORTS)) or ip_proto in IPSEC_PROTOCOLS or proto in {"esp", "ah"}:
                ipsec_rows.append(_event(row, src, dst, "ipsec"))

        findings: list[Finding] = []
        skipped_allowlisted = 0
        pptp_with_gre = 0
        pptp_control_only = 0
        l2tp_with_ipsec = 0
        l2tp_without_ipsec = 0

        grouped_pptp: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        for ctrl in pptp_controls:
            pair = _canonical_pair(ctrl["source"], ctrl["destination"])
            if _allowlisted(ctrl["source"], ctrl["destination"], allowed_hosts, allowed_pairs):
                skipped_allowlisted += 1
                continue
            has_gre = any(_same_pair_within(ctrl, gre, correlation_window) for gre in gre_rows)
            ctrl["has_correlated_gre"] = has_gre
            if has_gre:
                pptp_with_gre += 1
            else:
                pptp_control_only += 1
                if not report_pptp_control_only:
                    continue
            grouped_pptp[pair].append(ctrl)

        for pair, items in sorted(grouped_pptp.items()):
            any_gre = any(bool(x.get("has_correlated_gre")) for x in items)
            findings.append(_pptp_finding(pair, items, any_gre))

        grouped_l2tp: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        for row in l2tp_rows:
            if _allowlisted(row["source"], row["destination"], allowed_hosts, allowed_pairs):
                skipped_allowlisted += 1
                continue
            has_ipsec = any(_same_pair_within(row, sec, correlation_window) for sec in ipsec_rows)
            if has_ipsec:
                l2tp_with_ipsec += 1
                continue
            l2tp_without_ipsec += 1
            if report_l2tp_without_ipsec:
                grouped_l2tp[_canonical_pair(row["source"], row["destination"])].append(row)

        for pair, items in sorted(grouped_l2tp.items()):
            findings.append(_l2tp_finding(pair, items, correlation_window))

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "pptp_control_candidates": len(pptp_controls),
                "gre_candidates": len(gre_rows),
                "pptp_with_correlated_gre": pptp_with_gre,
                "pptp_control_only": pptp_control_only,
                "l2tp_candidates": len(l2tp_rows),
                "l2tp_with_correlated_ipsec": l2tp_with_ipsec,
                "l2tp_without_correlated_ipsec": l2tp_without_ipsec,
                "deprecated_vpn_findings": len(findings),
                "skipped_allowlisted": skipped_allowlisted,
            },
            evidence={
                "inspected_logs": ["conn"] if context.connections else [],
                "policy": policy,
                "notes": [
                    "PPTP is identified most strongly when TCP/1723 control traffic is accompanied by GRE (IP protocol 47) between the same peers.",
                    "TCP/1723 without GRE is lower-confidence PPTP evidence because a conn.log may not include all packets/protocols seen on the path.",
                    "L2TP on UDP/1701 is reported as lacking IPsec only when no IKE UDP/500 or UDP/4500, ESP (IP protocol 50), or AH (IP protocol 51) evidence is observed for the same peers in the correlation window.",
                    "Absence of IPsec in a passive capture is evidence-limited: asymmetric routing, sensor placement, or capture filtering can hide IKE/ESP/AH traffic.",
                ],
            },
            warnings=[],
        )


def _pptp_finding(pair: tuple[str, str], items: list[dict[str, Any]], has_gre: bool) -> Finding:
    src, dst = pair
    evidence = items[:MAX_EVIDENCE_ROWS]
    return Finding(
        title="PPTP deprecated VPN protocol observed" if has_gre else "Possible PPTP control traffic observed",
        severity="medium" if has_gre else "low",
        summary=(
            f"Observed {len(items)} TCP/1723 PPTP control flow(s) between {src} and {dst} with correlated GRE (IP protocol 47). PPTP is deprecated and should be replaced with a modern VPN protocol."
            if has_gre
            else f"Observed {len(items)} TCP/1723 control flow(s) between {src} and {dst} without correlated GRE in the available capture. This is consistent with PPTP control traffic but is not payload-confirmed."
        ),
        confidence="high" if has_gre else "low",
        detection_basis="derived" if has_gre else "port",
        devices=[src, dst],
        services=["PPTP"],
        ports=[PPTP_PORT],
        connection_pairs=[{"source": e["source"], "destination": e["destination"], "destination_port": e.get("destination_port"), "protocol": e.get("protocol")} for e in evidence],
        timestamps=[e["timestamp"] for e in evidence if e.get("timestamp") is not None],
        tags=["vpn", "pptp", "deprecated-protocol"],
        metadata={"correlated_gre": has_gre, "pair": {"endpoint_a": src, "endpoint_b": dst}},
    )


def _l2tp_finding(pair: tuple[str, str], items: list[dict[str, Any]], window: float) -> Finding:
    src, dst = pair
    evidence = items[:MAX_EVIDENCE_ROWS]
    return Finding(
        title="L2TP observed without correlated IPsec",
        severity="medium",
        summary=(
            f"Observed {len(items)} UDP/1701 L2TP flow(s) between {src} and {dst} with no correlated IKE, ESP, or AH evidence in the configured {window:g}-second window. Review whether L2TP is being used without IPsec protection."
        ),
        confidence="medium",
        detection_basis="derived",
        devices=[src, dst],
        services=["L2TP"],
        ports=[L2TP_PORT],
        connection_pairs=[{"source": e["source"], "destination": e["destination"], "destination_port": e.get("destination_port"), "protocol": e.get("protocol")} for e in evidence],
        timestamps=[e["timestamp"] for e in evidence if e.get("timestamp") is not None],
        tags=["vpn", "l2tp", "cleartext-or-unprotected", "deprecated-protocol"],
        metadata={"correlated_ipsec": False, "correlation_window_seconds": window, "pair": {"endpoint_a": src, "endpoint_b": dst}},
    )


def _event(row: dict[str, Any], src: str, dst: str, kind: str) -> dict[str, Any]:
    return {
        "kind": kind,
        "source": src,
        "destination": dst,
        "source_port": _as_int(_first(row, "source_port", "id.orig_p")),
        "destination_port": _as_int(_first(row, "destination_port", "id.resp_p")),
        "protocol": _text(_first(row, "protocol", "proto")).lower(),
        "timestamp": _timestamp(row),
        "uid": _text(row.get("uid")),
    }


def _same_pair_within(a: dict[str, Any], b: dict[str, Any], window: float) -> bool:
    if _canonical_pair(a["source"], a["destination"]) != _canonical_pair(b["source"], b["destination"]):
        return False
    ta, tb = a.get("timestamp"), b.get("timestamp")
    if ta is None or tb is None:
        return True
    return abs(float(ta) - float(tb)) <= window


def _canonical_pair(a: str, b: str) -> tuple[str, str]:
    return tuple(sorted((a, b)))  # type: ignore[return-value]


def _allowlisted(src: str, dst: str, hosts: set[str], pairs: set[tuple[str, str]]) -> bool:
    return src in hosts or dst in hosts or (src, dst) in pairs or (dst, src) in pairs


def _policy(metadata: dict[str, Any]) -> dict[str, Any]:
    value = metadata.get("deprecated_vpn_policy")
    return value if isinstance(value, dict) else {}


def _string_set(value: Any) -> set[str]:
    if not isinstance(value, (list, tuple, set)):
        return set()
    return {_text(x) for x in value if _text(x)}


def _pair_set(value: Any) -> set[tuple[str, str]]:
    result: set[tuple[str, str]] = set()
    if not isinstance(value, (list, tuple)):
        return result
    for item in value:
        if not isinstance(item, dict):
            continue
        src = _text(item.get("source"))
        dst = _text(item.get("destination"))
        if src and dst:
            result.add((src, dst))
    return result


def _ip_protocol_number(row: dict[str, Any], proto: str) -> int | None:
    for key in ("ip_proto", "ip_protocol", "protocol_number", "ip.protocol"):
        val = _as_int(row.get(key))
        if val is not None:
            return val
    aliases = {"gre": 47, "esp": 50, "ah": 51}
    return aliases.get(proto)


def _timestamp(row: dict[str, Any]) -> float | None:
    value = _first(row, "timestamp", "ts")
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _ip(value: Any) -> str:
    text = _text(value)
    return text if text not in {"", "-"} else ""


def _first(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in row and row[key] not in (None, "", "-"):
            return row[key]
    return None


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _as_float(value: Any, default: float) -> float:
    try:
        return max(0.0, float(value))
    except (TypeError, ValueError):
        return default


def _bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        if value.strip().lower() in {"true", "1", "yes", "on"}:
            return True
        if value.strip().lower() in {"false", "0", "no", "off"}:
            return False
    return default
