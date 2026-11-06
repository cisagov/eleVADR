from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata

MAX_EVIDENCE = 10


class ArpIpMacIdentityChangeModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="arp_ip_mac_identity_change",
        name="ARP / IP-MAC Identity Change",
        description=(
            "Detects ARP observations where an authoritative asset IP is claimed by an unexpected MAC address, "
            "or where one IP rapidly appears behind multiple MAC addresses."
        ),
        category="security_analysis",
        required_logs=("arp",),
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        rows = [_normalize_row(row) for row in context.arp]
        rows = [row for row in rows if row is not None]
        policy = _policy(context.metadata)
        authoritative = _authoritative_identity(context.metadata)
        ignored = {_normalize_ip(x) for x in policy.get("ignored_ips", []) if _normalize_ip(x)}
        window = _as_float(policy.get("change_window_seconds")) or 300.0

        by_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in rows:
            if row["ip"] not in ignored:
                by_ip[row["ip"]].append(row)

        findings: list[Finding] = []
        mismatch_count = 0
        conflict_count = 0
        for ip in sorted(by_ip):
            observed_rows = sorted(by_ip[ip], key=lambda x: x["timestamp"] if x["timestamp"] is not None else -1.0)
            observed_macs = {row["mac"] for row in observed_rows if row["mac"]}
            expected_macs = authoritative.get(ip, set())

            unexpected = observed_macs - expected_macs if expected_macs else set()
            if unexpected:
                mismatch_count += 1
                findings.append(Finding(
                    title="Authoritative OT asset IP observed with unexpected MAC",
                    severity="high",
                    summary=f"{ip} was observed in ARP evidence with MAC address(es) not present in the authoritative asset inventory.",
                    confidence="high",
                    detection_basis="protocol_log",
                    devices=[ip, *sorted(unexpected)],
                    flows=[_evidence(row) for row in observed_rows if row["mac"] in unexpected][:MAX_EVIDENCE],
                    timestamps=[row["timestamp"] for row in observed_rows if row["timestamp"] is not None][:MAX_EVIDENCE],
                    tags=["arp", "identity-change", "asset-identity"],
                    metadata={
                        "expected_macs": sorted(expected_macs),
                        "observed_macs": sorted(observed_macs),
                        "unexpected_macs": sorted(unexpected),
                        "authoritative_inventory_required": True,
                    },
                ))

            if len(observed_macs) >= 2 and _within_window(observed_rows, window):
                conflict_count += 1
                findings.append(Finding(
                    title="IP observed behind multiple MAC addresses",
                    severity="medium" if not expected_macs else "high",
                    summary=f"{ip} was associated with {len(observed_macs)} MAC addresses within the configured identity-change window.",
                    confidence="high",
                    detection_basis="protocol_log",
                    devices=[ip, *sorted(observed_macs)],
                    flows=[_evidence(row) for row in observed_rows][:MAX_EVIDENCE],
                    timestamps=[row["timestamp"] for row in observed_rows if row["timestamp"] is not None][:MAX_EVIDENCE],
                    tags=["arp", "identity-change", "possible-spoofing"],
                    metadata={
                        "observed_macs": sorted(observed_macs),
                        "change_window_seconds": window,
                        "expected_macs": sorted(expected_macs),
                    },
                ))

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "arp_records_evaluated": len(context.arp),
                "classified_identity_records": len(rows),
                "authoritative_mismatches": mismatch_count,
                "multi_mac_conflicts": conflict_count,
                "findings": len(findings),
            },
            evidence={
                "inspected_logs": ["arp"],
                "authoritative_asset_ips_with_macs": len(authoritative),
                "notes": [
                    "Authoritative IP-to-MAC expectations come only from non-Zeek asset inventory entries.",
                    "Observed ARP traffic never updates the authoritative inventory or creates an allowlist.",
                ],
            },
            warnings=[],
        )


def _normalize_row(row: dict[str, Any]) -> dict[str, Any] | None:
    ip = _normalize_ip(_first(row, "ip", "sender_ip", "src_ip", "source_ip", "spa", "arp_spa", "protocol_addr", "id.orig_h"))
    mac = _normalize_mac(_first(row, "mac", "sender_mac", "src_mac", "source_mac", "sha", "arp_sha", "hardware_addr"))
    if not ip or not mac:
        return None
    return {"ip": ip, "mac": mac, "timestamp": _as_float(_first(row, "timestamp", "ts")), "raw": row}


def _authoritative_identity(metadata: dict[str, Any]) -> dict[str, set[str]]:
    result: dict[str, set[str]] = defaultdict(set)
    inventory = metadata.get("asset_inventory")
    if not isinstance(inventory, list):
        return result
    for asset in inventory:
        if not isinstance(asset, dict):
            continue
        ips = asset.get("ips") if isinstance(asset.get("ips"), list) else [asset.get("ip")]
        macs = asset.get("macs") if isinstance(asset.get("macs"), list) else asset.get("mac_addresses") if isinstance(asset.get("mac_addresses"), list) else [asset.get("mac")]
        norm_macs = {_normalize_mac(x) for x in macs}
        norm_macs.discard(None)
        for raw_ip in ips:
            ip = _normalize_ip(raw_ip)
            if ip and norm_macs:
                result[ip].update(str(x) for x in norm_macs)
    return result


def _within_window(rows: list[dict[str, Any]], window: float) -> bool:
    timestamps = [row["timestamp"] for row in rows if row["timestamp"] is not None]
    if len(timestamps) < 2:
        return False
    return max(timestamps) - min(timestamps) <= window


def _evidence(row: dict[str, Any]) -> dict[str, Any]:
    return {"timestamp": row["timestamp"], "ip": row["ip"], "mac": row["mac"]}


def _policy(metadata: dict[str, Any]) -> dict[str, Any]:
    value = metadata.get("arp_identity_policy")
    return dict(value) if isinstance(value, dict) else {}


def _normalize_ip(value: Any) -> str | None:
    if value in (None, ""):
        return None
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def _normalize_mac(value: Any) -> str | None:
    if value in (None, ""):
        return None
    text = re.sub(r"[^0-9A-Fa-f]", "", str(value))
    if len(text) != 12:
        return None
    return ":".join(text[i:i+2] for i in range(0, 12, 2)).lower()


def _first(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if row.get(key) not in (None, ""):
            return row[key]
    return None


def _as_float(value: Any) -> float | None:
    try:
        return float(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None
