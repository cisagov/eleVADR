from __future__ import annotations

from collections import defaultdict
import ipaddress
import re
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata

MAX_EVIDENCE_ROWS = 25


class UnknownRogueDevicesModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="unknown_rogue_devices",
        name="Unknown / Rogue Devices",
        description=(
            "Identifies locally observed IP or MAC addresses that are not present in the supplied asset inventory."
        ),
        category="security_analysis",
        required_logs=(),
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        inventory = context.metadata.get("asset_inventory")
        if not isinstance(inventory, list) or not inventory:
            return ModuleResult(
                module_id=self.metadata.id,
                findings=[],
                metrics={
                    "unknown_or_rogue_devices": 0,
                    "unknown_ip_addresses": 0,
                    "unknown_mac_addresses": 0,
                    "observed_local_ip_addresses": 0,
                    "observed_mac_addresses": 0,
                },
                evidence={
                    "asset_inventory_loaded": False,
                    "asset_inventory_source": context.metadata.get("asset_inventory_source"),
                    "inspected_logs": _inspected_logs(context),
                    "notes": [
                        "No asset inventory was supplied, so unknown/rogue device detection was skipped.",
                        "Place asset_inventory.json or asset_inventory.csv beside the Zeek logs to enable this module.",
                    ],
                },
                warnings=[],
            )

        known_ips, known_macs = _inventory_identifiers(inventory)
        observed_ips, ip_flows = _observed_local_ips(context.connections)
        observed_macs, mac_rows, mac_to_ips = _observed_macs(context)

        unknown_ips = sorted(observed_ips - known_ips) if known_ips else []
        unknown_macs = sorted(observed_macs - known_macs) if known_macs else []

        findings: list[Finding] = []
        covered_ips: set[str] = set()

        for mac in unknown_macs:
            associated_ips = sorted(ip for ip in mac_to_ips.get(mac, set()) if ip)
            covered_ips.update(associated_ips)
            rows = mac_rows.get(mac, [])
            devices = [mac, *associated_ips]
            findings.append(
                Finding(
                    title=f"Unknown device MAC observed: {mac}",
                    severity="medium",
                    summary=(
                        f"Observed MAC address {mac} is not present in the supplied asset inventory. "
                        "This is a high-confidence identity mismatch and should be validated as an authorized asset."
                    ),
                    confidence="high",
                    detection_basis="derived",
                    devices=devices,
                    services=[],
                    ports=[],
                    connection_pairs=_pairs_from_rows(rows),
                    flows=rows[:MAX_EVIDENCE_ROWS],
                    subnets=[],
                    timestamps=_timestamps(rows),
                    tags=["asset-inventory", "unknown-device", "rogue-device", "mac-mismatch"],
                    metadata={
                        "identifier_type": "mac",
                        "identifier": mac,
                        "associated_ips": associated_ips,
                        "asset_inventory_source": context.metadata.get("asset_inventory_source"),
                    },
                )
            )

        for ip in unknown_ips:
            if ip in covered_ips:
                continue
            rows = ip_flows.get(ip, [])
            findings.append(
                Finding(
                    title=f"Unknown device IP observed: {ip}",
                    severity="low",
                    summary=(
                        f"Observed local IP address {ip} is not present in the supplied asset inventory. "
                        "IP-only mismatches are lower confidence because addresses may be dynamic, translated, or stale in the inventory."
                    ),
                    confidence="medium",
                    detection_basis="derived",
                    devices=[ip],
                    services=sorted({str(row.get("service")) for row in rows if row.get("service")}),
                    ports=sorted({_as_int(_first(row, "destination_port", "id.resp_p")) for row in rows if _as_int(_first(row, "destination_port", "id.resp_p")) is not None}),
                    connection_pairs=_pairs_from_rows(rows),
                    flows=rows[:MAX_EVIDENCE_ROWS],
                    subnets=[],
                    timestamps=_timestamps(rows),
                    tags=["asset-inventory", "unknown-device", "rogue-device", "ip-mismatch"],
                    metadata={
                        "identifier_type": "ip",
                        "identifier": ip,
                        "asset_inventory_source": context.metadata.get("asset_inventory_source"),
                    },
                )
            )

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "unknown_or_rogue_devices": len(findings),
                "unknown_ip_addresses": len([ip for ip in unknown_ips if ip not in covered_ips]),
                "unknown_mac_addresses": len(unknown_macs),
                "observed_local_ip_addresses": len(observed_ips),
                "observed_mac_addresses": len(observed_macs),
                "inventory_ip_addresses": len(known_ips),
                "inventory_mac_addresses": len(known_macs),
            },
            evidence={
                "asset_inventory_loaded": True,
                "asset_inventory_source": context.metadata.get("asset_inventory_source"),
                "inventory_records": len(inventory),
                "inspected_logs": _inspected_logs(context),
                "comparison": {
                    "ip_comparison_enabled": bool(known_ips),
                    "mac_comparison_enabled": bool(known_macs),
                },
                "notes": [
                    "Only local/private connection endpoints are compared for IP-based rogue-device detection unless Zeek explicitly marks an endpoint as local.",
                    "MAC-based mismatches are higher confidence than IP-only mismatches.",
                    "If the inventory contains no MAC addresses, MAC comparison is skipped; if it contains no IP addresses, IP comparison is skipped.",
                    "Dynamic addressing, NAT, stale inventories, virtualization, and temporary maintenance devices can produce legitimate mismatches.",
                ],
                "asset_inventory_format": {
                    "assets": [
                        {
                            "name": "PLC-01",
                            "ips": ["10.10.1.20"],
                            "macs": ["00:11:22:33:44:55"],
                        }
                    ]
                },
            },
            warnings=[],
        )


def _inventory_identifiers(inventory: list[dict[str, Any]]) -> tuple[set[str], set[str]]:
    ips: set[str] = set()
    macs: set[str] = set()
    for asset in inventory:
        for value in _values(asset, "ips", "ip_addresses", "ip", "address", "addresses"):
            normalized = _normalize_ip(value)
            if normalized:
                ips.add(normalized)
        for value in _values(asset, "macs", "mac_addresses", "mac", "mac_address"):
            normalized = _normalize_mac(value)
            if normalized:
                macs.add(normalized)
    return ips, macs


def _observed_local_ips(connections: list[dict[str, Any]]) -> tuple[set[str], dict[str, list[dict[str, Any]]]]:
    observed: set[str] = set()
    rows_by_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in connections:
        for ip_key, local_key in (("source_ip", "local_orig"), ("destination_ip", "local_resp")):
            fallback = "id.orig_h" if ip_key == "source_ip" else "id.resp_h"
            ip = _normalize_ip(_first(row, ip_key, fallback))
            if not ip or not _is_local_candidate(ip, row.get(local_key)):
                continue
            observed.add(ip)
            rows_by_ip[ip].append(row)
    return observed, rows_by_ip


def _observed_macs(context: AnalysisContext) -> tuple[set[str], dict[str, list[dict[str, Any]]], dict[str, set[str]]]:
    observed: set[str] = set()
    rows_by_mac: dict[str, list[dict[str, Any]]] = defaultdict(list)
    mac_to_ips: dict[str, set[str]] = defaultdict(set)
    for log_name in ("dhcp", "arp"):
        for row in context.log(log_name):
            mac_values = []
            for key, value in row.items():
                key_lower = str(key).lower()
                if "mac" in key_lower or key_lower in {"chaddr", "client_hardware_addr"}:
                    mac_values.extend(_split_values(value))
            ips = {
                normalized
                for key, value in row.items()
                if any(token in str(key).lower() for token in ("addr", "ip"))
                for candidate in _split_values(value)
                if (normalized := _normalize_ip(candidate))
            }
            for raw_mac in mac_values:
                mac = _normalize_mac(raw_mac)
                if not mac:
                    continue
                observed.add(mac)
                rows_by_mac[mac].append(row)
                mac_to_ips[mac].update(ips)
    return observed, rows_by_mac, mac_to_ips


def _is_local_candidate(ip: str, zeek_local_flag: Any) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    # Never treat protocol/special-use endpoints as candidate assets, even if
    # Zeek marks the side local. This excludes DHCP broadcast/unspecified and
    # multicast destinations from rogue-device inventory comparison.
    if addr.is_multicast or addr.is_unspecified or addr.is_loopback or addr.is_reserved:
        return False
    if _truthy(zeek_local_flag):
        return True
    return addr.is_private or addr.is_link_local


def _truthy(value: Any) -> bool:
    if value is True:
        return True
    if isinstance(value, str):
        return value.strip().lower() in {"t", "true", "1", "yes"}
    return False


def _normalize_ip(value: Any) -> str | None:
    if value is None:
        return None
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def _normalize_mac(value: Any) -> str | None:
    if value is None:
        return None
    text = re.sub(r"[^0-9A-Fa-f]", "", str(value))
    if len(text) != 12:
        return None
    return ":".join(text[i:i + 2] for i in range(0, 12, 2)).lower()


def _values(asset: dict[str, Any], *keys: str) -> list[Any]:
    values: list[Any] = []
    for key in keys:
        if key not in asset or asset[key] in (None, ""):
            continue
        values.extend(_split_values(asset[key]))
    return values


def _split_values(value: Any) -> list[Any]:
    if isinstance(value, (list, tuple, set)):
        return list(value)
    if isinstance(value, str) and any(separator in value for separator in (",", ";", "|")):
        return [part.strip() for part in re.split(r"[,;|]", value) if part.strip()]
    return [value]


def _pairs_from_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    pairs: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for row in rows:
        source = _first(row, "source_ip", "id.orig_h")
        destination = _first(row, "destination_ip", "id.resp_h")
        port = _as_int(_first(row, "destination_port", "id.resp_p"))
        protocol = str(_first(row, "protocol", "proto") or "")
        service = row.get("service")
        if not source or not destination:
            continue
        key = (source, destination, port, protocol, service)
        if key in seen:
            continue
        seen.add(key)
        pairs.append({
            "source": str(source),
            "destination": str(destination),
            "port": port,
            "protocol": protocol,
            "service": service,
        })
        if len(pairs) >= MAX_EVIDENCE_ROWS:
            break
    return pairs


def _timestamps(rows: list[dict[str, Any]]) -> list[float | str]:
    result: list[float | str] = []
    for row in rows:
        value = _first(row, "timestamp", "ts")
        if value is not None and value not in result:
            result.append(value)
        if len(result) >= MAX_EVIDENCE_ROWS:
            break
    return result


def _first(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if row.get(key) not in (None, ""):
            return row[key]
    return None


def _as_int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _inspected_logs(context: AnalysisContext) -> list[str]:
    return [name for name in ("conn", "dhcp", "arp") if context.log(name)]
