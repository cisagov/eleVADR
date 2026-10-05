"""PCAP context discovery for pre-populating Detection Context.

This runs Zeek as a lightweight discovery pass and returns observed facts only.
It deliberately does not create site-policy decisions such as authorized control
paths, approved external destinations, ignored hosts, segment exceptions, DHCP
policy, IPv6 policy, or asserted Purdue levels.
"""
from __future__ import annotations

import ipaddress
import shutil
import tempfile
import uuid
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable

from backend_bryan.integration.detector_runtime import ensure_detector_package

OT_PORTS: dict[int, str] = {
    102: "s7comm",
    502: "modbus",
    1911: "niagara-fox",
    2222: "enip",
    44818: "enip/cip",
    47808: "bacnet",
    20000: "dnp3",
    11740: "codesys",
    11741: "codesys",
    11742: "codesys",
    11743: "codesys",
}
OT_LOG_SERVICES = {
    "s7comm": "s7comm",
    "modbus": "modbus",
    "dnp3": "dnp3",
    "enip": "enip/cip",
    "bacnet": "bacnet",
    "snmp": "snmp",
    "mms": "iccp/tase2",
    "tftp": "tftp",
}
OT_TOKENS = ("modbus", "s7", "dnp3", "bacnet", "enip", "cip", "ethernet/ip", "fox", "niagara", "codesys", "iccp", "tase2", "snmp")


def _value(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = row.get(key)
        if value not in (None, "", "-"):
            return value
    return None


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _port(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _private24(value: str) -> str | None:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if address.version != 4 or not address.is_private:
        return None
    network = ipaddress.ip_network(f"{address}/24", strict=False)
    return str(network)


def _is_ipv6(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).version == 6
    except ValueError:
        return False


def _service_for_log(name: str) -> str:
    lowered = name.lower()
    for token, service in OT_LOG_SERVICES.items():
        if lowered == token or lowered.startswith(f"{token}_") or token in lowered:
            return service
    return ""


def _normalize_mac(value: Any) -> str | None:
    compact = "".join(ch for ch in _text(value).lower() if ch in "0123456789abcdef")
    if len(compact) != 12:
        return None
    return ":".join(compact[i:i+2] for i in range(0, 12, 2))


def _confidence(count: int, *, strong: bool = False) -> str:
    if strong or count >= 20:
        return "high"
    if count >= 5:
        return "medium"
    return "low"


def _context_logs(context: Any) -> dict[str, list[dict[str, Any]]]:
    names = (
        "connections", "dns", "http", "quic", "socks", "ftp", "tftp", "smtp", "telnet", "login",
        "ssl", "x509", "ssh", "kerberos", "ntlm", "ldap", "ldap_bind", "ldap_search", "smb", "smb_mapping",
        "smb_files", "smb_cmd", "rdp", "ssdp", "upnp", "upnp_igd", "vnc", "modbus", "dnp3", "enip", "bacnet",
        "s7comm", "mms", "iec61850", "dhcp", "ntp", "snmp", "arp", "files", "weird",
    )
    return {name: list(getattr(context, name, []) or []) for name in names}


def build_context_discovery_from_zeek(
    context: Any,
    zeek_path: str | Path,
    *,
    source_filename: str,
    progress: Callable[[str, int | None, str, str | None], None] | None = None,
) -> dict[str, Any]:
    """Build observed-only Detection Context suggestions from already-extracted Zeek evidence."""
    zeek_path = Path(zeek_path)
    if progress:
        progress("building-context", 90, "Building Detection Context observations…", source_filename)
    logs = _context_logs(context)

    hosts: dict[str, dict[str, Any]] = {}
    pair_counts: dict[tuple[str, str, str, int | None, str], int] = defaultdict(int)
    infra_counts: dict[tuple[str, str], int] = defaultdict(int)
    subnet_vlans: dict[str, set[int]] = defaultdict(set)
    dhcp_subnets: set[str] = set()
    ipv6_addresses: set[str] = set()
    dhcp_assignments = 0

    def host(ip: str) -> dict[str, Any]:
        return hosts.setdefault(ip, {"services": set(), "ports": set(), "macs": set(), "ot_score": 0, "count": 0})

    def observe_host(ip: str, service: str = "", port: int | None = None, weight: int = 0, mac: str | None = None) -> None:
        if not ip:
            return
        item = host(ip)
        if service:
            item["services"].add(service)
        if port is not None:
            item["ports"].add(port)
        if mac:
            item["macs"].add(mac)
        item["ot_score"] += weight
        item["count"] += 1
        if _is_ipv6(ip):
            ipv6_addresses.add(ip)

    for log_name, rows in logs.items():
        service_from_log = _service_for_log(log_name)
        for row in rows:
            src = _text(_value(row, "source_ip", "id.orig_h", "src", "src_ip"))
            dst = _text(_value(row, "destination_ip", "id.resp_h", "dst", "dst_ip"))
            protocol = _text(_value(row, "protocol", "proto")).lower()
            destination_port = _port(_value(row, "destination_port", "id.resp_p", "dst_port"))
            service = _text(_value(row, "service", "application", "protocol_name")).lower()
            inferred_service = service or OT_PORTS.get(destination_port or -1, "") or service_from_log
            ot_evidence = bool(inferred_service and any(token in inferred_service.lower() for token in OT_TOKENS))
            weight = 3 if ot_evidence or destination_port in OT_PORTS or service_from_log else 0

            observe_host(src, inferred_service, None, 0)
            observe_host(dst, inferred_service, destination_port, weight)
            if src and dst:
                pair_counts[(src, dst, protocol, destination_port, inferred_service)] += 1

            vlan_values: list[int] = []
            for key in ("vlan", "inner_vlan"):
                vlan = _port(row.get(key))
                if vlan is not None:
                    vlan_values.append(vlan)
            for ip in (src, dst):
                subnet = _private24(ip)
                if subnet:
                    subnet_vlans[subnet].update(vlan_values)

            if log_name == "dns" and dst:
                infra_counts[("dns", dst)] += 1
            if log_name == "ntp" and dst:
                infra_counts[("ntp", dst)] += 1
            if log_name == "dhcp":
                server = _text(_value(row, "server_addr", "server_ip", "destination_ip", "id.resp_h"))
                if server:
                    infra_counts[("dhcp", server)] += 1
                client_ip = _text(_value(row, "client_addr", "assigned_addr", "requested_addr", "yiaddr", "source_ip", "id.orig_h"))
                subnet = _private24(client_ip)
                if subnet:
                    dhcp_subnets.add(subnet)
                    dhcp_assignments += 1
            if log_name in {"dhcp", "arp"}:
                mac = _normalize_mac(_value(row, "client_mac", "mac", "mac_address", "client_hardware_addr", "chaddr", "src_mac", "source_mac"))
                ip = _text(_value(row, "client_addr", "assigned_addr", "requested_addr", "ip", "source_ip", "id.orig_h", "src"))
                if ip and mac:
                    observe_host(ip, mac=mac)

    assets: list[dict[str, Any]] = []
    subnet_host_counts: dict[str, dict[str, int]] = defaultdict(lambda: {"count": 0, "ot": 0})
    for ip, item in sorted(hosts.items()):
        ot_score = int(item["ot_score"])
        services = sorted(item["services"])
        record = {
            "id": str(uuid.uuid4()), "ip": ip, "hostname": "",
            "assetType": "OT/ICS candidate" if ot_score >= 3 else "Observed host",
            "role": "OT" if ot_score >= 3 else "Unknown",
            "macAddresses": sorted(item["macs"]), "services": services, "ports": sorted(item["ports"]),
            "source": "zeek", "confidence": "high" if ot_score >= 6 else "medium" if ot_score >= 3 else "low",
            "reason": "Observed using an OT/ICS protocol or well-known OT service port." if ot_score >= 3 else "Observed in Zeek network telemetry; role cannot be established from traffic alone.",
            "observedCount": int(item["count"]),
        }
        assets.append(record)
        subnet = _private24(ip)
        if subnet:
            subnet_host_counts[subnet]["count"] += 1
            if ot_score >= 3:
                subnet_host_counts[subnet]["ot"] += 1

    segments: list[dict[str, Any]] = []
    for cidr, evidence in sorted(subnet_host_counts.items()):
        related = [asset for asset in assets if _private24(asset["ip"]) == cidr]
        ot_protocols = sorted({service for asset in related for service in asset["services"] if any(token in service.lower() for token in OT_TOKENS)})
        likely_ot = evidence["ot"] > 0 or bool(ot_protocols)
        observed_dhcp = cidr in dhcp_subnets
        vlans = sorted(subnet_vlans.get(cidr, set()))
        segments.append({
            "id": str(uuid.uuid4()), "name": f"OT candidate {cidr}" if likely_ot else f"Observed {cidr}", "cidr": cidr,
            "role": "ot" if likely_ot else "unknown", "purdueLevel": "", "vlanId": vlans[0] if len(vlans) == 1 else None,
            "addressing": "dhcp" if observed_dhcp else "unknown", "dhcpAllowed": None, "ipv6Allowed": None,
            "observedDhcp": observed_dhcp, "observedOtProtocols": ot_protocols, "observedVlanIds": vlans,
            "suggestedRole": "ot" if likely_ot else "unknown", "suggestedPurdueLevel": "2" if likely_ot else "",
            "suggestedAddressing": "dhcp" if observed_dhcp else "unknown", "source": "zeek",
            "confidence": "medium" if likely_ot or observed_dhcp or vlans else "low",
            "reason": f"{evidence['ot']} observed host(s) in this subnet used OT/ICS protocol evidence" + (f" ({', '.join(ot_protocols)})." if ot_protocols else ".") if likely_ot else ("Derived from observed private IPv4 addresses; DHCP activity was observed in this subnet." if observed_dhcp else "Derived from observed private IPv4 addresses; network role may need adjustment."),
            "observedCount": evidence["count"],
        })

    infrastructure = [
        {"id": str(uuid.uuid4()), "kind": kind, "value": value, "label": "", "source": "zeek",
         "confidence": _confidence(count), "reason": f"Observed as a {kind.upper()} server/responder in Zeek telemetry.", "observedCount": count}
        for (kind, value), count in sorted(infra_counts.items())
    ]
    pairs = [
        {"id": str(uuid.uuid4()), "sourceIp": src, "destinationIp": dst, "protocol": proto,
         "destinationPort": port, "service": service, "description": "", "source": "zeek",
         "confidence": _confidence(count), "reason": f"Observed {count} time(s). Observation is evidence of use, not authorization.", "observedCount": count}
        for (src, dst, proto, port, service), count in sorted(pair_counts.items(), key=lambda item: item[1], reverse=True)[:500]
    ]

    log_types = {name: len(rows) for name, rows in logs.items() if rows}
    if progress:
        progress("context-ready", 98, "Finalizing Detection Context discovery…", f"{len(assets)} assets · {len(segments)} segments · {len(pairs)} communication pairs")

    return {
        "segments": segments, "assets": assets, "infrastructure": infrastructure, "pairs": pairs,
        "filesScanned": len(log_types), "selectedFileCount": 1,
        "sourceLabel": source_filename, "fileNames": sorted(child.name for child in zeek_path.iterdir() if child.is_file())[:100],
        "recordsParsed": sum(log_types.values()), "logTypes": log_types, "warnings": [],
        "dhcpAssignmentsObserved": dhcp_assignments, "ipv6AddressesObserved": len(ipv6_addresses), "logs": {},
    }


def discover_context_with_retained_evidence(
    pcap_path: str | Path,
    evidence_dir: str | Path,
    *,
    source_filename: str | None = None,
    progress: Callable[[str, int | None, str, str | None], None] | None = None,
) -> dict[str, Any]:
    """Run the comprehensive Zeek extraction once and retain its logs for later detector analysis."""
    ensure_detector_package()
    from backend_bryan.runtime.zeek_runtime import run_zeek_on_pcap

    resolved_source = source_filename or Path(pcap_path).name
    context, zeek_path = run_zeek_on_pcap(pcap_path, output_dir=evidence_dir, progress=progress)
    return build_context_discovery_from_zeek(
        context,
        zeek_path,
        source_filename=resolved_source,
        progress=progress,
    )


def discover_context_from_pcap(
    pcap_path: str | Path,
    *,
    source_filename: str | None = None,
    progress: Callable[[str, int | None, str, str | None], None] | None = None,
) -> dict[str, Any]:
    """Compatibility wrapper that extracts Zeek evidence into a temporary directory."""
    output_dir = Path(tempfile.mkdtemp(prefix="elevadr-context-discovery-"))
    try:
        return discover_context_with_retained_evidence(
            pcap_path,
            output_dir,
            source_filename=source_filename,
            progress=progress,
        )
    finally:
        shutil.rmtree(output_dir, ignore_errors=True)
