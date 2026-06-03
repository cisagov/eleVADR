"""Utility functions for network traffic analysis and data processing."""

# Standard Python Libraries
import ipaddress
import os
from collections import Counter
from enum import Enum
from pathlib import Path
from typing import Any

# Third-Party Libraries
import numpy as np
import pandas as pd


def _normalize_categories(categories: Any) -> str | None:
    """Convert list-like categories to a comma-separated string.

    Return ``None`` for null-ish or empty values.
    """
    if isinstance(categories, (list, np.ndarray)):
        # Filter out None/NaN from the list before joining
        filtered_categories = [
            str(x)
            for x in categories
            if x is not None and pd.notna(x) and str(x).strip() != ""
        ]
        if not filtered_categories:
            return None  # Return None if no valid categories remain
        return ", ".join(filtered_categories)
    elif (
        categories is None
        or pd.isna(categories)
        or (isinstance(categories, str) and categories.strip() == "")
    ):
        return None
    return str(categories)  # For single string values or other types


class FilePathInfo:
    """Container for file path configuration."""

    def __init__(
        self,
        path_to_pcap: str | None = None,
        path_to_zeek: str | None = None,
        path_to_zeek_scripts: str | None = None,
        path_to_assessor_data: str | None = None,
    ) -> None:
        """Initialize configured filesystem paths and ensure parent dirs exist."""
        self.path_to_pcap = path_to_pcap
        self.path_to_zeek = path_to_zeek
        self.path_to_zeek_scripts = path_to_zeek_scripts
        self.path_to_assessor_data = path_to_assessor_data

        # Create directories if they don't exist
        for path in [path_to_zeek, path_to_zeek_scripts, path_to_assessor_data]:
            if path and not Path(path).exists():
                os.mkdir(path)

        if path_to_pcap:
            pcap_parent = Path(path_to_pcap.rsplit("/", 1)[0])
            if not pcap_parent.exists():
                os.mkdir(pcap_parent)


class PortType(Enum):
    """Define the status of the port for service analysis."""

    KNOWN = 0  # eleVADR has a known service mapping for this port
    UNKNOWN_PRIV = (
        1  # unknown service operating on a port less than 1024, the privileged range
    )
    UNKNOWN = 2  # port between 1024 and 49152 without a mapping in eleVADR
    EPHEMERAL = (
        3  # ephemeral port, used for the client side of client-server communications
    )


# IP Processing Functions


def is_public_ip(ip: str) -> bool:
    """Check if an IP address is public (global)."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_global
    except ValueError, AttributeError:
        return False


def check_ip_version(ip: str) -> int:
    """Return IP version (4, 6, or 99 for invalid)."""
    try:
        return ipaddress.ip_address(str(ip)).version
    except ValueError:
        return 99


def connection_type_processing(ip: str) -> str | None:
    """Classify connection type: multicast, link-local, broadcast, or unicast."""
    try:
        ip_obj = ipaddress.ip_address(str(ip))

        if ip_obj.is_multicast:
            return "multicast"
        elif ip_obj.is_link_local:
            return "link-local"
        elif (
            ip_obj.version == 4
            and int.from_bytes(ip_obj.packed, byteorder="big") & 255 == 255
        ):
            return "broadcast"
        else:
            return "unicast"
    except ValueError, AttributeError:
        return None


def traffic_direction(row: pd.Series) -> str | None:
    """Determine traffic direction: inbound, outbound, lateral, external, or other."""
    try:
        src_ip = ipaddress.ip_address(row["src_endpoint.ip"])
        dst_ip = ipaddress.ip_address(row["dst_endpoint.ip"])
    except ValueError, KeyError:
        return None

    def _is_internal(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        # An IP is internal if it's private, loopback, or link-local.
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast

    src_is_internal = _is_internal(src_ip)
    dst_is_internal = _is_internal(dst_ip)

    if src_is_internal and dst_is_internal:
        return "lateral"
    if src_is_internal and not dst_is_internal:
        return "outbound"
    if not src_is_internal and dst_is_internal:
        return "inbound"
    if not src_is_internal and not dst_is_internal:
        if src_ip.version == dst_ip.version:
            return "external"
        else:
            return "other"

    return None


def subnet_membership(
    row: pd.Series,
    known_subnets: list[str] | None = None,
) -> pd.Series:
    """Calculate /24 subnet membership for source and destination IPs."""
    src_subnet: str | None = None
    dst_subnet: str | None = None

    src_ip_str = str(row.get("src_endpoint.ip", ""))
    dst_ip_str = str(row.get("dst_endpoint.ip", ""))

    if known_subnets:
        for subnet in known_subnets:
            try:
                network = ipaddress.ip_network(subnet, strict=False)
                if ipaddress.ip_address(row["src_endpoint.ip"]) in network:
                    src_subnet = str(network)
                if ipaddress.ip_address(row["dst_endpoint.ip"]) in network:
                    dst_subnet = str(network)
            except ValueError:
                pass
    else:
        if row["connection_info.protocol_ver_id"] == 4:
            try:
                src_ip_v4 = ipaddress.IPv4Address(src_ip_str)
                if src_ip_v4 != ipaddress.IPv4Address("0.0.0.0"):
                    src_network_v4 = ipaddress.IPv4Network(
                        f"{src_ip_v4}/24", strict=False
                    )
                    src_subnet = str(src_network_v4)
            except ValueError, ipaddress.AddressValueError:
                pass

            try:
                if dst_ip_str == "255.255.255.255":
                    dst_subnet = src_subnet
                elif dst_ip_str != "0.0.0.0":
                    dst_ip_v4 = ipaddress.IPv4Address(dst_ip_str)
                    dst_network_v4 = ipaddress.IPv4Network(
                        f"{dst_ip_v4}/24", strict=False
                    )
                    dst_subnet = str(dst_network_v4)
            except ValueError, ipaddress.AddressValueError:
                pass
        elif row["connection_info.protocol_ver_id"] == 6:
            try:
                src_ip_v6 = ipaddress.IPv6Address(src_ip_str)
                if src_ip_v6 != ipaddress.IPv6Address("::"):
                    src_network_v6 = ipaddress.IPv6Network(
                        f"{src_ip_v6}/64", strict=False
                    )
                    src_subnet = str(src_network_v6)

                if dst_ip_str != "::":
                    dst_ip_v6 = ipaddress.IPv6Address(dst_ip_str)
                    dst_network_v6 = ipaddress.IPv6Network(
                        f"{dst_ip_v6}/64", strict=False
                    )
                    dst_subnet = str(dst_network_v6)
            except ValueError, ipaddress.AddressValueError:
                pass

    row["src_endpoint.subnet"] = src_subnet
    row["dst_endpoint.subnet"] = dst_subnet
    return row


# Service Processing Functions


def service_processing(
    row: pd.Series, ports_df: pd.DataFrame, port_risk_df: pd.DataFrame
) -> pd.Series:
    """Map port to service name and enrich with risk information."""
    port = row["dst_endpoint.port"]
    # port_str = str(port) # No longer strictly needed for lookups on 'port' column

    # Initialize all service fields to None/default
    row["service.name"] = None
    row["service.is_ot"] = False
    row["service.description"] = None
    row["service.information_categories"] = None
    row["service.risk_categories"] = None
    row["service.risk_basis"] = None
    row["service.environment_exposure"] = None
    row["service.protocol_posture"] = None
    row["service.port_type"] = (
        None  # Will be set to KNOWN if found, else UNKNOWN_PRIV/UNKNOWN/EPHEMERAL
    )

    # Flag to track if the port is "known" in either dataset
    is_known_port = False

    # 1. Try to get basic service info from ports_df
    # Assuming ports_df also has a 'port' column after conversion
    ports_match = ports_df[ports_df["port"] == port]
    if not ports_match.empty:
        ports_row = ports_match.iloc[0]  # Get the first matching row
        row["service.name"] = ports_row["Service Name"]
        row["service.is_ot"] = ports_row["OT System Type"]
        row["service.port_type"] = PortType.KNOWN.name
        is_known_port = True

    # 2. Try to get risk info from port_risk_df
    port_risk_match = port_risk_df[port_risk_df["port"] == port]
    if not port_risk_match.empty:
        port_risk_row = port_risk_match.iloc[0]  # Get the first matching row
        # If port_risk_df has a service name, use it
        # (overwriting if ports_df already set one)
        if "service" in port_risk_row and pd.notna(port_risk_row["service"]):
            row["service.name"] = port_risk_row["service"]
        else:
            raise ValueError(f"Port {port} does not have a service name defined!")

        row["service.description"] = port_risk_row["description"]
        row["service.information_categories"] = _normalize_categories(
            port_risk_row["information_categories"]
        )
        row["service.risk_categories"] = _normalize_categories(
            port_risk_row["risk_categories"]
        )
        row["service.risk_basis"] = port_risk_row.get("risk_basis")
        row["service.environment_exposure"] = port_risk_row.get("environment_exposure")
        row["service.protocol_posture"] = port_risk_row.get("protocol_posture")

        # If risk info is found, it's a known port, even if ports_df didn't have a name
        row["service.port_type"] = PortType.KNOWN.name
        is_known_port = True

        # # Fall back to "KNOWN <port>" if neither ports_df
        # nor port_risk_df provided a specific name
        if row["service.name"] is None:
            row["service.name"] = f"KNOWN {port}"  # Use port (int) directly

    # 3. If still not known, categorize as unknown/ephemeral
    if not is_known_port:
        row["service.is_ot"] = False  # Default to false if not in known ports
        if int(port) < 1024:
            row["service.port_type"] = PortType.UNKNOWN_PRIV.name
            row["service.name"] = PortType.UNKNOWN_PRIV.name + " " + str(port)
            row["service.description"] = (
                "Unassigned well-known port number; this port should not be used."
            )
            row["service.risk_categories"] = _normalize_categories(
                ["Legacy Protocol", "Unknown Service"]
            )
        elif int(port) < 49151:
            row["service.port_type"] = PortType.UNKNOWN.name
            row["service.name"] = PortType.UNKNOWN.name + " " + str(port)
            row["service.description"] = (
                "Unknown assigned port. Please inform CISA which vendor or "
                "service we should track at elevadr@cisa.dhs.gov."
            )
            row["service.risk_categories"] = _normalize_categories(["Unknown Service"])
        else:
            row["service.port_type"] = PortType.EPHEMERAL.name
            row["service.name"] = PortType.EPHEMERAL.name + " " + str(port)
            row["service.description"] = PortType.EPHEMERAL.name + " " + str(port)
            # Ephemeral ports typically don't have risk categories
            # unless explicitly assigned
            row["service.risk_categories"] = _normalize_categories([])

    # Ensure name is never None regardless of lookup path
    if row["service.name"] is None:
        row["service.name"] = (
            f"{row['service.port_type']} {port}"
            if row["service.port_type"]
            else f"UNKNOWN {port}"
        )

    return row


# Endpoint Processing Functions


def set_manufacturers(row: pd.Series, manufacturers_df: pd.DataFrame) -> pd.Series:
    """Look up device manufacturer from MAC address OUI."""
    mac = row["device.mac"]
    if not isinstance(mac, str) or mac.strip() == "":
        row["device.manufacturer"] = None
        return row

    normalized_mac = mac.replace(":", "-").upper()
    oui = normalized_mac[:8] if "-" in normalized_mac else normalized_mac[:6]

    try:
        val = manufacturers_df.at[oui, "manufacturer"]
        row["device.manufacturer"] = None if pd.isna(val) else val
    except KeyError:
        row["device.manufacturer"] = None

    return row


def is_using_ot_services(row: pd.Series, traffic_df: pd.DataFrame) -> bool:
    """Check if device uses industrial/OT protocols across any of its IPs."""
    ipv4 = row.get("device.ipv4_ips")
    ipv6 = row.get("device.ipv6_ips")

    ips_to_check: list[str] = []
    if isinstance(ipv4, list):
        ips_to_check.extend(ipv4)
    if isinstance(ipv6, list):
        ips_to_check.extend(ipv6)

    if not ips_to_check:
        return False

    device_traffic = traffic_df[
        traffic_df["src_endpoint.ip"].isin(ips_to_check)
        | traffic_df["dst_endpoint.ip"].isin(ips_to_check)
    ]

    if device_traffic.empty:
        return False

    return bool(device_traffic["service.is_ot"].any())


def is_communicating_with_ot_hosts(
    row: pd.Series, traffic_df: pd.DataFrame, ot_ips: set[str]
) -> pd.Series:
    """Check if non-OT device communicates with known OT devices."""
    if row.get("device.is_ot") is True:
        return row

    ipv4 = row.get("device.ipv4_ips")
    ipv6 = row.get("device.ipv6_ips")

    device_ips: list[str] = []
    if isinstance(ipv4, list):
        device_ips.extend(ipv4)
    if isinstance(ipv6, list):
        device_ips.extend(ipv6)

    if not device_ips:
        return row

    device_traffic = traffic_df[
        traffic_df["src_endpoint.ip"].isin(device_ips)
        | traffic_df["dst_endpoint.ip"].isin(device_ips)
    ]

    connected_ips = set(device_traffic["src_endpoint.ip"]) | set(
        device_traffic["dst_endpoint.ip"]
    )
    connected_ips -= set(device_ips)

    if not connected_ips.isdisjoint(ot_ips):
        row["device.is_ot"] = True
    return row


def convert_list_col_to_str(row: pd.Series, column_name: str) -> pd.Series:
    """Convert list values in column to comma-separated strings."""
    value = row[column_name]
    if isinstance(value, list):
        row[column_name] = ", ".join(value) if value else value
    return row


def count_values_in_list_column(
    df: pd.DataFrame,
    column: str,
) -> dict[str, int]:
    """Count occurrences of values in a comma-separated string column."""
    counter: Counter[str] = Counter()
    for _, row in df.iterrows():
        values = row[column]
        if isinstance(values, str):
            if values != "":  # Prevent counting cases of blank values
                value_list = list(values.split(", "))
                counter.update(value_list)
    return dict(counter)
