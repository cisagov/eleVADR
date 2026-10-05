from __future__ import annotations

import json
import struct
from pathlib import Path

from backend_bryan.integration.detector_runtime import ensure_detector_package
from backend_bryan.regression.dataset15_fixture_builder import (
    _arp_reply, _dhcp_payload, _ethernet, _modbus_adu, _tcp_frame, _tcp_session, _udp,
)
from backend_bryan.regression.dataset16_fixture_builder import (
    _dns_query, _dns_response, _ntp_packet, _udp_pair,
)
from backend_bryan.regression.dataset17_fixture_builder import _tcp_conversation

ROOT = Path(__file__).resolve().parent
FIXTURE = ROOT / "fixtures" / "19_site_like_multi_hour_ot.pcap"
CONTEXT = ROOT / "fixtures" / "19_site_like_multi_hour_ot_context.json"
MANIFEST = ROOT / "fixtures" / "19_site_like_multi_hour_ot_manifest.json"

# Four-hour deterministic synthetic site.
DURATION = 4 * 60 * 60
PLC_IP, PLC_MAC = "10.190.20.20", "00:19:00:00:20:20"
HMI_IP, HMI_MAC = "10.190.20.30", "00:19:00:00:20:30"
EWS_IP, EWS_MAC = "10.190.10.50", "00:19:00:00:10:50"
DNS_IP, DNS_MAC = "10.190.10.53", "00:19:00:00:10:53"
NTP_IP, NTP_MAC = "10.190.10.123", "00:19:00:00:10:7b"
DHCP_IP, DHCP_MAC = "10.190.10.2", "00:19:00:00:10:02"
CLIENT_IP, CLIENT_MAC = "10.190.10.80", "00:19:00:00:10:80"
CONTRACTOR_IP, CONTRACTOR_MAC = "10.190.10.99", "00:19:00:00:10:99"
MCAST_IP, MCAST_MAC = "239.1.1.1", "01:00:5e:01:01:01"
MCAST_PORT = 31000
BCAST = "ff:ff:ff:ff:ff:ff"


def _write_pcap(path: Path, packets: list[tuple[float, bytes]]) -> None:
    packets.sort(key=lambda item: item[0])
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        handle.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, frame in packets:
            sec = int(ts)
            usec = int(round((ts - sec) * 1_000_000))
            handle.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            handle.write(frame)


def _dhcp_exchange(packets: list[tuple[float, bytes]], *, ts: float, server_ip: str, server_mac: str, xid: int) -> None:
    discover = _dhcp_payload(op=1, xid=xid, client_mac=CLIENT_MAC, msg_type=1)
    offer = _dhcp_payload(op=2, xid=xid, client_mac=CLIENT_MAC, yiaddr=CLIENT_IP, siaddr=server_ip, msg_type=2, server_id=server_ip)
    request = _dhcp_payload(op=1, xid=xid, client_mac=CLIENT_MAC, msg_type=3, server_id=server_ip, requested_ip=CLIENT_IP)
    ack = _dhcp_payload(op=2, xid=xid, client_mac=CLIENT_MAC, yiaddr=CLIENT_IP, siaddr=server_ip, msg_type=5, server_id=server_ip)
    base = int(ts) & 0xFFFF
    packets.extend([
        (ts, _ethernet(CLIENT_MAC, BCAST, 0x0800, _udp("0.0.0.0", "255.255.255.255", 68, 67, discover, base))),
        (ts + 0.2, _ethernet(server_mac, BCAST, 0x0800, _udp(server_ip, "255.255.255.255", 67, 68, offer, base + 1))),
        (ts + 0.4, _ethernet(CLIENT_MAC, BCAST, 0x0800, _udp("0.0.0.0", "255.255.255.255", 68, 67, request, base + 2))),
        (ts + 0.6, _ethernet(server_mac, BCAST, 0x0800, _udp(server_ip, "255.255.255.255", 67, 68, ack, base + 3))),
    ])


def build_fixture(path: Path = FIXTURE) -> Path:
    packets: list[tuple[float, bytes]] = []
    ident = 1000

    # Stable OT polling for the entire four-hour capture. Function 3 is read-only.
    for idx, ts in enumerate(range(0, DURATION + 1, 60)):
        req = _modbus_adu(1000 + idx, 3, address=0, value=8)
        _tcp_session(
            packets, ts=float(ts), client_ip=HMI_IP, server_ip=PLC_IP,
            client_mac=HMI_MAC, server_mac=PLC_MAC, sport=20000 + (idx % 20000),
            request=req, response=req, ident_base=ident,
        )
        ident += 10

    # Expected site DNS and NTP. Both appear during the baseline and stay stable.
    for idx, ts in enumerate(range(30, DURATION + 1, 300)):
        txid = 0x2000 + idx
        _udp_pair(
            packets, ts=float(ts), client_ip=HMI_IP, server_ip=DNS_IP,
            client_mac=HMI_MAC, server_mac=DNS_MAC, client_port=53000 + (idx % 1000), server_port=53,
            request=_dns_query("plc-a.site.local", txid),
            response=_dns_response("plc-a.site.local", txid, PLC_IP), ident=ident,
        )
        ident += 2
    for idx, ts in enumerate(range(45, DURATION + 1, 900)):
        client_tx = 0xE100000000000000 + idx * 3
        _udp_pair(
            packets, ts=float(ts), client_ip=PLC_IP, server_ip=NTP_IP,
            client_mac=PLC_MAC, server_mac=NTP_MAC, client_port=12300 + idx, server_port=123,
            request=_ntp_packet(mode=3, transmit=client_tx),
            response=_ntp_packet(mode=4, originate=client_tx, receive=client_tx + 1, transmit=client_tx + 2), ident=ident,
        )
        ident += 2

    # Expected cyclic multicast telemetry to an explicitly approved group.
    for idx, ts in enumerate(range(15, DURATION + 1, 120)):
        packets.append((float(ts), _ethernet(PLC_MAC, MCAST_MAC, 0x0800, _udp(PLC_IP, MCAST_IP, 41000 + (idx % 1000), MCAST_PORT, b"SITE-TELEMETRY", ident))))
        ident += 1

    # Routine ARP refreshes and DHCP lease churn are legitimate site behavior.
    for ts in range(10, DURATION + 1, 1200):
        packets.append((float(ts), _arp_reply(PLC_IP, PLC_MAC, HMI_IP, HMI_MAC)))
        packets.append((float(ts) + 0.1, _arp_reply(HMI_IP, HMI_MAC, PLC_IP, PLC_MAC)))
    _dhcp_exchange(packets, ts=20.0, server_ip=DHCP_IP, server_mac=DHCP_MAC, xid=0x19000001)
    _dhcp_exchange(packets, ts=7200.0, server_ip=DHCP_IP, server_mac=DHCP_MAC, xid=0x19000002)

    # Scheduled remote-maintenance sessions to the same HMI target; no target fan-out.
    for idx, ts in enumerate((60.0, 3600.0, 7200.0, 10800.0)):
        _tcp_conversation(
            packets, ts=ts, client_ip=EWS_IP, server_ip=HMI_IP,
            client_mac=EWS_MAC, server_mac=HMI_MAC, sport=45000 + idx, dport=3389, ident_base=ident,
        )
        ident += 20

    # Maintenance window: one explicitly authorized Modbus write.
    auth = _modbus_adu(5000, 6, address=200, value=1)
    _tcp_session(
        packets, ts=7250.0, client_ip=EWS_IP, server_ip=PLC_IP,
        client_mac=EWS_MAC, server_mac=PLC_MAC, sport=46000,
        request=auth, response=auth, ident_base=ident,
    )
    ident += 20

    # Deliberate anomaly 1: one unapproved control write from a known contractor host.
    unauth = _modbus_adu(5001, 6, address=201, value=1)
    _tcp_session(
        packets, ts=12600.0, client_ip=CONTRACTOR_IP, server_ip=PLC_IP,
        client_mac=CONTRACTOR_MAC, server_mac=PLC_MAC, sport=47000,
        request=unauth, response=unauth, ident_base=ident,
    )
    ident += 20

    # Deliberate anomaly 2: a known contractor host briefly answers DHCP.
    _dhcp_exchange(packets, ts=13200.0, server_ip=CONTRACTOR_IP, server_mac=CONTRACTOR_MAC, xid=0x1900BAD0)

    # Keep normal periodic traffic alive through the capture end so silence detectors stay quiet.
    packets.append((float(DURATION), _arp_reply(PLC_IP, PLC_MAC, HMI_IP, HMI_MAC)))
    _write_pcap(path, packets)
    return path


def build_context(path: Path = CONTEXT) -> Path:
    _ctx, modules, _pkg = ensure_detector_package()
    selected = sorted(modules)
    profile = {
        "schemaVersion": 3,
        "id": "regression-19",
        "name": "Dataset 19 - Four-Hour OT Site Simulation",
        "segments": [
            {"name": "OT Support", "cidr": "10.190.10.0/24", "role": "OT", "purdueLevel": "Level 2", "addressing": "dhcp", "dhcpAllowed": True},
            {"name": "Cell Control", "cidr": "10.190.20.0/24", "role": "OT", "purdueLevel": "Level 1", "addressing": "static", "dhcpAllowed": False},
        ],
        "assets": [
            {"ip": PLC_IP, "macAddresses": [PLC_MAC], "name": "PLC-A", "role": "OT", "assetType": "PLC", "source": "user"},
            {"ip": HMI_IP, "macAddresses": [HMI_MAC], "name": "HMI-A", "role": "OT", "assetType": "HMI", "source": "user"},
            {"ip": EWS_IP, "macAddresses": [EWS_MAC], "name": "EWS-A", "role": "OT", "assetType": "Engineering Workstation", "source": "user"},
            {"ip": DNS_IP, "macAddresses": [DNS_MAC], "name": "OT-DNS", "role": "OT", "assetType": "Server", "source": "user"},
            {"ip": NTP_IP, "macAddresses": [NTP_MAC], "name": "OT-NTP", "role": "OT", "assetType": "Server", "source": "user"},
            {"ip": DHCP_IP, "macAddresses": [DHCP_MAC], "name": "OT-DHCP", "role": "OT", "assetType": "Server", "source": "user"},
            {"ip": CLIENT_IP, "macAddresses": [CLIENT_MAC], "name": "Mobile-HMI", "role": "OT", "assetType": "HMI", "source": "user"},
            {"ip": CONTRACTOR_IP, "macAddresses": [CONTRACTOR_MAC], "name": "Contractor-Laptop", "role": "OT", "assetType": "Engineering Workstation", "source": "user"},
        ],
        "infrastructure": [
            {"kind": "dns", "value": DNS_IP}, {"kind": "ntp", "value": NTP_IP}, {"kind": "dhcp", "value": DHCP_IP},
        ],
        "communicationPairs": [],
        "allowedHosts": [],
        "allowedSegmentPairs": [{"source": "10.190.10.0/24", "destination": "10.190.20.0/24"}],
        "approvedExternalDestinations": [],
        "captureScope": {"internalIcsOnlyExpected": True, "dedicatedOtSensor": True, "ipv4OnlyExpected": True},
        "authorizedControlActions": [
            {"protocol": "modbus", "source": EWS_IP, "destination": PLC_IP, "allowedFunctionCodes": [6], "allowedOperations": ["write"]}
        ],
        "modulePolicies": {
            "remote_access_tool_exposure": {"allowed_hosts": [EWS_IP]},
            "remote_access_session_anomaly": {"authorized_sources": [EWS_IP], "baseline_seconds": 900, "minimum_new_targets": 2},
            "unexpected_multicast_behavior": {"allowed_groups": [MCAST_IP], "minimum_flows": 3},
            "excessive_broadcast_multicast_ot": {"ignored_destinations": [MCAST_IP, "255.255.255.255"]},
            "new_ot_conversation_pair": {"baseline_seconds": 900, "ignored_hosts": [CONTRACTOR_IP], "allowed_pairs": [[EWS_IP, HMI_IP], [EWS_IP, PLC_IP], [HMI_IP, DNS_IP], [PLC_IP, NTP_IP]]},
            "plc_rtu_peer_change": {"baseline_seconds": 900, "ignored_hosts": [CONTRACTOR_IP], "allowed_pairs": [{"source": EWS_IP, "destination": PLC_IP}]},
            "ot_asset_gone_silent": {"baseline_seconds": 900, "ignored_hosts": [DNS_IP, NTP_IP, DHCP_IP, CLIENT_IP, CONTRACTOR_IP]},
            "unexpected_dhcp_server": {"expected_servers": [DHCP_IP]},
            "rogue_dhcp_static_ot": {"expected_servers": [DHCP_IP]},
        },
        "selectedModules": selected,
        "scan": {"simulation": {"durationSeconds": DURATION, "maintenanceWindowSeconds": [7200, 7500]}},
    }
    path.write_text(json.dumps(profile, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def build_manifest(path: Path = MANIFEST) -> Path:
    manifest = {
        "dataset": "19_site_like_multi_hour_ot",
        "purpose": "False-positive tripwire across the complete 75-detector registry using a four-hour site-like OT simulation.",
        "duration_seconds": DURATION,
        "deliberate_anomalies": [
            {"id": "unauthorized_modbus_write", "timestamp": 12600, "expected_modules": ["ics_write_operations"]},
            {"id": "unexpected_dhcp_server", "timestamp": 13200, "expected_modules": ["unexpected_dhcp_server", "rogue_dhcp_static_ot"]},
        ],
        "allowed_finding_modules": ["ics_write_operations", "unexpected_dhcp_server", "rogue_dhcp_static_ot"],
        "required_finding_modules": ["ics_write_operations", "unexpected_dhcp_server", "rogue_dhcp_static_ot"],
        "normal_behaviors": [
            "60-second Modbus polling", "internal DNS", "internal NTP", "approved multicast telemetry",
            "DHCP lease renewal", "scheduled RDP maintenance", "authorized maintenance write", "routine ARP refresh",
        ],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def build_all() -> tuple[Path, Path, Path]:
    return build_fixture(), build_context(), build_manifest()


if __name__ == "__main__":
    for result in build_all():
        print(result)
