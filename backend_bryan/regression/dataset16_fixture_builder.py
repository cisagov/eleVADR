from __future__ import annotations

import struct
from pathlib import Path

from backend_bryan.regression.dataset15_fixture_builder import (
    _ethernet,
    _ip,
    _ipv4,
    _mac,
    _tcp_frame,
    _udp,
)

ROOT = Path(__file__).resolve().parent
FIXTURE = ROOT / "fixtures" / "16_wave2_raw_pcap.pcap"

OT_CLIENT_IP = "10.160.0.20"
OT_CLIENT_MAC = "00:16:00:00:00:20"
TRUSTED_DNS_IP = "10.160.0.2"
TRUSTED_DNS_MAC = "00:16:00:00:00:02"
TRUSTED_NTP_IP = "10.160.0.3"
TRUSTED_NTP_MAC = "00:16:00:00:00:03"
ROGUE_INFRA_IP = "10.160.0.99"
ROGUE_INFRA_MAC = "00:16:00:00:00:99"
SCANNER_IP = "10.160.0.50"
SCANNER_MAC = "00:16:00:00:00:50"
MULTICAST_MAC = "01:00:5e:09:09:09"
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
ZERO_MAC = "00:00:00:00:00:00"


def _arp_request(sender_ip: str, sender_mac: str, target_ip: str) -> bytes:
    payload = struct.pack(
        "!HHBBH6s4s6s4s",
        1,
        0x0800,
        6,
        4,
        1,
        _mac(sender_mac),
        _ip(sender_ip),
        _mac(ZERO_MAC),
        _ip(target_ip),
    )
    return _ethernet(sender_mac, BROADCAST_MAC, 0x0806, payload)


def _dns_query(name: str, txid: int) -> bytes:
    labels = b"".join(bytes([len(part)]) + part.encode("ascii") for part in name.split(".")) + b"\x00"
    header = struct.pack("!HHHHHH", txid & 0xFFFF, 0x0100, 1, 0, 0, 0)
    return header + labels + struct.pack("!HH", 1, 1)


def _dns_response(name: str, txid: int, answer_ip: str) -> bytes:
    labels = b"".join(bytes([len(part)]) + part.encode("ascii") for part in name.split(".")) + b"\x00"
    header = struct.pack("!HHHHHH", txid & 0xFFFF, 0x8180, 1, 1, 0, 0)
    question = labels + struct.pack("!HH", 1, 1)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + _ip(answer_ip)
    return header + question + answer


def _ntp_packet(*, mode: int, originate: int = 0, receive: int = 0, transmit: int = 0) -> bytes:
    # Minimal NTPv4 packet.  The fixed-point timestamp values are arbitrary but
    # deterministic; Zeek only needs a structurally valid NTP message here.
    first = (4 << 3) | (mode & 0x7)
    return struct.pack(
        "!BBBbII4sQQQQ",
        first,
        2 if mode == 4 else 0,
        6,
        -20,
        0,
        0,
        b"LOCL" if mode == 4 else b"\x00\x00\x00\x00",
        0,
        originate,
        receive,
        transmit,
    )


def _udp_pair(
    packets: list[tuple[float, bytes]],
    *,
    ts: float,
    client_ip: str,
    server_ip: str,
    client_mac: str,
    server_mac: str,
    client_port: int,
    server_port: int,
    request: bytes,
    response: bytes,
    ident: int,
) -> None:
    packets.append(
        (
            ts,
            _ethernet(
                client_mac,
                server_mac,
                0x0800,
                _udp(client_ip, server_ip, client_port, server_port, request, ident),
            ),
        )
    )
    packets.append(
        (
            ts + 0.05,
            _ethernet(
                server_mac,
                client_mac,
                0x0800,
                _udp(server_ip, client_ip, server_port, client_port, response, ident + 1),
            ),
        )
    )


def build_fixture(path: Path = FIXTURE) -> Path:
    packets: list[tuple[float, bytes]] = []

    # DNS: establish the trusted resolver first, then use an explicitly untrusted
    # resolver after the 120-second detector baseline.
    for ts, server_ip, server_mac, txid in (
        (5.0, TRUSTED_DNS_IP, TRUSTED_DNS_MAC, 0x1001),
        (200.0, ROGUE_INFRA_IP, ROGUE_INFRA_MAC, 0x1002),
    ):
        _udp_pair(
            packets,
            ts=ts,
            client_ip=OT_CLIENT_IP,
            server_ip=server_ip,
            client_mac=OT_CLIENT_MAC,
            server_mac=server_mac,
            client_port=53000 + (txid & 0xFF),
            server_port=53,
            request=_dns_query("plc.example", txid),
            response=_dns_response("plc.example", txid, "10.160.0.20"),
            ident=100 + (txid & 0xFF),
        )

    # NTP: same trusted-then-untrusted pattern, with valid request/response
    # packets so Zeek's NTP analyzer emits ntp.log evidence.
    for index, (ts, server_ip, server_mac) in enumerate(
        ((10.0, TRUSTED_NTP_IP, TRUSTED_NTP_MAC), (210.0, ROGUE_INFRA_IP, ROGUE_INFRA_MAC)),
        start=1,
    ):
        client_tx = 0xE000000000000000 + index
        server_rx = client_tx + 1
        server_tx = client_tx + 2
        _udp_pair(
            packets,
            ts=ts,
            client_ip=OT_CLIENT_IP,
            server_ip=server_ip,
            client_mac=OT_CLIENT_MAC,
            server_mac=server_mac,
            client_port=12300 + index,
            server_port=123,
            request=_ntp_packet(mode=3, transmit=client_tx),
            response=_ntp_packet(mode=4, originate=client_tx, receive=server_rx, transmit=server_tx),
            ident=200 + index * 10,
        )

    # ARP reconnaissance: 20 distinct targets inside 19 seconds.
    for i in range(20):
        target = f"10.160.0.{100 + i}"
        packets.append((30.0 + i, _arp_request(SCANNER_IP, SCANNER_MAC, target)))

    # Unexpected multicast: use three distinct source ports so Zeek records
    # three separate conn.log flows to the same unapproved group.
    for i in range(3):
        payload = b"ELEVADR-MCAST-" + bytes([i])
        packets.append(
            (
                70.0 + i,
                _ethernet(
                    OT_CLIENT_MAC,
                    MULTICAST_MAC,
                    0x0800,
                    _udp(OT_CLIENT_IP, "239.9.9.9", 40000 + i, 2222, payload, 300 + i),
                ),
            )
        )

    # TCP reset/reject surge: 10 rejected connection attempts to one OT target
    # within 20 seconds.  A responder RST+ACK after SYN is represented by Zeek
    # as a rejected/reset connection state (typically REJ).
    for i in range(10):
        ts = 90.0 + i * 2
        sport = 45000 + i
        cseq = 1000 + i * 100
        packets.append(
            (
                ts,
                _tcp_frame(
                    SCANNER_IP,
                    OT_CLIENT_IP,
                    SCANNER_MAC,
                    OT_CLIENT_MAC,
                    sport,
                    5020,
                    cseq,
                    0,
                    0x02,
                    b"",
                    400 + i * 2,
                ),
            )
        )
        packets.append(
            (
                ts + 0.02,
                _tcp_frame(
                    OT_CLIENT_IP,
                    SCANNER_IP,
                    OT_CLIENT_MAC,
                    SCANNER_MAC,
                    5020,
                    sport,
                    0,
                    cseq + 1,
                    0x14,
                    b"",
                    401 + i * 2,
                ),
            )
        )

    packets.sort(key=lambda item: item[0])
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        handle.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, frame in packets:
            sec = int(ts)
            usec = int(round((ts - sec) * 1_000_000))
            handle.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            handle.write(frame)
    return path


if __name__ == "__main__":
    print(build_fixture())
