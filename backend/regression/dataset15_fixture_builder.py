from __future__ import annotations

import ipaddress
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent
FIXTURE = ROOT / "fixtures" / "15_new_detector_raw_pcap.pcap"

PLC_IP = "10.150.0.20"
PLC_MAC = "00:11:22:33:44:55"
EWS_IP = "10.150.0.50"
EWS_MAC = "00:11:22:33:44:50"
ROGUE_IP = "10.150.0.99"
ROGUE_MAC = "66:77:88:99:aa:bb"
PEER_IP = "10.150.0.60"
PEER_MAC = "00:11:22:33:44:60"
CLIENT_IP = "10.150.0.30"
CLIENT_MAC = "02:00:00:00:00:30"
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
ZERO_MAC = "00:00:00:00:00:00"


def _mac(value: str) -> bytes:
    return bytes.fromhex(value.replace(":", ""))


def _ip(value: str) -> bytes:
    return ipaddress.ip_address(value).packed


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _ethernet(src_mac: str, dst_mac: str, ethertype: int, payload: bytes) -> bytes:
    return _mac(dst_mac) + _mac(src_mac) + struct.pack("!H", ethertype) + payload


def _arp_reply(sender_ip: str, sender_mac: str, target_ip: str, target_mac: str) -> bytes:
    payload = struct.pack(
        "!HHBBH6s4s6s4s",
        1,
        0x0800,
        6,
        4,
        2,
        _mac(sender_mac),
        _ip(sender_ip),
        _mac(target_mac),
        _ip(target_ip),
    )
    return _ethernet(sender_mac, target_mac, 0x0806, payload)


def _ipv4(src_ip: str, dst_ip: str, proto: int, payload: bytes, ident: int) -> bytes:
    ver_ihl = 0x45
    total_len = 20 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl,
        0,
        total_len,
        ident & 0xFFFF,
        0x4000,
        64,
        proto,
        0,
        _ip(src_ip),
        _ip(dst_ip),
    )
    csum = _checksum(header)
    header = header[:10] + struct.pack("!H", csum) + header[12:]
    return header + payload


def _udp(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes, ident: int) -> bytes:
    # IPv4 permits a zero UDP checksum. Keeping it zero makes the synthetic
    # fixture deterministic while remaining standards-compliant.
    segment = struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0) + payload
    return _ipv4(src_ip, dst_ip, 17, segment, ident)


def _tcp_segment(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes,
) -> bytes:
    offset_flags = (5 << 12) | flags
    header = struct.pack(
        "!HHIIHHHH",
        src_port,
        dst_port,
        seq,
        ack,
        offset_flags,
        64240,
        0,
        0,
    )
    pseudo = _ip(src_ip) + _ip(dst_ip) + struct.pack("!BBH", 0, 6, len(header) + len(payload))
    csum = _checksum(pseudo + header + payload)
    return header[:16] + struct.pack("!H", csum) + header[18:] + payload


def _tcp_frame(
    src_ip: str,
    dst_ip: str,
    src_mac: str,
    dst_mac: str,
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes,
    ident: int,
) -> bytes:
    tcp = _tcp_segment(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload)
    return _ethernet(src_mac, dst_mac, 0x0800, _ipv4(src_ip, dst_ip, 6, tcp, ident))


def _dhcp_payload(
    *,
    op: int,
    xid: int,
    client_mac: str,
    yiaddr: str = "0.0.0.0",
    siaddr: str = "0.0.0.0",
    msg_type: int,
    server_id: str | None = None,
    requested_ip: str | None = None,
) -> bytes:
    chaddr = _mac(client_mac) + b"\x00" * 10
    fixed = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s",
        op,
        1,
        6,
        0,
        xid,
        0,
        0x8000,
        _ip("0.0.0.0"),
        _ip(yiaddr),
        _ip(siaddr),
        _ip("0.0.0.0"),
        chaddr,
        b"\x00" * 64,
        b"\x00" * 128,
    )
    options = bytearray(b"\x63\x82\x53\x63")
    options += bytes([53, 1, msg_type])
    if requested_ip:
        options += bytes([50, 4]) + _ip(requested_ip)
    if server_id:
        options += bytes([54, 4]) + _ip(server_id)
    if msg_type in {2, 5}:
        options += bytes([51, 4]) + struct.pack("!I", 3600)
        options += bytes([1, 4]) + _ip("255.255.255.0")
    options += b"\xff"
    return fixed + bytes(options)


def _modbus_adu(transaction: int, function: int, address: int = 1, value: int = 1) -> bytes:
    pdu = struct.pack("!BHH", function, address, value)
    return struct.pack("!HHHB", transaction & 0xFFFF, 0, 1 + len(pdu), 1) + pdu


def _tcp_session(
    packets: list[tuple[float, bytes]],
    *,
    ts: float,
    client_ip: str,
    server_ip: str,
    client_mac: str,
    server_mac: str,
    sport: int,
    request: bytes,
    response: bytes,
    ident_base: int,
) -> None:
    cseq = 100000 + sport
    sseq = 200000 + sport
    steps = [
        (0.000, client_ip, server_ip, client_mac, server_mac, sport, 502, cseq, 0, 0x02, b""),
        (0.010, server_ip, client_ip, server_mac, client_mac, 502, sport, sseq, cseq + 1, 0x12, b""),
        (0.020, client_ip, server_ip, client_mac, server_mac, sport, 502, cseq + 1, sseq + 1, 0x10, b""),
        (0.030, client_ip, server_ip, client_mac, server_mac, sport, 502, cseq + 1, sseq + 1, 0x18, request),
        (0.040, server_ip, client_ip, server_mac, client_mac, 502, sport, sseq + 1, cseq + 1 + len(request), 0x18, response),
        (0.050, client_ip, server_ip, client_mac, server_mac, sport, 502, cseq + 1 + len(request), sseq + 1 + len(response), 0x11, b""),
        (0.060, server_ip, client_ip, server_mac, client_mac, 502, sport, sseq + 1 + len(response), cseq + 2 + len(request), 0x11, b""),
        (0.070, client_ip, server_ip, client_mac, server_mac, sport, 502, cseq + 2 + len(request), sseq + 2 + len(response), 0x10, b""),
    ]
    for index, (delta, sip, dip, smac, dmac, sp, dp, seq, ack, flags, payload) in enumerate(steps):
        packets.append((ts + delta, _tcp_frame(sip, dip, smac, dmac, sp, dp, seq, ack, flags, payload, ident_base + index)))


def build_fixture(path: Path = FIXTURE) -> Path:
    packets: list[tuple[float, bytes]] = []

    # ARP identity: the authoritative PLC identity is first seen correctly,
    # then the same IP is claimed by a different MAC one second later.
    packets.append((1.0, _arp_reply(PLC_IP, PLC_MAC, EWS_IP, EWS_MAC)))
    packets.append((2.0, _arp_reply(PLC_IP, ROGUE_MAC, EWS_IP, EWS_MAC)))

    # Rogue DHCP transaction. Detection Context trusts 10.150.0.2, not .99.
    xid = 0x1234ABCD
    discover = _dhcp_payload(op=1, xid=xid, client_mac=CLIENT_MAC, msg_type=1)
    offer = _dhcp_payload(op=2, xid=xid, client_mac=CLIENT_MAC, yiaddr=CLIENT_IP, siaddr=ROGUE_IP, msg_type=2, server_id=ROGUE_IP)
    request = _dhcp_payload(op=1, xid=xid, client_mac=CLIENT_MAC, msg_type=3, server_id=ROGUE_IP, requested_ip=CLIENT_IP)
    ack = _dhcp_payload(op=2, xid=xid, client_mac=CLIENT_MAC, yiaddr=CLIENT_IP, siaddr=ROGUE_IP, msg_type=5, server_id=ROGUE_IP)
    packets.append((4.0, _ethernet(CLIENT_MAC, BROADCAST_MAC, 0x0800, _udp("0.0.0.0", "255.255.255.255", 68, 67, discover, 100))))
    packets.append((5.0, _ethernet(ROGUE_MAC, BROADCAST_MAC, 0x0800, _udp(ROGUE_IP, "255.255.255.255", 67, 68, offer, 101))))
    packets.append((6.0, _ethernet(CLIENT_MAC, BROADCAST_MAC, 0x0800, _udp("0.0.0.0", "255.255.255.255", 68, 67, request, 102))))
    packets.append((7.0, _ethernet(ROGUE_MAC, BROADCAST_MAC, 0x0800, _udp(ROGUE_IP, "255.255.255.255", 67, 68, ack, 103))))

    # Five authorized write-single-register transactions from the engineering
    # workstation. These establish the PLC as a Modbus responder and also form
    # a control-operation burst within 60 seconds.
    for i, ts in enumerate((10.0, 20.0, 30.0, 40.0, 50.0), start=1):
        adu = _modbus_adu(100 + i, 6, address=100 + i, value=i)
        _tcp_session(
            packets,
            ts=ts,
            client_ip=EWS_IP,
            server_ip=PLC_IP,
            client_mac=EWS_MAC,
            server_mac=PLC_MAC,
            sport=15000 + i,
            request=adu,
            response=adu,
            ident_base=200 + i * 10,
        )

    # After the 120-second baseline, the PLC originates Modbus traffic itself.
    # This is the role-reversal case and also a new controller peer.
    read_adu = _modbus_adu(300, 3, address=0, value=2)
    _tcp_session(
        packets,
        ts=200.0,
        client_ip=PLC_IP,
        server_ip=PEER_IP,
        client_mac=PLC_MAC,
        server_mac=PEER_MAC,
        sport=16000,
        request=read_adu,
        response=read_adu,
        ident_base=400,
    )

    # A second new post-baseline peer initiates Modbus toward the PLC.
    rogue_read = _modbus_adu(301, 3, address=10, value=1)
    _tcp_session(
        packets,
        ts=210.0,
        client_ip=ROGUE_IP,
        server_ip=PLC_IP,
        client_mac=ROGUE_MAC,
        server_mac=PLC_MAC,
        sport=17000,
        request=rogue_read,
        response=rogue_read,
        ident_base=500,
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
    result = build_fixture()
    print(result)
