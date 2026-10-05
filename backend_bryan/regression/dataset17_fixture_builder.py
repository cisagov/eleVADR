from __future__ import annotations

import struct
from pathlib import Path

from backend_bryan.regression.dataset15_fixture_builder import _ethernet, _tcp_frame

ROOT = Path(__file__).resolve().parent
FIXTURE = ROOT / "fixtures" / "17_wave3_raw_pcap.pcap"

TLS_CLIENT_IP = "10.170.0.10"
TLS_CLIENT_MAC = "00:17:00:00:00:10"
TLS_SERVER_IP = "10.170.0.11"
TLS_SERVER_MAC = "00:17:00:00:00:11"
MGMT_IP = "10.170.0.5"
MGMT_MAC = "00:17:00:00:00:05"
RDP_BASE_IP = "10.170.0.21"
RDP_BASE_MAC = "00:17:00:00:00:21"
RDP_NEW1_IP = "10.170.0.22"
RDP_NEW1_MAC = "00:17:00:00:00:22"
RDP_NEW2_IP = "10.170.0.23"
RDP_NEW2_MAC = "00:17:00:00:00:23"
SERVICE_CLIENT_IP = "10.170.0.31"
SERVICE_CLIENT_MAC = "00:17:00:00:00:31"
SERVICE_HOST_IP = "10.170.0.30"
SERVICE_HOST_MAC = "00:17:00:00:00:30"
POLL_CLIENT_IP = "10.170.0.41"
POLL_CLIENT_MAC = "00:17:00:00:00:41"
POLL_HOST_IP = "10.170.0.40"
POLL_HOST_MAC = "00:17:00:00:00:40"
CONTROLLER_IP = "10.170.0.50"
CONTROLLER_MAC = "00:17:00:00:00:50"
JITTER_PEER_IP = "10.170.0.60"
JITTER_PEER_MAC = "00:17:00:00:00:60"


def _tls_client_hello(server_name: str, *, cipher_suite: int = 0x002F) -> bytes:
    # TLS 1.2 ClientHello with a single SNI and cipher suite.  It is intentionally
    # small but structurally valid enough for Zeek's SSL analyzer.
    name = server_name.encode("ascii")
    sni_entry = b"\x00" + struct.pack("!H", len(name)) + name
    sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
    sni_ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list
    body = (
        b"\x03\x03"
        + bytes(range(32))
        + b"\x00"
        + struct.pack("!H", 2)
        + struct.pack("!H", cipher_suite)
        + b"\x01\x00"
        + struct.pack("!H", len(sni_ext))
        + sni_ext
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def _tls_server_hello(*, cipher_suite: int = 0x002F) -> bytes:
    body = (
        b"\x03\x03"
        + bytes(reversed(range(32)))
        + b"\x00"
        + struct.pack("!H", cipher_suite)
        + b"\x00"
        + b"\x00\x00"
    )
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + struct.pack("!H", len(handshake)) + handshake


def _tcp_conversation(
    packets: list[tuple[float, bytes]],
    *,
    ts: float,
    client_ip: str,
    server_ip: str,
    client_mac: str,
    server_mac: str,
    sport: int,
    dport: int,
    ident_base: int,
    client_payload: bytes = b"",
    server_payload: bytes = b"",
) -> None:
    cseq = 100000 + ident_base * 10
    sseq = 200000 + ident_base * 10
    steps: list[tuple[float, str, str, str, str, int, int, int, int, int, bytes]] = [
        (0.000, client_ip, server_ip, client_mac, server_mac, sport, dport, cseq, 0, 0x02, b""),
        (0.010, server_ip, client_ip, server_mac, client_mac, dport, sport, sseq, cseq + 1, 0x12, b""),
        (0.020, client_ip, server_ip, client_mac, server_mac, sport, dport, cseq + 1, sseq + 1, 0x10, b""),
    ]
    cnext = cseq + 1
    snext = sseq + 1
    if client_payload:
        steps.append((0.030, client_ip, server_ip, client_mac, server_mac, sport, dport, cnext, snext, 0x18, client_payload))
        cnext += len(client_payload)
    if server_payload:
        steps.append((0.040, server_ip, client_ip, server_mac, client_mac, dport, sport, snext, cnext, 0x18, server_payload))
        snext += len(server_payload)
    steps.extend(
        [
            (0.060, client_ip, server_ip, client_mac, server_mac, sport, dport, cnext, snext, 0x11, b""),
            (0.070, server_ip, client_ip, server_mac, client_mac, dport, sport, snext, cnext + 1, 0x11, b""),
            (0.080, client_ip, server_ip, client_mac, server_mac, sport, dport, cnext + 1, snext + 1, 0x10, b""),
        ]
    )
    for index, (delta, sip, dip, smac, dmac, sp, dp, seq, ack, flags, payload) in enumerate(steps):
        packets.append((ts + delta, _tcp_frame(sip, dip, smac, dmac, sp, dp, seq, ack, flags, payload, ident_base + index)))


def build_fixture(path: Path = FIXTURE) -> Path:
    packets: list[tuple[float, bytes]] = []
    ident = 100

    # Encrypted-session fingerprint baseline: three sessions use the same SNI.
    # A post-baseline session uses a different SNI, which changes the SSL
    # fingerprint without requiring any site policy to trust the new value.
    for index, (ts, sni) in enumerate(
        ((10.0, "secure-plc.local"), (30.0, "secure-plc.local"), (50.0, "secure-plc.local"), (180.0, "secure-plc-new.local"))
    ):
        _tcp_conversation(
            packets,
            ts=ts,
            client_ip=TLS_CLIENT_IP,
            server_ip=TLS_SERVER_IP,
            client_mac=TLS_CLIENT_MAC,
            server_mac=TLS_SERVER_MAC,
            sport=41000 + index,
            dport=443,
            ident_base=ident,
            client_payload=_tls_client_hello(sni),
            server_payload=_tls_server_hello(),
        )
        ident += 20

    # Remote-access baseline to one target, followed by two new RDP targets.
    for index, (ts, target_ip, target_mac) in enumerate(
        (
            (5.0, RDP_BASE_IP, RDP_BASE_MAC),
            (25.0, RDP_BASE_IP, RDP_BASE_MAC),
            (180.0, RDP_NEW1_IP, RDP_NEW1_MAC),
            (190.0, RDP_NEW2_IP, RDP_NEW2_MAC),
        )
    ):
        _tcp_conversation(
            packets,
            ts=ts,
            client_ip=MGMT_IP,
            server_ip=target_ip,
            client_mac=MGMT_MAC,
            server_mac=target_mac,
            sport=42000 + index,
            dport=3389,
            ident_base=ident,
        )
        ident += 20

    # OT service replacement on one explicitly scoped host.  Plain TCP is
    # sufficient: if Zeek does not identify the application, the detector's
    # fallback identity is tcp/<port>, which still preserves the service swap.
    for index, ts in enumerate((10.0, 40.0, 70.0)):
        _tcp_conversation(
            packets,
            ts=ts,
            client_ip=SERVICE_CLIENT_IP,
            server_ip=SERVICE_HOST_IP,
            client_mac=SERVICE_CLIENT_MAC,
            server_mac=SERVICE_HOST_MAC,
            sport=43000 + index,
            dport=502,
            ident_base=ident,
        )
        ident += 20
    for index, ts in enumerate((180.0, 200.0, 220.0)):
        _tcp_conversation(
            packets,
            ts=ts,
            client_ip=SERVICE_CLIENT_IP,
            server_ip=SERVICE_HOST_IP,
            client_mac=SERVICE_CLIENT_MAC,
            server_mac=SERVICE_HOST_MAC,
            sport=43100 + index,
            dport=102,
            ident_base=ident,
        )
        ident += 20

    # Stable 10-second polling during baseline, shifting to 30 seconds later.
    for index, ts in enumerate((0.0, 10.0, 20.0, 30.0, 40.0, 50.0, 180.0, 210.0, 240.0, 270.0)):
        _tcp_conversation(
            packets,
            ts=ts,
            client_ip=POLL_CLIENT_IP,
            server_ip=POLL_HOST_IP,
            client_mac=POLL_CLIENT_MAC,
            server_mac=POLL_HOST_MAC,
            sport=44000 + index,
            dport=20001,
            ident_base=ident,
        )
        ident += 20

    # Controller cadence is perfectly regular during baseline and highly
    # variable after baseline to create an unambiguous jitter increase.
    for index, ts in enumerate((0.0, 10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 180.0, 185.0, 205.0, 213.0, 250.0)):
        _tcp_conversation(
            packets,
            ts=ts,
            client_ip=CONTROLLER_IP,
            server_ip=JITTER_PEER_IP,
            client_mac=CONTROLLER_MAC,
            server_mac=JITTER_PEER_MAC,
            sport=45000 + index,
            dport=20002,
            ident_base=ident,
        )
        ident += 20

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
