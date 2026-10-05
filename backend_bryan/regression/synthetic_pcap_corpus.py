from __future__ import annotations

import argparse
import hashlib
import json
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from backend_bryan.regression.dataset15_fixture_builder import build_fixture as build_dataset15
from backend_bryan.regression.dataset16_fixture_builder import build_fixture as build_dataset16
from backend_bryan.regression.dataset17_fixture_builder import build_fixture as build_dataset17
from backend_bryan.regression.dataset19_fixture_builder import build_fixture as build_dataset19

ROOT = Path(__file__).resolve().parent
FIXTURES = ROOT / "fixtures"


@dataclass(frozen=True)
class CorpusEntry:
    dataset: int
    name: str
    pcap: str
    context: str
    sha256: str
    purpose: str
    builder: Callable[[Path], Path] | None = None


CORPUS: tuple[CorpusEntry, ...] = (
    CorpusEntry(
        1,
        "Mixed OT baseline",
        "01_mixed_ot_baseline.pcap",
        "01_mixed_ot_baseline_context.json",
        "c190af79a619c28affa68b0f6b65127a8aaf525090906180491e175f16291e47",
        "Legacy mixed-OT baseline and trusted-infrastructure semantics.",
    ),
    CorpusEntry(
        2,
        "Legacy high-risk",
        "02_legacy_high_risk.pcap",
        "02_legacy_high_risk_context.json",
        "1635f067ef12173c19a13ce1c2b5cf47733ec397febee4323c4fadd88d1fb5aa",
        "Legacy high-risk and rogue-inventory behavior.",
    ),
    CorpusEntry(
        3,
        "Outbound IPv6/QUIC/ICMP",
        "03_outbound_ipv6_quic_icmp.pcap",
        "03_outbound_ipv6_quic_icmp_context.json",
        "491567cd67da29e0c18f1bc4ae7987cc06caa482a2c8b01d88616db1cbe1b8be",
        "Outbound volume, HTTP upload, ICMP timing, IPv6, QUIC, and service drift.",
    ),
    CorpusEntry(
        15,
        "Wave 1 raw PCAP",
        "15_new_detector_raw_pcap.pcap",
        "15_new_detector_raw_pcap_context.json",
        "5f6d103011414c7dcc61efddc576c726d747eb75f863ccb746aa9170706fbd75",
        "ARP identity, rogue DHCP, role reversal, peer change, and control burst.",
        build_dataset15,
    ),
    CorpusEntry(
        16,
        "Wave 2 raw PCAP",
        "16_wave2_raw_pcap.pcap",
        "16_wave2_raw_pcap_context.json",
        "1659680bccc5167a4ed581913293af93e05a3ed5b3a934365609e1adeb9f1d4c",
        "DNS/NTP drift, ARP reconnaissance, multicast drift, and TCP reset surge.",
        build_dataset16,
    ),
    CorpusEntry(
        17,
        "Wave 3 raw PCAP",
        "17_wave3_raw_pcap.pcap",
        "17_wave3_raw_pcap_context.json",
        "661a4cec3a780225ae86b3a9692b0c58d0b77d50b6200cb8e9fb408f1f0ba201",
        "TLS fingerprint drift, remote-access expansion, service replacement, polling drift, and jitter.",
        build_dataset17,
    ),
    CorpusEntry(
        19,
        "Four-hour site-like OT simulation",
        "19_site_like_multi_hour_ot.pcap",
        "19_site_like_multi_hour_ot_context.json",
        "764009dffce55e8ef0ff1ad3ffdc00a1c75e870453e0a80d31a2d974e9473858",
        "Four-hour mixed OT operations and false-positive tripwire across all 75 detectors.",
        build_dataset19,
    ),
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _pcap_stats(path: Path) -> tuple[int, float]:
    with path.open("rb") as handle:
        header = handle.read(24)
        if len(header) != 24:
            raise ValueError("truncated PCAP global header")
        magic = header[:4]
        if magic == b"\xd4\xc3\xb2\xa1":
            endian, scale = "<", 1_000_000
        elif magic == b"\xa1\xb2\xc3\xd4":
            endian, scale = ">", 1_000_000
        elif magic == b"\x4d\x3c\xb2\xa1":
            endian, scale = "<", 1_000_000_000
        elif magic == b"\xa1\xb2\x3c\x4d":
            endian, scale = ">", 1_000_000_000
        else:
            raise ValueError(f"unsupported PCAP magic {magic.hex()}")

        first_ts: float | None = None
        last_ts: float | None = None
        packets = 0
        while True:
            packet_header = handle.read(16)
            if not packet_header:
                break
            if len(packet_header) != 16:
                raise ValueError("truncated PCAP packet header")
            ts_sec, ts_frac, incl_len, _orig_len = struct.unpack(f"{endian}IIII", packet_header)
            payload = handle.read(incl_len)
            if len(payload) != incl_len:
                raise ValueError("truncated PCAP packet payload")
            timestamp = ts_sec + ts_frac / scale
            first_ts = timestamp if first_ts is None else first_ts
            last_ts = timestamp
            packets += 1

    duration = 0.0 if first_ts is None or last_ts is None else max(0.0, last_ts - first_ts)
    return packets, duration


def verify_corpus(*, check_rebuilds: bool = True, verbose: bool = True) -> list[str]:
    failures: list[str] = []
    if verbose:
        print("eleVADR synthetic/raw-PCAP corpus integrity check")
        print("=" * 60)

    for entry in CORPUS:
        pcap = FIXTURES / entry.pcap
        context = FIXTURES / entry.context
        prefix = f"Dataset {entry.dataset:02d}"

        if not pcap.is_file():
            failures.append(f"{prefix}: missing {pcap}")
            continue
        if not context.is_file():
            failures.append(f"{prefix}: missing {context}")
            continue

        actual_hash = _sha256(pcap)
        if actual_hash != entry.sha256:
            failures.append(
                f"{prefix}: PCAP SHA-256 changed: expected {entry.sha256}, got {actual_hash}"
            )

        try:
            payload = json.loads(context.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                failures.append(f"{prefix}: context JSON must be an object")
        except Exception as exc:
            failures.append(f"{prefix}: invalid context JSON: {type(exc).__name__}: {exc}")

        try:
            packets, duration = _pcap_stats(pcap)
            if packets <= 0:
                failures.append(f"{prefix}: PCAP contains no packets")
        except Exception as exc:
            failures.append(f"{prefix}: invalid PCAP: {type(exc).__name__}: {exc}")
            packets, duration = 0, 0.0

        rebuild_status = "frozen"
        if check_rebuilds and entry.builder is not None:
            with tempfile.TemporaryDirectory(prefix=f"elevadr-ds{entry.dataset:02d}-") as temp_dir:
                rebuilt = Path(temp_dir) / entry.pcap
                entry.builder(rebuilt)
                rebuilt_hash = _sha256(rebuilt)
                if rebuilt_hash != entry.sha256:
                    failures.append(
                        f"{prefix}: deterministic rebuild mismatch: expected {entry.sha256}, got {rebuilt_hash}"
                    )
                    rebuild_status = "MISMATCH"
                else:
                    rebuild_status = "rebuild-ok"

        if verbose:
            print(
                f"{prefix}: {entry.name} | packets={packets} | duration={duration:.3f}s | "
                f"sha256={actual_hash[:12]}... | {rebuild_status}"
            )
            print(f"  {entry.purpose}")

    if verbose:
        if failures:
            print(f"FAIL: corpus integrity check found {len(failures)} issue(s).")
        else:
            print(f"PASS: {len(CORPUS)} raw-PCAP fixtures and contexts verified.")
    return failures


def run_live_validation() -> int:
    commands = (
        [sys.executable, "-m", "backend_bryan.regression.runner", "--mode", "live"],
        [sys.executable, "-m", "backend_bryan.regression.dataset15_runner"],
        [sys.executable, "-m", "backend_bryan.regression.dataset16_runner"],
        [sys.executable, "-m", "backend_bryan.regression.dataset17_runner"],
        [sys.executable, "-m", "backend_bryan.regression.dataset19_runner"],
    )
    print("\nRunning all raw-PCAP fixtures through the live Zeek path...")
    for command in commands:
        print(f"\n> {' '.join(command)}")
        result = subprocess.run(command, cwd=ROOT.parent.parent, check=False)
        if result.returncode != 0:
            return result.returncode
    print("\nPASS: all seven raw-PCAP regression fixtures completed successfully.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify the eleVADR raw-PCAP regression corpus and optionally execute it through Zeek."
    )
    parser.add_argument(
        "--no-rebuild-check",
        action="store_true",
        help="Skip deterministic rebuild verification for generated Datasets 15-17 and 19.",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="After integrity checks, run Datasets 01-03, 15-17, and 19 through the live Zeek analysis path.",
    )
    args = parser.parse_args()

    failures = verify_corpus(check_rebuilds=not args.no_rebuild_check, verbose=True)
    if failures:
        for failure in failures:
            print(f"  - {failure}")
        return 1
    if args.live:
        return run_live_validation()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
