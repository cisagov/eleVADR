from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from backend_bryan.integration.pcap_analysis import analyze_pcap_to_report

ROOT = Path(__file__).resolve().parent
FIXTURE = ROOT / "fixtures" / "15_new_detector_raw_pcap.pcap"
CONTEXT = ROOT / "fixtures" / "15_new_detector_raw_pcap_context.json"
EXPECTED = {
    "arp_ip_mac_identity_change",
    "unexpected_dhcp_server",
    "ot_protocol_role_reversal",
    "plc_rtu_peer_change",
    "engineering_workstation_control_burst",
}


def _results(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    arch = report.get("arch_insights") if isinstance(report.get("arch_insights"), dict) else {}
    rows = arch.get("detector_results") if isinstance(arch.get("detector_results"), list) else []
    return {
        str(row.get("module_id")): row
        for row in rows
        if isinstance(row, dict) and row.get("module_id")
    }


def _findings(result: dict[str, Any]) -> list[dict[str, Any]]:
    value = result.get("findings")
    return [row for row in value if isinstance(row, dict)] if isinstance(value, list) else []


def run(verbose: bool = True) -> list[str]:
    failures: list[str] = []
    profile = json.loads(CONTEXT.read_text(encoding="utf-8"))

    if verbose:
        print("\n=== 15_new_detector_raw_pcap: Raw PCAP -> Zeek -> five new detectors ===")

    def progress(stage: str, value: int | None, message: str, detail: str | None) -> None:
        if not verbose:
            return
        if stage in {"docker-check", "docker-pull", "docker-ready", "zeek-running", "parsing-zeek", "building-report", "report-ready"}:
            suffix = f" ({detail})" if detail else ""
            print(f"[15_new_detector_raw_pcap] {message}{suffix}")

    try:
        report = analyze_pcap_to_report(
            FIXTURE,
            profile,
            source_filename=FIXTURE.name,
            progress=progress,
        )
    except Exception as exc:
        return [f"PCAP pipeline failed: {type(exc).__name__}: {exc}"]

    arch = report.get("arch_insights") if isinstance(report.get("arch_insights"), dict) else {}
    provenance = arch.get("analysis_provenance") if isinstance(arch.get("analysis_provenance"), dict) else {}
    results = _results(report)

    def check(label: str, condition: bool, detail: Any = None) -> None:
        if condition:
            if verbose:
                print(f"PASS  {label}")
        else:
            failures.append(f"{label}: {detail!r}")
            if verbose:
                print(f"FAIL  {label} ({detail!r})")

    check(
        "Zeek produced conn/modbus/dhcp/arp evidence from the raw PCAP",
        {"conn", "modbus", "dhcp", "arp"}.issubset(set((provenance.get("zeek_log_types") or {}).keys())),
        provenance.get("zeek_log_types"),
    )
    check(
        "Exactly the five new detectors completed with zero module errors",
        provenance.get("detector_modules_requested") == 5
        and provenance.get("detector_modules_completed") == 5
        and provenance.get("detector_modules_failed") == 0
        and EXPECTED.issubset(results),
        provenance,
    )

    arp = results.get("arp_ip_mac_identity_change", {})
    arp_findings = _findings(arp)
    check(
        "ARP/IP-MAC identity change fires from Zeek ARP evidence",
        bool(arp_findings)
        and any("10.150.0.20" in (finding.get("devices") or []) for finding in arp_findings)
        and int((arp.get("metrics") or {}).get("authoritative_mismatches", 0)) >= 1,
        arp,
    )

    dhcp = results.get("unexpected_dhcp_server", {})
    dhcp_findings = _findings(dhcp)
    check(
        "Unexpected DHCP server fires from Zeek dhcp.log evidence",
        len(dhcp_findings) >= 1
        and any("10.150.0.99" in (finding.get("devices") or []) for finding in dhcp_findings),
        dhcp,
    )

    role = results.get("ot_protocol_role_reversal", {})
    role_findings = _findings(role)
    check(
        "OT role reversal learns PLC responder baseline then catches PLC originator traffic",
        len(role_findings) >= 1
        and any((finding.get("devices") or [None])[0] == "10.150.0.20" for finding in role_findings),
        role,
    )

    peer = results.get("plc_rtu_peer_change", {})
    peer_findings = _findings(peer)
    check(
        "PLC/RTU peer change catches a post-baseline peer from conn.log",
        len(peer_findings) >= 1
        and any(
            {"10.150.0.20", "10.150.0.99"}.issubset(set(finding.get("devices") or []))
            or {"10.150.0.20", "10.150.0.60"}.issubset(set(finding.get("devices") or []))
            for finding in peer_findings
        ),
        peer,
    )

    burst = results.get("engineering_workstation_control_burst", {})
    burst_findings = _findings(burst)
    check(
        "Engineering workstation control burst fires from Zeek Modbus function names on an authorized path",
        len(burst_findings) >= 1
        and any(
            int((finding.get("metadata") or {}).get("authorized_operation_count", 0)) >= 5
            and int((finding.get("metadata") or {}).get("unauthorized_operation_count", 0)) == 0
            for finding in burst_findings
        ),
        burst,
    )

    if verbose:
        if failures:
            print(f"FAIL: Dataset 15 had {len(failures)} failure(s).")
        else:
            total_findings = sum(len(_findings(results[module_id])) for module_id in EXPECTED)
            print(f"PASS: Dataset 15 proved all five new detectors from raw PCAP/Zeek evidence ({total_findings} finding(s)).")
    return failures


def main() -> int:
    failures = run(True)
    if failures:
        for failure in failures:
            print(f"  - {failure}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
