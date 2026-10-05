from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from backend_bryan.integration.pcap_analysis import analyze_pcap_to_report

ROOT = Path(__file__).resolve().parent
FIXTURE = ROOT / "fixtures" / "16_wave2_raw_pcap.pcap"
CONTEXT = ROOT / "fixtures" / "16_wave2_raw_pcap_context.json"
EXPECTED = {
    "dns_source_drift",
    "ntp_source_drift",
    "arp_l2_reconnaissance",
    "unexpected_multicast_behavior",
    "tcp_reset_abort_surge",
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
        print("\n=== 16_wave2_raw_pcap: Raw PCAP -> Zeek -> five Wave 2 detectors ===")

    def progress(stage: str, value: int | None, message: str, detail: str | None) -> None:
        if not verbose:
            return
        if stage in {"docker-check", "docker-pull", "docker-ready", "zeek-running", "parsing-zeek", "building-report", "report-ready"}:
            suffix = f" ({detail})" if detail else ""
            print(f"[16_wave2_raw_pcap] {message}{suffix}")

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
        "Zeek produced conn/dns/ntp/arp evidence from the raw PCAP",
        {"conn", "dns", "ntp", "arp"}.issubset(set((provenance.get("zeek_log_types") or {}).keys())),
        provenance.get("zeek_log_types"),
    )
    check(
        "Exactly the five Wave 2 detectors completed with zero module errors",
        provenance.get("detector_modules_requested") == 5
        and provenance.get("detector_modules_completed") == 5
        and provenance.get("detector_modules_failed") == 0
        and EXPECTED.issubset(results),
        provenance,
    )

    dns = results.get("dns_source_drift", {})
    dns_findings = _findings(dns)
    check(
        "DNS source drift fires from Zeek dns.log evidence outside trusted infrastructure",
        bool(dns_findings)
        and any("10.160.0.99" in (finding.get("devices") or []) for finding in dns_findings)
        and any(bool((finding.get("metadata") or {}).get("outside_trusted_infrastructure")) for finding in dns_findings),
        dns,
    )

    ntp = results.get("ntp_source_drift", {})
    ntp_findings = _findings(ntp)
    check(
        "NTP source drift fires from Zeek ntp.log evidence outside trusted infrastructure",
        bool(ntp_findings)
        and any("10.160.0.99" in (finding.get("devices") or []) for finding in ntp_findings)
        and any(bool((finding.get("metadata") or {}).get("outside_trusted_infrastructure")) for finding in ntp_findings),
        ntp,
    )

    arp = results.get("arp_l2_reconnaissance", {})
    arp_findings = _findings(arp)
    check(
        "ARP/L2 reconnaissance fires from a 20-target Zeek ARP sweep",
        bool(arp_findings)
        and any("10.160.0.50" in (finding.get("devices") or []) for finding in arp_findings)
        and any(int((finding.get("metadata") or {}).get("distinct_targets", 0)) >= 20 for finding in arp_findings),
        arp,
    )

    multicast = results.get("unexpected_multicast_behavior", {})
    multicast_findings = _findings(multicast)
    check(
        "Unexpected multicast fires from conn.log while configured group remains allowed only by policy",
        bool(multicast_findings)
        and any("239.9.9.9" in (finding.get("devices") or []) for finding in multicast_findings)
        and all("239.1.1.1" not in (finding.get("devices") or []) for finding in multicast_findings),
        multicast,
    )

    resets = results.get("tcp_reset_abort_surge", {})
    reset_findings = _findings(resets)
    check(
        "TCP reset/abort surge fires from native Zeek conn_state evidence",
        bool(reset_findings)
        and any("10.160.0.20" in (finding.get("devices") or []) for finding in reset_findings)
        and any(int((finding.get("metadata") or {}).get("failure_events", 0)) >= 10 for finding in reset_findings),
        resets,
    )

    if verbose:
        if failures:
            print(f"FAIL: Dataset 16 had {len(failures)} failure(s).")
        else:
            total_findings = sum(len(_findings(results[module_id])) for module_id in EXPECTED)
            print(f"PASS: Dataset 16 proved all five Wave 2 detectors from raw PCAP/Zeek evidence ({total_findings} finding(s)).")
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
