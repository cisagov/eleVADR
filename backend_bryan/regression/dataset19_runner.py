from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from backend_bryan.integration.pcap_analysis import analyze_pcap_to_report

ROOT = Path(__file__).resolve().parent
FIXTURE = ROOT / "fixtures" / "19_site_like_multi_hour_ot.pcap"
CONTEXT = ROOT / "fixtures" / "19_site_like_multi_hour_ot_context.json"
MANIFEST = ROOT / "fixtures" / "19_site_like_multi_hour_ot_manifest.json"


def _results(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    arch = report.get("arch_insights") if isinstance(report.get("arch_insights"), dict) else {}
    rows = arch.get("detector_results") if isinstance(arch.get("detector_results"), list) else []
    return {str(row.get("module_id")): row for row in rows if isinstance(row, dict) and row.get("module_id")}


def _findings(result: dict[str, Any]) -> list[dict[str, Any]]:
    rows = result.get("findings")
    return [dict(row) for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def run(verbose: bool = True) -> list[str]:
    failures: list[str] = []
    profile = json.loads(CONTEXT.read_text(encoding="utf-8"))
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    required = set(manifest["required_finding_modules"])
    allowed = set(manifest["allowed_finding_modules"])

    if verbose:
        print("\n=== 19_site_like_multi_hour_ot: four-hour site-like OT false-positive tripwire ===")

    def progress(stage: str, value: int | None, message: str, detail: str | None) -> None:
        if not verbose:
            return
        if stage in {"docker-check", "docker-pull", "docker-ready", "zeek-running", "parsing-zeek", "building-report", "report-ready"}:
            suffix = f" ({detail})" if detail else ""
            print(f"[19_site_like_multi_hour_ot] {message}{suffix}")

    try:
        report = analyze_pcap_to_report(FIXTURE, profile, source_filename=FIXTURE.name, progress=progress)
    except Exception as exc:
        return [f"PCAP pipeline failed: {type(exc).__name__}: {exc}"]

    arch = report.get("arch_insights") if isinstance(report.get("arch_insights"), dict) else {}
    provenance = arch.get("analysis_provenance") if isinstance(arch.get("analysis_provenance"), dict) else {}
    results = _results(report)
    finding_counts = {module_id: len(_findings(row)) for module_id, row in results.items()}
    finding_modules = {module_id for module_id, count in finding_counts.items() if count}

    def check(label: str, condition: bool, detail: Any = None) -> None:
        if condition:
            if verbose:
                print(f"PASS  {label}")
        else:
            failures.append(f"{label}: {detail!r}")
            if verbose:
                print(f"FAIL  {label} ({detail!r})")

    check(
        "All 75 detector modules complete with zero module errors",
        provenance.get("detector_modules_requested") == 75
        and provenance.get("detector_modules_completed") == 75
        and provenance.get("detector_modules_failed") == 0
        and len(results) == 75,
        {"provenance": provenance, "result_count": len(results)},
    )
    check(
        "Zeek produced the core site evidence types",
        {"conn", "modbus", "dns", "ntp", "dhcp", "arp"}.issubset(set((provenance.get("zeek_log_types") or {}).keys())),
        provenance.get("zeek_log_types"),
    )
    check(
        "All deliberate anomaly modules fire",
        required.issubset(finding_modules),
        {"required": sorted(required), "actual": sorted(finding_modules)},
    )
    check(
        "Normal site behavior creates no findings outside the reviewed anomaly allowlist",
        finding_modules.issubset(allowed),
        {"unexpected_modules": sorted(finding_modules - allowed), "all_finding_modules": sorted(finding_modules)},
    )

    write_findings = _findings(results.get("ics_write_operations", {}))
    check(
        "Authorized maintenance write is suppressed while the contractor write remains",
        len(write_findings) == 1
        and any("10.190.10.99" in (row.get("devices") or []) and "10.190.20.20" in (row.get("devices") or []) for row in write_findings),
        write_findings,
    )

    unexpected_dhcp = _findings(results.get("unexpected_dhcp_server", {}))
    check(
        "Trusted DHCP renewals stay quiet and the contractor DHCP server is identified",
        bool(unexpected_dhcp)
        and all("10.190.10.2" not in (row.get("devices") or []) for row in unexpected_dhcp)
        and any("10.190.10.99" in (row.get("devices") or []) for row in unexpected_dhcp),
        unexpected_dhcp,
    )

    if verbose:
        print("Finding counts by module:")
        for module_id in sorted(finding_modules):
            print(f"  {module_id}: {finding_counts[module_id]}")
        if failures:
            print(f"FAIL: Dataset 19 had {len(failures)} failure(s).")
        else:
            print(f"PASS: Dataset 19 completed all 75 detectors with findings limited to {', '.join(sorted(finding_modules))}.")
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
