from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from backend_bryan.integration.pcap_analysis import analyze_pcap_to_report

ROOT = Path(__file__).resolve().parent
FIXTURE = ROOT / "fixtures" / "17_wave3_raw_pcap.pcap"
CONTEXT = ROOT / "fixtures" / "17_wave3_raw_pcap_context.json"
EXPECTED = {
    "encrypted_session_fingerprint_change",
    "remote_access_session_anomaly",
    "service_disappearance_replacement",
    "polling_cadence_disruption",
    "controller_communication_jitter",
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
        print("\n=== 17_wave3_raw_pcap: Raw PCAP -> Zeek -> five Wave 3 detectors ===")

    def progress(stage: str, value: int | None, message: str, detail: str | None) -> None:
        if not verbose:
            return
        if stage in {"docker-check", "docker-pull", "docker-ready", "zeek-running", "parsing-zeek", "building-report", "report-ready"}:
            suffix = f" ({detail})" if detail else ""
            print(f"[17_wave3_raw_pcap] {message}{suffix}")

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
        "Zeek produced conn/ssl evidence from the raw PCAP",
        {"conn", "ssl"}.issubset(set((provenance.get("zeek_log_types") or {}).keys())),
        provenance.get("zeek_log_types"),
    )
    check(
        "Exactly the five Wave 3 detectors completed with zero module errors",
        provenance.get("detector_modules_requested") == 5
        and provenance.get("detector_modules_completed") == 5
        and provenance.get("detector_modules_failed") == 0
        and EXPECTED.issubset(results),
        provenance,
    )

    tls = results.get("encrypted_session_fingerprint_change", {})
    tls_findings = _findings(tls)
    check(
        "Encrypted-session fingerprint change fires from native Zeek ssl.log evidence",
        bool(tls_findings)
        and any({"10.170.0.10", "10.170.0.11"}.issubset(set(finding.get("devices") or [])) for finding in tls_findings)
        and any(
            "secure-plc-new.local" in " ".join(str(value) for value in (finding.get("metadata") or {}).get("observed_fingerprints", []))
            for finding in tls_findings
        ),
        tls,
    )

    remote = results.get("remote_access_session_anomaly", {})
    remote_findings = _findings(remote)
    check(
        "Remote-access anomaly learns one RDP target then catches two new targets from conn.log",
        bool(remote_findings)
        and any((finding.get("devices") or [None])[0] == "10.170.0.5" for finding in remote_findings)
        and any(
            {"10.170.0.22", "10.170.0.23"}.issubset(set((finding.get("metadata") or {}).get("new_targets", [])))
            for finding in remote_findings
        ),
        remote,
    )

    service = results.get("service_disappearance_replacement", {})
    service_findings = _findings(service)
    check(
        "Service disappearance/replacement detects the OT endpoint port/service swap",
        bool(service_findings)
        and any("10.170.0.30" in (finding.get("devices") or []) for finding in service_findings)
        and any(
            bool((finding.get("metadata") or {}).get("disappeared_services"))
            and bool((finding.get("metadata") or {}).get("new_services"))
            for finding in service_findings
        ),
        service,
    )

    cadence = results.get("polling_cadence_disruption", {})
    cadence_findings = _findings(cadence)
    check(
        "Polling cadence disruption detects the 10-second to 30-second interval shift",
        bool(cadence_findings)
        and any({"10.170.0.41", "10.170.0.40"}.issubset(set(finding.get("devices") or [])) for finding in cadence_findings)
        and any(float((finding.get("metadata") or {}).get("change_ratio", 0)) >= 0.5 for finding in cadence_findings),
        cadence,
    )

    jitter = results.get("controller_communication_jitter", {})
    jitter_findings = _findings(jitter)
    check(
        "Controller communication jitter detects post-baseline timing variance from conn.log",
        bool(jitter_findings)
        and any({"10.170.0.50", "10.170.0.60"}.issubset(set(finding.get("devices") or [])) for finding in jitter_findings)
        and any(
            float((finding.get("metadata") or {}).get("post_baseline_jitter_mad", 0))
            > float((finding.get("metadata") or {}).get("baseline_jitter_mad", 0))
            for finding in jitter_findings
        ),
        jitter,
    )

    if verbose:
        if failures:
            print(f"FAIL: Dataset 17 had {len(failures)} failure(s).")
        else:
            total_findings = sum(len(_findings(results[module_id])) for module_id in EXPECTED)
            print(f"PASS: Dataset 17 proved all five Wave 3 detectors from raw PCAP/Zeek evidence ({total_findings} finding(s)).")
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
