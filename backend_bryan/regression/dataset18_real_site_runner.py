from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from backend_bryan.integration.pcap_analysis import analyze_pcap_to_report

DISPOSITIONS = {"expected", "useful-noisy", "false-positive", "false-negative", "uncertain", "not-applicable"}


def _mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _list(value: Any) -> list[Any]:
    return list(value) if isinstance(value, list) else []


def _stable(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _review_id(module_id: str, finding: Mapping[str, Any]) -> str:
    basis = {
        "module_id": module_id,
        "title": finding.get("title"),
        "devices": finding.get("devices"),
        "services": finding.get("services"),
        "ports": finding.get("ports"),
        "connection_pairs": finding.get("connection_pairs"),
        "metadata": finding.get("metadata"),
    }
    return hashlib.sha256(_stable(basis).encode("utf-8")).hexdigest()[:16]


def _json_cell(value: Any) -> str:
    if value in (None, "", [], {}):
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)


def _detector_results(report: Mapping[str, Any]) -> list[dict[str, Any]]:
    arch = _mapping(report.get("arch_insights"))
    return [dict(row) for row in _list(arch.get("detector_results")) if isinstance(row, Mapping)]


def _review_rows(report: Mapping[str, Any]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for result in _detector_results(report):
        module_id = str(result.get("module_id") or "unknown")
        for raw in _list(result.get("findings")):
            if not isinstance(raw, Mapping):
                continue
            finding = dict(raw)
            metadata = _mapping(finding.get("metadata"))
            rows.append({
                "review_id": _review_id(module_id, finding),
                "module_id": module_id,
                "title": str(finding.get("title") or ""),
                "severity": str(finding.get("severity") or ""),
                "confidence": str(finding.get("confidence") or metadata.get("confidence") or ""),
                "detection_basis": str(finding.get("detection_basis") or metadata.get("detection_basis") or ""),
                "summary": str(finding.get("summary") or ""),
                "devices": _json_cell(finding.get("devices")),
                "services": _json_cell(finding.get("services")),
                "ports": _json_cell(finding.get("ports")),
                "connection_pairs": _json_cell(finding.get("connection_pairs")),
                "timestamps": _json_cell(finding.get("timestamps")),
                "metadata": _json_cell(metadata),
                "analyst_disposition": "",
                "analyst_notes": "",
                "suggested_tuning_action": "",
            })
    return rows


def _coverage(report: Mapping[str, Any]) -> dict[str, Any]:
    arch = _mapping(report.get("arch_insights"))
    provenance = _mapping(arch.get("analysis_provenance"))
    results = _detector_results(report)
    finding_counts = {str(row.get("module_id")): len(_list(row.get("findings"))) for row in results}
    warnings = {str(row.get("module_id")): _list(row.get("warnings")) for row in results if _list(row.get("warnings"))}
    connections = _list(report.get("connections"))
    service_counts: Counter[str] = Counter()
    state_counts: Counter[str] = Counter()
    for raw in connections:
        if not isinstance(raw, Mapping):
            continue
        service = raw.get("service.name")
        if service:
            service_counts[str(service)] += 1
        state = raw.get("state")
        if state:
            state_counts[str(state)] += 1

    return {
        "source_filename": provenance.get("source_filename"),
        "detection_context_name": provenance.get("detection_context_name"),
        "zeek_runtime": provenance.get("zeek_runtime"),
        "zeek_log_types": provenance.get("zeek_log_types") or {},
        "detector_modules_requested": provenance.get("detector_modules_requested"),
        "detector_modules_completed": provenance.get("detector_modules_completed"),
        "detector_modules_failed": provenance.get("detector_modules_failed"),
        "module_errors": arch.get("detector_errors") or [],
        "findings_total": sum(finding_counts.values()),
        "finding_counts_by_module": finding_counts,
        "modules_with_findings": sorted(module_id for module_id, count in finding_counts.items() if count),
        "modules_without_findings": sorted(module_id for module_id, count in finding_counts.items() if not count),
        "module_warnings": warnings,
        "service_counts": dict(sorted(service_counts.items(), key=lambda item: (-item[1], item[0]))),
        "connection_state_counts": dict(sorted(state_counts.items())),
        "zeek_parse_diagnostics": _mapping(arch.get("analysis_context_metadata")).get("zeek_parse_diagnostics")
        or _mapping(provenance.get("analysis_context_metadata")).get("zeek_parse_diagnostics")
        or {},
    }


def _read_review(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        rows = [dict(row) for row in csv.DictReader(handle)]
    for row in rows:
        disposition = (row.get("analyst_disposition") or "").strip().lower()
        if disposition and disposition not in DISPOSITIONS:
            raise ValueError(f"Unsupported analyst_disposition {disposition!r} for review_id {row.get('review_id')!r}")
    return rows


def _review_summary(rows: Iterable[Mapping[str, str]]) -> dict[str, Any]:
    rows = list(rows)
    counts = Counter((row.get("analyst_disposition") or "unreviewed").strip().lower() or "unreviewed" for row in rows)
    false_positive_modules = Counter(
        str(row.get("module_id") or "unknown")
        for row in rows
        if (row.get("analyst_disposition") or "").strip().lower() == "false-positive"
    )
    noisy_modules = Counter(
        str(row.get("module_id") or "unknown")
        for row in rows
        if (row.get("analyst_disposition") or "").strip().lower() == "useful-noisy"
    )
    return {
        "reviewed_rows": sum(count for key, count in counts.items() if key != "unreviewed"),
        "total_rows": len(rows),
        "dispositions": dict(sorted(counts.items())),
        "false_positive_modules": dict(false_positive_modules.most_common()),
        "useful_but_noisy_modules": dict(noisy_modules.most_common()),
        "tuning_candidates": [
            {
                "review_id": row.get("review_id"),
                "module_id": row.get("module_id"),
                "title": row.get("title"),
                "disposition": (row.get("analyst_disposition") or "").strip().lower(),
                "analyst_notes": row.get("analyst_notes") or "",
                "suggested_tuning_action": row.get("suggested_tuning_action") or "",
            }
            for row in rows
            if (row.get("analyst_disposition") or "").strip().lower() in {"false-positive", "useful-noisy", "false-negative"}
        ],
    }


def _write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    fields = list(rows[0].keys()) if rows else [
        "review_id", "module_id", "title", "severity", "confidence", "detection_basis", "summary",
        "devices", "services", "ports", "connection_pairs", "timestamps", "metadata",
        "analyst_disposition", "analyst_notes", "suggested_tuning_action",
    ]
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def _default_output_dir() -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return Path("real_site_validation") / stamp


def run_analysis(pcap: Path, context_path: Path, output_dir: Path) -> int:
    if not pcap.is_file():
        raise FileNotFoundError(f"PCAP not found: {pcap}")
    if not context_path.is_file():
        raise FileNotFoundError(f"Detection Context not found: {context_path}")

    profile = json.loads(context_path.read_text(encoding="utf-8"))
    if not isinstance(profile, dict):
        raise ValueError("Detection Context JSON must contain an object")

    output_dir.mkdir(parents=True, exist_ok=True)

    def progress(stage: str, value: int | None, message: str, detail: str | None) -> None:
        suffix = f" ({detail})" if detail else ""
        print(f"[real-site] {message}{suffix}")

    report = analyze_pcap_to_report(pcap, profile, source_filename=pcap.name, progress=progress)
    report_path = output_dir / "canonical_report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")

    rows = _review_rows(report)
    review_path = output_dir / "finding_review.csv"
    _write_csv(review_path, rows)

    coverage = _coverage(report)
    coverage["generated_at"] = datetime.now(timezone.utc).isoformat()
    coverage["input_pcap"] = pcap.name
    coverage["input_context"] = context_path.name
    coverage_path = output_dir / "coverage_summary.json"
    coverage_path.write_text(json.dumps(coverage, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")

    missed_path = output_dir / "missed_detection_review.csv"
    with missed_path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["expected_behavior", "expected_module", "devices", "evidence_available", "analyst_rationale", "notes"])

    instructions = output_dir / "REVIEW.md"
    instructions.write_text(
        "# Real-site analyst review\n\n"
        "Review `finding_review.csv` without changing the evidence/policy boundary. For each finding, set "
        "`analyst_disposition` to one of: `expected`, `useful-noisy`, `false-positive`, `false-negative`, "
        "`uncertain`, or `not-applicable`. Add analyst notes and a suggested tuning action where useful.\n\n"
        "Observed traffic is evidence only. Do not add a host, peer, resolver, service, multicast group, or control "
        "path to Detection Context merely because it was observed. Only encode authorization/expectation when it is "
        "independently known to be legitimate.\n\n"
        "If an analyst expected a detection that is absent, record it in `missed_detection_review.csv`; do not force an existing finding into a false-negative label.\n\n"
        "After review, run:\n\n"
        "```powershell\n"
        f"python -m backend_bryan.regression.dataset18_real_site_runner --summarize-review \"{review_path}\" --output-dir \"{output_dir}\"\n"
        "```\n",
        encoding="utf-8",
    )

    print(f"Report:   {report_path}")
    print(f"Review:   {review_path}")
    print(f"Coverage: {coverage_path}")
    print(f"Missed:   {missed_path}")
    print(f"Findings: {coverage['findings_total']}")
    print(f"Detectors completed: {coverage.get('detector_modules_completed')}/{coverage.get('detector_modules_requested')}")
    print("No detector policy was changed by this validation run.")
    return 0


def summarize_review(review_path: Path, output_dir: Path) -> int:
    rows = _read_review(review_path)
    summary = _review_summary(rows)
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "analyst_review_summary.json"
    path.write_text(json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Review summary: {path}")
    print(f"Reviewed: {summary['reviewed_rows']}/{summary['total_rows']}")
    print(f"Dispositions: {summary['dispositions']}")
    if summary["tuning_candidates"]:
        print(f"Tuning candidates: {len(summary['tuning_candidates'])}")
    else:
        print("Tuning candidates: 0")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Dataset 18 real-site PCAP validation and analyst tuning harness")
    parser.add_argument("--pcap", type=Path, help="Representative sanitized real-site PCAP")
    parser.add_argument("--context", type=Path, help="Matching Detection Context JSON")
    parser.add_argument("--output-dir", type=Path, default=None, help="Directory for report/review artifacts")
    parser.add_argument("--summarize-review", type=Path, help="Summarize a completed finding_review.csv")
    args = parser.parse_args()

    output_dir = args.output_dir or _default_output_dir()
    try:
        if args.summarize_review:
            return summarize_review(args.summarize_review, output_dir)
        if not args.pcap or not args.context:
            parser.error("--pcap and --context are required unless --summarize-review is used")
        return run_analysis(args.pcap, args.context, output_dir)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
