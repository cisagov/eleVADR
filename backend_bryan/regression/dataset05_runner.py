from __future__ import annotations

from pathlib import Path

from backend_bryan.integration.detector_runtime import ensure_detector_package

ROOT = Path(__file__).resolve().parent
FIXTURE = ROOT / "fixtures" / "05_parser_edge_cases"


def _rows(result):
    return result.findings if hasattr(result, "findings") else result.get("findings", [])


def main() -> int:
    AnalysisContext, modules, module_file = ensure_detector_package()
    # Import from the exact vendored package that ensure_detector_package resolved.
    from elevadr_modules.zeek.parser import load_zeek_directory

    context = load_zeek_directory(FIXTURE)
    failures: list[str] = []

    print("\n=== 05_parser_edge_cases: Malformed Zeek evidence and VLAN/weird robustness ===")

    diagnostics = context.metadata.get("zeek_parse_diagnostics", {})
    conn_diag = diagnostics.get("conn", {})
    weird_diag = diagnostics.get("weird", {})
    dns_diag = diagnostics.get("dns", {})

    checks = [
        (len(context.connections) == 5, f"conn parser retained {len(context.connections)} row(s), expected 5"),
        (conn_diag.get("short_rows") == 2, f"conn short_rows={conn_diag.get('short_rows')}, expected 2"),
        (conn_diag.get("extra_value_rows") == 1, f"conn extra_value_rows={conn_diag.get('extra_value_rows')}, expected 1"),
        (len(context.weird) == 4, f"weird parser retained {len(context.weird)} row(s), expected 4"),
        (weird_diag.get("skipped_rows") == 2, f"weird skipped_rows={weird_diag.get('skipped_rows')}, expected 2"),
        (bool(dns_diag.get("parse_error")), "dns log missing #fields did not produce a parse_error diagnostic"),
        (context.dns == [], "malformed dns.log should be isolated to an empty DNS log"),
        (len(context.modbus) == 3, f"partial Modbus rows retained {len(context.modbus)} row(s), expected 3"),
    ]
    for passed, message in checks:
        if not passed:
            failures.append(message)

    expected_findings = {
        "weird_protocol_violations": 4,
        "vlan_tag_mismatch_double_tag": 3,
    }
    for module_id, expected in expected_findings.items():
        result = modules[module_id].analyze(context)
        actual = len(_rows(result))
        status = "PASS" if actual == expected else "FAIL"
        print(f"{status:4}  {module_id:38} {actual} finding(s) (expected {expected})")
        if actual != expected:
            failures.append(f"{module_id}: expected {expected}, got {actual}")

    # No detector may take down a partial/malformed capture. Individual modules may
    # return warnings or no findings, but all 75 must complete.
    detector_errors: list[str] = []
    for module_id, module in modules.items():
        try:
            module.analyze(context)
        except Exception as exc:  # regression guard: report every crash together
            detector_errors.append(f"{module_id}: {type(exc).__name__}: {exc}")
    if detector_errors:
        failures.extend(f"detector crashed on partial evidence: {error}" for error in detector_errors)

    # Explicit parser diagnostics must remain observational metadata only.
    if any(key in context.metadata for key in ("allowed_hosts", "allowed_segment_pairs", "authorized_control_actions")):
        failures.append("parser diagnostics unexpectedly created authorization/policy metadata")

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1

    print(
        "PASS: Dataset 05 isolated malformed records, retained usable evidence, "
        f"and all {len(modules)} detector modules completed without exception."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
