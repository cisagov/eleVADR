from __future__ import annotations

import json
from pathlib import Path

from backend_bryan.integration.detector_runtime import ensure_detector_package

ROOT = Path(__file__).resolve().parent
FIXTURE = ROOT / "fixtures" / "04_control_protocol_semantics.json"


def main() -> int:
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    AnalysisContext, modules, _module_file = ensure_detector_package()
    context = AnalysisContext(metadata=payload["metadata"], **payload["logs"])
    failures: list[str] = []
    total = 0
    print("\n=== 04_control_protocol_semantics: Explicit OT control/discovery evidence ===")
    for module_id, expected in payload["expectations"].items():
        result = modules[module_id].analyze(context)
        findings = result.findings if hasattr(result, "findings") else result.get("findings", [])
        actual = len(findings)
        total += actual
        status = "PASS" if actual == expected else "FAIL"
        print(f"{status:4}  {module_id:38} {actual} finding(s) (expected {expected})")
        if actual != expected:
            failures.append(f"{module_id}: expected {expected}, got {actual}")

        # Critical semantic guard: explicit observed control traffic must not become
        # authorization. The fixture intentionally authorizes a different manager.
        if module_id in {"ics_write_operations", "s7comm_unauthorized_write_stop", "enip_cip_write_session_abuses"}:
            for finding in findings:
                metadata = finding.metadata if hasattr(finding, "metadata") else finding.get("metadata", {})
                if metadata.get("unauthorized_operation_confirmed") is not True:
                    failures.append(f"{module_id}: observed write was not retained as outside authorization")

    # SNMP evidence must redact its credential from returned evidence.
    snmp = modules["snmp_write_ot_devices"].analyze(context)
    if snmp.findings:
        for row in snmp.findings[0].flows:
            if row.get("community") not in (None, "", "[REDACTED]"):
                failures.append("snmp_write_ot_devices: community credential leaked into finding evidence")

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1
    print(f"PASS: Dataset 04 semantic fixture produced {total} expected finding(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
