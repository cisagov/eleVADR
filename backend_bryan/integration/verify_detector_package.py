"""CLI contract harness for the simplified request and standalone 75-module package."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from backend_bryan.integration.analysis_request import build_analysis_context, validate_analysis_request


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("request", type=Path, help="DetectionAnalysisRequest JSON file")
    args = parser.parse_args()

    try:
        from elevadr_modules.registry import MODULES
    except ImportError as exc:
        print("elevadr_modules is not importable. Add the standalone detector package to PYTHONPATH.", file=sys.stderr)
        print(str(exc), file=sys.stderr)
        return 2

    request = json.loads(args.request.read_text(encoding="utf-8"))
    profile = validate_analysis_request(request)
    context = build_analysis_context(request)
    selected = profile.get("selectedModules", [])
    module_ids = [module_id for module_id in selected if module_id in MODULES]

    failures: list[dict[str, str]] = []
    passed: list[str] = []
    for module_id in module_ids:
        module = MODULES[module_id]
        try:
            result = module.analyze(context)
            if result.module_id != module_id:
                raise AssertionError(f"result.module_id={result.module_id!r}")
            passed.append(module_id)
        except Exception as exc:
            failures.append({"module": module_id, "error": f"{type(exc).__name__}: {exc}"})

    summary = {
        "contract_version": request.get("contractVersion"),
        "registry_count": len(MODULES),
        "selected_count": len(module_ids),
        "passed_count": len(passed),
        "failed_count": len(failures),
        "passed": passed,
        "failures": failures,
    }
    print(json.dumps(summary, indent=2))
    return 0 if len(MODULES) == 75 and not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
