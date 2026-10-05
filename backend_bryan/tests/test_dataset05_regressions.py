from __future__ import annotations

import json
from pathlib import Path

from backend_bryan.integration.detector_runtime import ensure_detector_package

FIXTURE = Path(__file__).resolve().parents[1] / "regression" / "fixtures" / "05_parser_edge_cases"


def test_dataset05_parser_diagnostics_and_detectors_complete() -> None:
    ensure_detector_package()
    from elevadr_modules.zeek.parser import load_zeek_directory
    from elevadr_modules.registry import MODULES

    context = load_zeek_directory(FIXTURE)
    diagnostics = context.metadata["zeek_parse_diagnostics"]

    assert len(context.connections) == 5
    assert diagnostics["conn"]["short_rows"] == 2
    assert diagnostics["conn"]["extra_value_rows"] == 1
    assert len(context.weird) == 4
    assert diagnostics["weird"]["skipped_rows"] == 2
    assert diagnostics["dns"]["parse_error"]
    assert context.dns == []

    assert len(MODULES["weird_protocol_violations"].analyze(context).findings) == 4
    assert len(MODULES["vlan_tag_mismatch_double_tag"].analyze(context).findings) == 3

    for module in MODULES.values():
        module.analyze(context)


def test_json_lines_parser_skips_malformed_and_non_object_rows(tmp_path: Path) -> None:
    ensure_detector_package()
    from elevadr_modules.zeek.parser import parse_zeek_log

    path = tmp_path / "weird.json"
    path.write_text(
        '{"ts":1,"name":"bad_checksum"}\nnot-json\n[1,2,3]\n{"ts":2,"name":"truncated_packet"}\n',
        encoding="utf-8",
    )
    rows = parse_zeek_log(path, "weird")
    assert [row["name"] for row in rows] == ["bad_checksum", "truncated_packet"]
