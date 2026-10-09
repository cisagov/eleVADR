from __future__ import annotations

import argparse
import ast
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SNAPSHOT = ROOT / "backend_bryan" / "reference" / "module_registry_snapshot.json"
MODULE_DIR = ROOT / "backend_bryan" / "vendor" / "elevadr_modules" / "modules"
DETAILS = ROOT / "frontend" / "src" / "app" / "components" / "DetectionConfiguration" / "moduleDetails.ts"
SCHEMA = ROOT / "frontend" / "src" / "app" / "components" / "DetectionConfiguration" / "advancedPolicySchema.ts"
DEFAULTS = ROOT / "frontend" / "src" / "app" / "components" / "DetectionConfiguration" / "moduleHelpDefaults.ts"


@dataclass(frozen=True)
class DetectorMetadata:
    id: str
    name: str
    description: str
    required_logs: tuple[str, ...]
    required_any_logs: tuple[str, ...]
    path: Path


def _literal(node: ast.AST | None, env: dict[str, Any]) -> Any:
    if node is None:
        return None
    try:
        return ast.literal_eval(node)
    except Exception:
        if isinstance(node, ast.Name):
            return env.get(node.id)
    return None


def _source_metadata(path: Path) -> DetectorMetadata | None:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    env: dict[str, Any] = {}
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        value = _literal(node.value, env)
        if value is None:
            continue
        for target in targets:
            if isinstance(target, ast.Name):
                env[target.id] = value

    for class_node in (n for n in tree.body if isinstance(n, ast.ClassDef)):
        for node in class_node.body:
            if not isinstance(node, ast.Assign):
                continue
            if not any(isinstance(t, ast.Name) and t.id == "metadata" for t in node.targets):
                continue
            if not isinstance(node.value, ast.Call):
                continue
            kwargs = {kw.arg: kw.value for kw in node.value.keywords if kw.arg}
            module_id = _literal(kwargs.get("id"), env)
            name = _literal(kwargs.get("name"), env)
            description = _literal(kwargs.get("description"), env)
            required_logs = _literal(kwargs.get("required_logs"), env) or ()
            required_any_logs = _literal(kwargs.get("required_any_logs"), env) or ()
            if all(isinstance(v, str) for v in (module_id, name, description)):
                return DetectorMetadata(
                    id=module_id,
                    name=name,
                    description=description,
                    required_logs=tuple(required_logs),
                    required_any_logs=tuple(required_any_logs),
                    path=path,
                )
    return None


def _frontend_details() -> dict[str, dict[str, Any]]:
    text = DETAILS.read_text(encoding="utf-8")
    start = text.index("export const DETECTION_MODULE_DETAILS")
    text = text[start:]
    entries: dict[str, dict[str, Any]] = {}
    cursor = text.index("{") + 1
    while True:
        match = re.search(r'\n\s{2}"([^"]+)":\s*\{', text[cursor:])
        if not match:
            break
        module_id = match.group(1)
        block_start = cursor + match.end() - 1
        depth = 0
        in_string = False
        escaped = False
        end = block_start
        for end in range(block_start, len(text)):
            char = text[end]
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
                continue
            if char == '"':
                in_string = True
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    break
        block = text[block_start : end + 1]

        def string(field: str) -> str:
            m = re.search(rf'\b{re.escape(field)}:\s*"((?:[^"\\]|\\.)*)"', block, flags=re.S)
            if not m:
                raise ValueError(f"{module_id}: missing {field} in {DETAILS}")
            return bytes(m.group(1), "utf-8").decode("unicode_escape")

        def string_array(field: str) -> tuple[str, ...]:
            m = re.search(rf'\b{re.escape(field)}:\s*\[([^\]]*)\]', block, flags=re.S)
            if not m:
                raise ValueError(f"{module_id}: missing {field} in {DETAILS}")
            return tuple(re.findall(r'"([^"]+)"', m.group(1)))

        entries[module_id] = {
            "id": string("id"),
            "name": string("name"),
            "description": string("description"),
            "required_logs": string_array("requiredLogs"),
            "required_any_logs": string_array("requiredAnyLogs"),
        }
        cursor = end + 1
    return entries


def _numeric_schema_fields() -> dict[str, set[str]]:
    text = SCHEMA.read_text(encoding="utf-8")
    result: dict[str, set[str]] = {}
    for match in re.finditer(r'\{"moduleId":"([^"]+)","fields":\[(.*?)\]\}', text):
        module_id, body = match.group(1), match.group(2)
        numeric = set(re.findall(r'\{"key":"([^"]+)","type":"number"\}', body))
        if numeric:
            result[module_id] = numeric
    return result


def _frontend_defaults() -> dict[str, dict[str, float]]:
    text = DEFAULTS.read_text(encoding="utf-8")
    marker = "export const MODULE_HELP_NUMERIC_DEFAULTS"
    start = text.index(marker)
    text = text[start:]
    outer_start = text.index("{")
    entries: dict[str, dict[str, float]] = {}
    cursor = outer_start + 1
    pattern = re.compile(r'\b([a-z0-9_]+):\s*\{')
    while True:
        match = pattern.search(text, cursor)
        if not match:
            break
        module_id = match.group(1)
        block_start = match.end() - 1
        depth = 0
        end = block_start
        for end in range(block_start, len(text)):
            if text[end] == "{":
                depth += 1
            elif text[end] == "}":
                depth -= 1
                if depth == 0:
                    break
        block = text[block_start + 1 : end]
        values = {
            key: float(value)
            for key, value in re.findall(r'\b([a-z0-9_]+):\s*(-?\d+(?:\.\d+)?)', block)
        }
        entries[module_id] = values
        cursor = end + 1
    return entries


def _constant_environment(source: str) -> dict[str, Any]:
    tree = ast.parse(source)
    env: dict[str, Any] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
            continue
        try:
            env[node.targets[0].id] = ast.literal_eval(node.value)
        except Exception:
            pass
    return env


def _resolve_token(token: str, env: dict[str, Any]) -> float | None:
    token = token.strip()
    if token in env and isinstance(env[token], (int, float)):
        return float(env[token])
    try:
        value = ast.literal_eval(token)
    except Exception:
        return None
    return float(value) if isinstance(value, (int, float)) else None


def _implementation_default(path: Path, field: str) -> float | None:
    source = path.read_text(encoding="utf-8")
    env = _constant_environment(source)
    escaped = re.escape(field)
    token = r'([A-Za-z_][A-Za-z0-9_]*|-?\d+(?:\.\d+)?)'
    patterns = [
        rf'\.get\(["\']{escaped}["\']\s*,\s*{token}\)',
        rf'\.get\(["\']{escaped}["\']\)\s*,\s*{token}\)',
        rf'\.get\(["\']{escaped}["\']\)[^\n;]{{0,80}}?\bor\s+{token}',
    ]
    for pattern in patterns:
        match = re.search(pattern, source)
        if match:
            value = _resolve_token(match.group(1), env)
            if value is not None:
                return value
    return None


def audit(*, allowed_missing_sources: set[str] | None = None) -> list[str]:
    allowed_missing_sources = allowed_missing_sources or set()
    errors: list[str] = []
    snapshot_rows = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    snapshot = {row["id"]: row for row in snapshot_rows}
    frontend = _frontend_details()

    if len(snapshot) != 75:
        errors.append(f"Registry snapshot must contain 75 modules; found {len(snapshot)}")
    if set(frontend) != set(snapshot):
        errors.append(
            "Frontend module IDs differ from registry snapshot: "
            f"missing={sorted(set(snapshot) - set(frontend))} extra={sorted(set(frontend) - set(snapshot))}"
        )

    source_by_id: dict[str, DetectorMetadata] = {}
    for path in MODULE_DIR.glob("*.py"):
        if path.name in {"__init__.py", "base.py", "template.py", "remote_access.py"}:
            continue
        metadata = _source_metadata(path)
        if metadata and metadata.id in snapshot:
            source_by_id[metadata.id] = metadata

    missing_sources = set(snapshot) - set(source_by_id)
    unexpected_missing = missing_sources - allowed_missing_sources
    if unexpected_missing:
        errors.append(f"Detector implementation source missing for: {sorted(unexpected_missing)}")

    for module_id, row in sorted(snapshot.items()):
        detail = frontend.get(module_id)
        if not detail:
            continue
        expected_any = tuple(row.get("required_any_logs", []))
        comparisons = {
            "id": module_id,
            "name": row["name"],
            "required_logs": tuple(row.get("required_logs", [])),
            "required_any_logs": expected_any,
        }
        for field, expected in comparisons.items():
            if detail[field] != expected:
                errors.append(f"{module_id}: frontend {field}={detail[field]!r}, registry={expected!r}")

        metadata = source_by_id.get(module_id)
        if metadata:
            source_checks = {
                "name": metadata.name,
                "description": metadata.description,
                "required_logs": metadata.required_logs,
                "required_any_logs": metadata.required_any_logs,
            }
            for field, expected in source_checks.items():
                if detail[field] != expected:
                    errors.append(f"{module_id}: frontend {field}={detail[field]!r}, implementation={expected!r}")

    schema_numeric = _numeric_schema_fields()
    frontend_defaults = _frontend_defaults()
    schema_pairs = {(module_id, field) for module_id, fields in schema_numeric.items() for field in fields}
    default_pairs = {(module_id, field) for module_id, values in frontend_defaults.items() for field in values}
    if schema_pairs != default_pairs:
        errors.append(
            "Numeric help defaults must cover exactly the numeric Context schema fields: "
            f"missing={sorted(schema_pairs - default_pairs)} extra={sorted(default_pairs - schema_pairs)}"
        )

    for module_id, field in sorted(schema_pairs & default_pairs):
        metadata = source_by_id.get(module_id)
        if not metadata:
            if module_id not in allowed_missing_sources:
                errors.append(f"{module_id}.{field}: cannot verify default because implementation source is missing")
            continue
        actual = _implementation_default(metadata.path, field)
        documented = frontend_defaults[module_id][field]
        if actual is None:
            errors.append(f"{module_id}.{field}: could not extract implementation default from {metadata.path.name}")
        elif abs(actual - documented) > 1e-12:
            errors.append(f"{module_id}.{field}: help default={documented:g}, implementation default={actual:g}")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit frontend detector help against the 75-module implementation contract.")
    parser.add_argument(
        "--allow-missing-source",
        action="append",
        default=[],
        metavar="MODULE_ID",
        help="Allow a named implementation source to be absent (diagnostic use only; regression tests are strict).",
    )
    args = parser.parse_args()
    errors = audit(allowed_missing_sources=set(args.allow_missing_source))
    if errors:
        print("FAIL  module help accuracy audit")
        for error in errors:
            print(f"  - {error}")
        return 1
    print("PASS  module help accuracy audit: 75 modules, registry/input parity, implementation descriptions, and numeric Context defaults verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
