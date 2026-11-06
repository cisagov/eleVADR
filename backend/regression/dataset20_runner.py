from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "frontend" / "src" / "tests" / "fixtures" / "topology_dense_report.json"
TEST = ROOT / "frontend" / "src" / "tests" / "NetworkTopologyInteraction.test.tsx"
TOPOLOGY = ROOT / "frontend" / "src" / "app" / "components" / "NetworkTopology" / "NetworkTopology.tsx"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    print("\n=== 20_topology_interaction_regression: dense fixture + interaction contract ===")
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    test = TEST.read_text(encoding="utf-8")
    topology = TOPOLOGY.read_text(encoding="utf-8")

    devices = sum(len(data["modules"][key]) for key in ("ot_devices", "it_devices", "edge_devices"))
    connections = len(data["modules"]["connection_success_panel"]["connections"])
    findings = len(data["arch_insights"]["detector_findings"])
    suspicious = len(data["modules"]["suspicious_outbound_connections_panel"])
    assets = data["arch_insights"]["detection_context_snapshot"]["assets"]
    roles = {str(item.get("role")) for item in assets}
    purdue = {str(item.get("purdueLevel")) for item in assets}
    subnets = {subnet for key in ("ot_devices", "it_devices", "edge_devices") for dev in data["modules"][key] for subnet in dev.get("subnets", [])}

    checks = [
        ("Dense fixture has at least 90 devices", devices >= 90, f"found {devices}"),
        ("Dense fixture has at least 150 connections", connections >= 150, f"found {connections}"),
        ("Dense fixture includes finding-related paths", findings >= 10, f"found {findings} findings"),
        ("Dense fixture includes suspicious flows", suspicious >= 6, f"found {suspicious}"),
        ("Dense fixture spans at least four subnets", len(subnets) >= 4, f"found {subnets}"),
        ("Dense fixture covers OT, IT, and Network roles", {"OT", "IT", "Network"}.issubset(roles), f"found {roles}"),
        ("Dense fixture covers Purdue 1, 2, 3.5, and 5", {"1", "2", "3.5", "5"}.issubset(purdue), f"found {purdue}"),
        ("Component tests cover device selection and connection inspection", "selects a device on click without opening details" in test and "opens connection details" in test, "drawer interaction tests missing"),
        ("Component tests cover node-body drag lifecycle", "drags a device from its node body" in test and "pointerUp" in test, "node-body drag test missing"),
        ("Component tests cover page-scroll versus modifier zoom", "modifier-wheel" in test and "ctrlKey: true" in test, "wheel/zoom interaction test missing"),
        ("Component tests cover Escape-to-clear", "Escape clears selection" in test, "selection clear test missing"),
        ("Component tests cover explicit filter toggle", "toggles the selected device filter" in test, "filter toggle test missing"),
        ("Topology retains a wide invisible edge hit target", "strokeWidth={Math.max(16, width + 12)}" in topology, "wide edge hit target missing"),
        ("Topology supports dragging from the node body", "onPointerDown={(event) => beginNodeDrag(event, node)}" in topology and 'className="node-drag-handle"' not in topology, "node-body drag wiring missing"),
        ("Drag release clears active drag state", "dragRef.current = null;" in topology and "finishNodeDrag" in topology, "drag release cleanup missing"),
        ("Ordinary wheel input is reserved for report scrolling", "if (!event.ctrlKey && !event.metaKey) return;" in topology, "ordinary wheel scrolling is not protected"),
        ("Double-click neighborhood focus remains wired", re.search(
    r'onDoubleClick=\{\(event\)\s*=>\s*\{\s*'
    r'event\.stopPropagation\(\);\s*'
    r'focusNodeNeighborhood\(node\);\s*'
    r'\}\}',
    topology,
) is not None, "double-click focus missing"),
        ("Escape-to-clear remains wired", 'if (event.key !== "Escape") return;' in topology, "Escape-to-clear missing"),
    ]

    for index, (label, ok, detail) in enumerate(checks, start=1):
        require(ok, f"{label}: {detail}")
        print(f"PASS  {index:02d}  {label}")

    print(f"PASS: topology regression fixture has {devices} devices, {connections} connections, {findings} findings, {suspicious} suspicious flows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
