from __future__ import annotations

from collections import defaultdict
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata

CONTROLLER_WORDS = ("plc", "rtu", "controller", "dcs", "ied")
OT_PORTS = {502, 20000, 102, 44818, 2222, 47808}
MAX_EVIDENCE = 10


class PlcRtuPeerChangeModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="plc_rtu_peer_change",
        name="PLC / RTU Peer Change",
        description="Detects a new communication peer involving an authoritative PLC, RTU, controller, or IED after the capture baseline.",
        category="security_analysis",
        required_logs=("conn",),
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        policy = _policy(context.metadata)
        baseline_seconds = _as_float(policy.get("baseline_seconds")) or 300.0
        controllers = set(_controller_hosts(context.metadata)) | {str(x) for x in policy.get("controller_hosts", [])}
        ignored = {str(x) for x in policy.get("ignored_hosts", [])}
        allowed_pairs = {_pair_key(item) for item in policy.get("allowed_pairs", []) if isinstance(item, dict)}
        allowed_pairs.discard(None)
        rows = [_normalize(row) for row in context.connections]
        rows = [row for row in rows if row and (row["source_ip"] in controllers or row["destination_ip"] in controllers) and _is_otish(row)]
        times = [row["timestamp"] for row in rows if row["timestamp"] is not None]
        if not rows or not times:
            return ModuleResult(self.metadata.id, [], {"candidate_connections": len(rows), "findings": 0}, {"inspected_logs": ["conn"], "controller_hosts": sorted(controllers)}, [])

        capture_start = min(times)
        baseline_end = capture_start + baseline_seconds
        baseline_pairs: set[tuple[str, str, str, int | None]] = set()
        new_rows: dict[tuple[str, str, str, int | None], list[dict[str, Any]]] = defaultdict(list)
        for row in rows:
            key = (row["source_ip"], row["destination_ip"], row["service"], row["destination_port"])
            if row["timestamp"] is not None and row["timestamp"] <= baseline_end:
                baseline_pairs.add(key)
                continue
            if row["source_ip"] in ignored or row["destination_ip"] in ignored:
                continue
            simple_pair = (row["source_ip"], row["destination_ip"])
            reverse_pair = (row["destination_ip"], row["source_ip"])
            if key not in baseline_pairs and simple_pair not in allowed_pairs and reverse_pair not in allowed_pairs:
                new_rows[key].append(row)

        findings: list[Finding] = []
        for key, events in sorted(new_rows.items(), key=lambda item: str(item[0])):
            source, destination, service, port = key
            controller = source if source in controllers else destination
            peer = destination if controller == source else source
            findings.append(Finding(
                title="PLC/RTU communicated with a new peer after baseline",
                severity="medium",
                summary=f"Controller {controller} communicated with new peer {peer} using {service or 'OT traffic'} after the baseline window.",
                confidence="high",
                detection_basis="derived",
                devices=[controller, peer],
                services=[service] if service else [],
                ports=[port] if port is not None else [],
                connection_pairs=[{"source": source, "destination": destination, "port": port, "service": service}],
                flows=[event["raw"] for event in events[:MAX_EVIDENCE]],
                timestamps=[event["timestamp"] for event in events if event["timestamp"] is not None][:MAX_EVIDENCE],
                tags=["ot", "controller", "peer-change"],
                metadata={"baseline_start": capture_start, "baseline_end": baseline_end, "event_count": len(events)},
            ))

        return ModuleResult(
            self.metadata.id,
            findings,
            {"controller_hosts": len(controllers), "candidate_connections": len(rows), "new_controller_pairs": len(new_rows), "findings": len(findings)},
            {
                "inspected_logs": ["conn"],
                "controller_hosts": sorted(controllers),
                "baseline_start": capture_start,
                "baseline_end": baseline_end,
                "notes": [
                    "Controller identity comes from authoritative asset inventory or explicit detector policy.",
                    "Observed communication pairs are baseline evidence only and never become authorization; only explicit allowed_pairs can suppress a pair.",
                ],
            },
            [],
        )


def _controller_hosts(metadata: dict[str, Any]) -> list[str]:
    result: list[str] = []
    inventory = metadata.get("asset_inventory")
    if not isinstance(inventory, list): return result
    for asset in inventory:
        if not isinstance(asset, dict): continue
        text = " ".join(str(asset.get(k, "")) for k in ("asset_type", "role", "name", "hostname")).lower()
        if any(word in text for word in CONTROLLER_WORDS):
            for value in asset.get("ips", []) if isinstance(asset.get("ips"), list) else [asset.get("ip")]:
                if value: result.append(str(value))
    return result


def _is_otish(row: dict[str, Any]) -> bool:
    return row["destination_port"] in OT_PORTS or row["service"] in {"modbus", "dnp3", "s7comm", "s7", "enip", "ethernetip", "cip", "bacnet"}


def _normalize(row: dict[str, Any]) -> dict[str, Any] | None:
    source = str(_first(row, "source_ip", "id.orig_h") or "").strip(); dest = str(_first(row, "destination_ip", "id.resp_h") or "").strip()
    if not source or not dest: return None
    port = _as_int(_first(row, "destination_port", "id.resp_p"))
    service = str(_first(row, "service", "protocol_name") or "").strip().lower() or {502:"modbus",20000:"dnp3",102:"s7comm",44818:"enip",47808:"bacnet"}.get(port, "")
    return {"source_ip": source, "destination_ip": dest, "destination_port": port, "service": service, "timestamp": _as_float(_first(row, "timestamp", "ts")), "raw": row}


def _pair_key(item: dict[str, Any]) -> tuple[str, str] | None:
    source = str(item.get("source", "")).strip(); destination = str(item.get("destination", "")).strip()
    return (source, destination) if source and destination else None


def _policy(metadata: dict[str, Any]) -> dict[str, Any]:
    value = metadata.get("plc_rtu_peer_change_policy")
    return dict(value) if isinstance(value, dict) else {}


def _first(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if row.get(key) not in (None, ""): return row[key]
    return None

def _as_float(value: Any) -> float | None:
    try: return float(value) if value not in (None, "") else None
    except (TypeError, ValueError): return None

def _as_int(value: Any) -> int | None:
    try: return int(value) if value not in (None, "") else None
    except (TypeError, ValueError): return None
