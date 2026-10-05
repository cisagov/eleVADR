from __future__ import annotations

from collections import defaultdict, deque
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata

ENGINEERING_WORDS = ("engineering", "engineer", "ews", "programming workstation")
MAX_EVIDENCE = 10
MODBUS_WRITES = {5, 6, 15, 16, 22, 23}
CIP_WRITES = {0x4D, 0x4E, 0x53}
MODBUS_FUNCTION_CODES = {
    "write_single_coil": 5,
    "write_single_register": 6,
    "write_multiple_coils": 15,
    "write_multiple_registers": 16,
    "mask_write_register": 22,
    "read_write_multiple_registers": 23,
}


class EngineeringWorkstationControlBurstModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="engineering_workstation_control_burst",
        name="Engineering Workstation Control Burst",
        description="Detects bursts of control-write/programming operations from authoritative engineering workstations, including bursts on otherwise authorized paths.",
        category="security_analysis",
        required_logs=(),
        required_any_logs=("modbus", "dnp3", "s7comm", "enip"),
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        policy = _policy(context.metadata)
        window = _as_float(policy.get("window_seconds")) or 60.0
        threshold = _as_int(policy.get("minimum_operations")) or 10
        engineering_hosts = set(_engineering_hosts(context.metadata)) | {str(x) for x in policy.get("engineering_hosts", [])}
        authorized_paths = [item for item in policy.get("authorized_paths", []) if isinstance(item, dict)]
        events: list[dict[str, Any]] = []
        for protocol in ("modbus", "dnp3", "s7comm", "enip"):
            for row in context.log(protocol):
                event = _write_event(protocol, row)
                if event and event["source_ip"] in engineering_hosts and event["timestamp"] is not None:
                    event["authorized"] = _authorized(event, authorized_paths)
                    events.append(event)
        events.sort(key=lambda row: row["timestamp"])

        by_source: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for event in events: by_source[event["source_ip"]].append(event)
        findings: list[Finding] = []
        for source in sorted(by_source):
            queue: deque[dict[str, Any]] = deque()
            best: list[dict[str, Any]] = []
            for event in by_source[source]:
                queue.append(event)
                while queue and event["timestamp"] - queue[0]["timestamp"] > window:
                    queue.popleft()
                if len(queue) >= threshold and len(queue) > len(best):
                    best = list(queue)
            if len(best) < threshold: continue
            unauthorized_count = sum(1 for event in best if not event["authorized"])
            destinations = sorted({event["destination_ip"] for event in best})
            services = sorted({event["protocol"] for event in best})
            findings.append(Finding(
                title="Engineering workstation issued a burst of control operations",
                severity="high" if unauthorized_count else "medium",
                summary=f"{source} issued {len(best)} control-write/programming operations within {window:g} seconds.",
                confidence="high",
                detection_basis="protocol_log",
                devices=[source, *destinations[:5]],
                services=services,
                ports=sorted({event["destination_port"] for event in best if event["destination_port"] is not None}),
                connection_pairs=[{"source": event["source_ip"], "destination": event["destination_ip"], "port": event["destination_port"], "service": event["protocol"]} for event in best[:MAX_EVIDENCE]],
                flows=[_redacted(event["raw"]) for event in best[:MAX_EVIDENCE]],
                timestamps=[event["timestamp"] for event in best[:MAX_EVIDENCE]],
                tags=["ot", "engineering-workstation", "control-burst"],
                metadata={
                    "window_seconds": window,
                    "minimum_operations": threshold,
                    "operation_count": len(best),
                    "authorized_operation_count": len(best) - unauthorized_count,
                    "unauthorized_operation_count": unauthorized_count,
                    "authorized_paths_do_not_suppress_burst_behavior": True,
                },
            ))

        return ModuleResult(
            self.metadata.id,
            findings,
            {"engineering_hosts": len(engineering_hosts), "write_events_evaluated": len(events), "findings": len(findings)},
            {
                "inspected_logs": [name for name in ("modbus", "dnp3", "s7comm", "enip") if context.log(name)],
                "engineering_hosts": sorted(engineering_hosts),
                "notes": [
                    "Engineering-workstation identity comes from authoritative asset inventory or explicit detector policy.",
                    "Explicit control authorization is reported as context but does not suppress anomalous burst behavior.",
                    "Observed control traffic never creates authorization.",
                ],
            },
            [],
        )


def _engineering_hosts(metadata: dict[str, Any]) -> list[str]:
    result: list[str] = []
    inventory = metadata.get("asset_inventory")
    if not isinstance(inventory, list): return result
    for asset in inventory:
        if not isinstance(asset, dict): continue
        text = " ".join(str(asset.get(k, "")) for k in ("asset_type", "role", "name", "hostname")).lower()
        if any(word in text for word in ENGINEERING_WORDS):
            values = asset.get("ips", []) if isinstance(asset.get("ips"), list) else [asset.get("ip")]
            result.extend(str(value) for value in values if value)
    return result


def _write_event(protocol: str, row: dict[str, Any]) -> dict[str, Any] | None:
    source = str(_first(row, "source_ip", "id.orig_h", "src") or "").strip(); destination = str(_first(row, "destination_ip", "id.resp_h", "dst") or "").strip()
    if not source or not destination: return None
    raw_function = _first(row, "function_code", "func", "fc", "cip_service", "service_code", "function")
    code = _as_int(raw_function)
    text = " ".join(str(_first(row, key) or "") for key in ("function_name", "func", "operation", "command", "service_name", "function", "activity")).lower()
    if protocol == "modbus" and code is None:
        normalized_func = str(raw_function or "").strip().lower().replace("-", "_").replace(" ", "_")
        code = MODBUS_FUNCTION_CODES.get(normalized_func)
    explicit = _first(row, "is_write", "write", "write_operation")
    is_write = explicit is True or str(explicit).lower() in {"true", "t", "1", "yes"}
    if protocol == "modbus": is_write = is_write or code in MODBUS_WRITES or "write" in text
    elif protocol == "dnp3": is_write = is_write or any(word in text for word in ("write", "operate", "select", "direct_operate", "control"))
    elif protocol == "s7comm": is_write = is_write or any(word in text for word in ("write", "download", "stop", "start", "plc_control")) or code in {5, 0x05, 0x28, 0x29}
    elif protocol == "enip": is_write = is_write or code in CIP_WRITES or any(word in text for word in ("write", "set_attribute", "download"))
    if not is_write: return None
    return {
        "protocol": protocol,
        "source_ip": source,
        "destination_ip": destination,
        "destination_port": _as_int(_first(row, "destination_port", "id.resp_p")) or {"modbus":502,"dnp3":20000,"s7comm":102,"enip":44818}.get(protocol),
        "timestamp": _as_float(_first(row, "timestamp", "ts")),
        "function_code": code,
        "raw": row,
    }


def _authorized(event: dict[str, Any], paths: list[dict[str, Any]]) -> bool:
    for path in paths:
        if str(path.get("protocol", "")).lower() not in {"", event["protocol"]}: continue
        if str(path.get("source", "")) != event["source_ip"] or str(path.get("destination", "")) != event["destination_ip"]: continue
        codes = path.get("allowed_function_codes")
        if isinstance(codes, list) and codes and event["function_code"] not in {_as_int(x) for x in codes}:
            continue
        return True
    return False


def _redacted(row: dict[str, Any]) -> dict[str, Any]:
    result = dict(row)
    for key in list(result):
        if any(token in key.lower() for token in ("password", "community", "credential", "secret")):
            result[key] = "[REDACTED]"
    return result


def _policy(metadata: dict[str, Any]) -> dict[str, Any]:
    value = metadata.get("engineering_control_burst_policy")
    return dict(value) if isinstance(value, dict) else {}


def _first(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if row.get(key) not in (None, ""): return row[key]
    return None

def _as_float(value: Any) -> float | None:
    try: return float(value) if value not in (None, "") else None
    except (TypeError, ValueError): return None

def _as_int(value: Any) -> int | None:
    try:
        if isinstance(value, str) and value.lower().startswith("0x"): return int(value, 16)
        return int(value) if value not in (None, "") else None
    except (TypeError, ValueError): return None
