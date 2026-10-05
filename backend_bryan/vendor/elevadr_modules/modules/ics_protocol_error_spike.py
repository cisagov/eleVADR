from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from statistics import mean
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata

MAX_EVIDENCE = 10
PROTOCOLS = ("modbus", "dnp3", "enip", "s7comm")


@dataclass(slots=True)
class _Event:
    protocol: str
    row: dict[str, Any]
    timestamp: float
    source: str
    destination: str
    source_port: int | None
    destination_port: int | None
    is_error: bool
    error_detail: str | None


class IcsProtocolErrorSpikeModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="ics_protocol_error_spike",
        name="ICS Protocol Error / Exception Spike",
        description=(
            "Detects elevated rates of ICS protocol error responses, including Modbus exceptions, "
            "DNP3 IIN error indications, EtherNet/IP/CIP general-status failures, and S7 error returns."
        ),
        category="security_analysis",
        required_logs=(),
        required_any_logs=PROTOCOLS,
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        policy = _policy(context.metadata)
        events: list[_Event] = []
        for protocol, rows in (
            ("modbus", context.modbus),
            ("dnp3", context.dnp3),
            ("enip", context.enip),
            ("s7comm", context.s7comm),
        ):
            for row in rows:
                event = _event(protocol, row)
                if event is not None:
                    events.append(event)

        findings, spike_windows = _detect(events, policy)
        error_events = sum(e.is_error for e in events)
        by_protocol = {
            p: {
                "events": sum(e.protocol == p for e in events),
                "errors": sum(e.protocol == p and e.is_error for e in events),
            }
            for p in PROTOCOLS
        }

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "protocol_events_evaluated": len(events),
                "protocol_error_events": error_events,
                "modbus_error_events": by_protocol["modbus"]["errors"],
                "dnp3_error_events": by_protocol["dnp3"]["errors"],
                "enip_cip_error_events": by_protocol["enip"]["errors"],
                "s7comm_error_events": by_protocol["s7comm"]["errors"],
                "error_spike_windows": spike_windows,
                "ics_protocol_error_spike_findings": len(findings),
            },
            evidence={
                "inspected_logs": [name for name, rows in (
                    ("modbus", context.modbus), ("dnp3", context.dnp3),
                    ("enip", context.enip), ("s7comm", context.s7comm),
                ) if rows],
                "policy_loaded": bool(policy),
                "notes": [
                    "The detector is rate-based: isolated exceptions are not sufficient for a finding.",
                    "Error ratios are evaluated in fixed analysis windows and compared with both an absolute threshold and, when sufficient baseline data exists, the learned baseline error ratio.",
                    "Modbus uses explicit exception evidence (exception fields/codes or exception responses); generic Modbus traffic is not treated as erroneous.",
                    "DNP3 requires explicit error/trouble IIN evidence; ordinary class/event IIN bits are not automatically errors.",
                    "CIP/EtherNet/IP general status 0 is success; non-zero general status is treated as an error response.",
                    "S7 uses explicit error class/code or non-success return evidence; generic S7 responses are not assumed to be errors.",
                    "Passive captures can miss responses because of asymmetric routing or packet loss, so absence or apparent concentration of errors should be interpreted in capture context.",
                ],
            },
            warnings=[],
        )


def _event(protocol: str, row: dict[str, Any]) -> _Event | None:
    ts = _as_float(_first(row, "timestamp", "ts"))
    if ts is None:
        return None
    is_error, detail = _classify_error(protocol, row)
    return _Event(
        protocol=protocol,
        row=row,
        timestamp=ts,
        source=_text(_first(row, "source_ip", "id.orig_h", "src", "source")),
        destination=_text(_first(row, "destination_ip", "id.resp_h", "dst", "destination")),
        source_port=_as_int(_first(row, "source_port", "id.orig_p", "src_port")),
        destination_port=_as_int(_first(row, "destination_port", "id.resp_p", "dst_port")),
        is_error=is_error,
        error_detail=detail,
    )


def _classify_error(protocol: str, row: dict[str, Any]) -> tuple[bool, str | None]:
    if protocol == "modbus":
        flag = _first(row, "is_exception", "exception", "exception_response")
        if _truthy(flag):
            return True, "exception_response"
        code = _as_int(_first(row, "exception_code", "modbus_exception_code", "exception_id"))
        if code is not None and code != 0:
            return True, f"exception_code={code}"
        function = _as_int(_first(row, "function_code", "function", "fc", "modbus_function"))
        if function is not None and function >= 0x80:
            return True, f"exception_function=0x{function:02x}"
        text = _norm(_first(row, "status", "response_status", "error", "exception_name", "function_name"))
        if any(term in text for term in ("exception", "illegal function", "illegal data", "server device failure", "gateway target failed")):
            return True, text
        return False, None

    if protocol == "enip":
        status = _first(row, "general_status", "cip_general_status", "cip_status", "response_status", "error_status")
        numeric = _as_int(status)
        if numeric is not None:
            if numeric != 0:
                return True, f"general_status={numeric}"
            return False, None
        text = _norm(status)
        if text and text not in {"success", "ok", "0", "0x00", "none"}:
            if any(term in text for term in ("error", "fail", "invalid", "denied", "unsupported", "not found", "conflict", "timeout")):
                return True, text
        return False, None

    if protocol == "s7comm":
        for key in ("error_class", "error_code", "s7_error_class", "s7_error_code"):
            value = _as_int(row.get(key))
            if value is not None and value != 0:
                return True, f"{key}={value}"
        value = _first(row, "return_code", "return_value", "status", "response_status", "error")
        numeric = _as_int(value)
        if numeric is not None:
            if numeric not in {0, 0xFF}:
                return True, f"return_code={numeric}"
            return False, None
        text = _norm(value)
        if text and text not in {"success", "ok", "reserved", "data ok", "no error"}:
            if any(term in text for term in ("error", "fail", "denied", "invalid", "not available", "not found", "access")):
                return True, text
        return False, None

    if protocol == "dnp3":
        explicit = _first(row, "iin_error", "iin_errors", "error_iin", "error_flag", "device_trouble")
        if _truthy(explicit):
            return True, _text(explicit) or "iin_error"
        for key in ("iin", "iin_bits", "iin_flags", "internal_indications", "response_iin"):
            text = _norm(row.get(key))
            if not text:
                continue
            # Deliberately exclude ordinary class/event indicators and restart-only state.
            error_terms = (
                "device trouble", "config corrupt", "configuration corrupt", "object unknown",
                "parameter error", "already executing", "event buffer overflow", "function unknown",
                "function not supported", "local control", "error", "trouble", "corrupt",
            )
            if any(term in text for term in error_terms):
                return True, text
        status = _norm(_first(row, "status", "response_status", "error"))
        if status and any(term in status for term in ("error", "fail", "invalid", "unsupported", "trouble")):
            return True, status
        return False, None

    return False, None


def _detect(events: list[_Event], policy: dict[str, Any]) -> tuple[list[Finding], int]:
    if not events:
        return [], 0

    baseline_seconds = max(0.0, _as_float(policy.get("baseline_seconds")) or 300.0)
    window_seconds = max(1.0, _as_float(policy.get("window_seconds")) or 60.0)
    min_events = max(1, _as_int(policy.get("min_events_per_window")) or 10)
    min_errors = max(1, _as_int(policy.get("min_errors_per_window")) or 3)
    min_error_ratio = _bounded_ratio(policy.get("min_error_ratio"), 0.25)
    baseline_multiplier = max(1.0, _as_float(policy.get("baseline_multiplier")) or 3.0)
    min_baseline_events = max(1, _as_int(policy.get("min_baseline_events")) or 10)
    group_by_pair = bool(policy.get("group_by_peer_pair", True))

    start = min(e.timestamp for e in events)
    baseline_end = start + baseline_seconds

    grouped: dict[tuple[str, str, str], list[_Event]] = defaultdict(list)
    for event in events:
        if _allowed(event, policy):
            continue
        key = (event.protocol, event.source if group_by_pair else "*", event.destination if group_by_pair else "*")
        grouped[key].append(event)

    findings: list[Finding] = []
    spike_windows = 0

    for key, rows in sorted(grouped.items()):
        protocol, source, destination = key
        rows.sort(key=lambda e: e.timestamp)
        baseline = [e for e in rows if e.timestamp < baseline_end]
        baseline_ratio = (sum(e.is_error for e in baseline) / len(baseline)) if baseline else 0.0
        baseline_is_sufficient = len(baseline) >= min_baseline_events

        windows: dict[int, list[_Event]] = defaultdict(list)
        for event in rows:
            if event.timestamp < baseline_end:
                continue
            index = int((event.timestamp - baseline_end) // window_seconds)
            windows[index].append(event)

        qualifying: list[tuple[int, list[_Event], float]] = []
        for index, wr in sorted(windows.items()):
            errors = sum(e.is_error for e in wr)
            ratio = errors / len(wr) if wr else 0.0
            if len(wr) < min_events or errors < min_errors or ratio < min_error_ratio:
                continue
            if baseline_is_sufficient:
                comparison_floor = baseline_ratio * baseline_multiplier
                if baseline_ratio == 0:
                    comparison_floor = min_error_ratio
                if ratio < max(min_error_ratio, comparison_floor):
                    continue
            qualifying.append((index, wr, ratio))

        if not qualifying:
            continue

        spike_windows += len(qualifying)
        all_errors = [e for _, wr, _ in qualifying for e in wr if e.is_error]
        peak_ratio = max(r for _, _, r in qualifying)
        total_window_events = sum(len(wr) for _, wr, _ in qualifying)
        total_window_errors = len(all_errors)
        severity = "high" if peak_ratio >= 0.5 and total_window_errors >= max(5, min_errors) else "medium"
        confidence = "high" if baseline_is_sufficient else "medium"
        basis_note = (
            f"Baseline error ratio was {baseline_ratio:.1%} across {len(baseline)} event(s)."
            if baseline_is_sufficient else
            f"Only {len(baseline)} baseline event(s) were available, so the finding relies on absolute spike thresholds."
        )
        display_source = source if source != "*" else "multiple sources"
        display_destination = destination if destination != "*" else "multiple destinations"

        findings.append(Finding(
            title=f"{_protocol_name(protocol)} error/exception rate spike",
            severity=severity,
            confidence=confidence,
            detection_basis="protocol_log",
            summary=(
                f"Observed {total_window_errors} error response(s) in {total_window_events} {_protocol_name(protocol)} event(s) "
                f"across {len(qualifying)} qualifying window(s) for {display_source} -> {display_destination}; "
                f"peak error ratio was {peak_ratio:.1%}. {basis_note}"
            ),
            devices=sorted({x for e in all_errors for x in (e.source, e.destination) if x}),
            services=[protocol],
            ports=sorted({p for e in all_errors for p in (e.source_port, e.destination_port) if p is not None}),
            connection_pairs=[] if source == "*" else [{"source": source, "destination": destination}],
            flows=[_flow(e) for e in all_errors[:MAX_EVIDENCE]],
            timestamps=[e.timestamp for e in all_errors[:MAX_EVIDENCE]],
            tags=["ics", protocol, "protocol-error", "error-spike"],
            metadata={
                "protocol": protocol,
                "source": None if source == "*" else source,
                "destination": None if destination == "*" else destination,
                "baseline_event_count": len(baseline),
                "baseline_error_count": sum(e.is_error for e in baseline),
                "baseline_error_ratio": baseline_ratio,
                "baseline_sufficient": baseline_is_sufficient,
                "qualifying_window_count": len(qualifying),
                "qualifying_window_event_count": total_window_events,
                "qualifying_window_error_count": total_window_errors,
                "peak_error_ratio": peak_ratio,
                "window_seconds": window_seconds,
                "min_events_per_window": min_events,
                "min_errors_per_window": min_errors,
                "min_error_ratio": min_error_ratio,
                "baseline_multiplier": baseline_multiplier,
                "error_details": sorted({e.error_detail for e in all_errors if e.error_detail})[:20],
                "evidence_event_count": min(len(all_errors), MAX_EVIDENCE),
                "evidence_truncated": len(all_errors) > MAX_EVIDENCE,
            },
        ))

    return findings, spike_windows


def _flow(event: _Event) -> dict[str, Any]:
    return {
        "timestamp": event.timestamp,
        "source_ip": event.source,
        "destination_ip": event.destination,
        "source_port": event.source_port,
        "destination_port": event.destination_port,
        "protocol": event.protocol,
        "error_detail": event.error_detail,
    }


def _allowed(event: _Event, policy: dict[str, Any]) -> bool:
    hosts = {_text(x) for x in _list(policy.get("allowed_hosts"))}
    if event.source in hosts or event.destination in hosts:
        return True
    for pair in _list(policy.get("allowed_pairs")):
        if not isinstance(pair, dict):
            continue
        if _text(pair.get("source")) != event.source or _text(pair.get("destination")) != event.destination:
            continue
        protocols = {_norm(x) for x in _list(pair.get("protocols"))}
        if not protocols or event.protocol in protocols:
            return True
    return False


def _policy(metadata: dict[str, Any]) -> dict[str, Any]:
    for key in ("ics_protocol_error_policy", "ics_error_spike_policy", "protocol_error_spike_policy"):
        value = metadata.get(key)
        if isinstance(value, dict):
            return value
    return {}


def _protocol_name(protocol: str) -> str:
    return {"modbus": "Modbus", "dnp3": "DNP3", "enip": "EtherNet/IP CIP", "s7comm": "S7comm"}.get(protocol, protocol)


def _first(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in row and row[key] not in (None, "", "-"):
            return row[key]
    return None


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _norm(value: Any) -> str:
    return " ".join(_text(value).lower().replace("_", " ").replace("-", " ").split())


def _as_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        if isinstance(value, str):
            text = value.strip().lower()
            if not text:
                return None
            return int(text, 16) if text.startswith("0x") else int(float(text))
        return int(value)
    except (TypeError, ValueError):
        return None


def _as_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return _norm(value) in {"true", "yes", "1", "set", "exception", "error", "failed", "failure"}


def _list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _bounded_ratio(value: Any, default: float) -> float:
    parsed = _as_float(value)
    if parsed is None:
        return default
    return min(1.0, max(0.0, parsed))
