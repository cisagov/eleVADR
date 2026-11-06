from __future__ import annotations

from typing import Any

# These OT protocol logs carry one row per individual request/response message,
# unlike conn.log, which logs one row per TCP session. A persistent/long-lived
# session shows up as a single conn.log row no matter how many polls happen
# inside it; the protocol log preserves per-poll timing when present.
# cip.log (ICSNPP-ENIP's separate CIP-service-code log) can carry per-poll
# timestamps for EtherNet/IP conversations that enip.log alone collapses.
OT_PROTOCOL_LOGS = ("modbus", "dnp3", "s7comm", "enip", "cip")


def protocol_poll_series(
    context: Any, source: str, destination: str
) -> list[tuple[float, dict[str, Any]]]:
    """Return (timestamp, row) pairs from OT protocol logs for this exact pair.

    Empty when no protocol log has matching rows, so callers can fall back to
    conn.log-level (per-session) granularity.
    """
    items: list[tuple[float, dict[str, Any]]] = []
    for log_name in OT_PROTOCOL_LOGS:
        for row in context.log(log_name):
            src = str(row.get("source_ip") or row.get("id.orig_h") or "")
            dst = str(row.get("destination_ip") or row.get("id.resp_h") or "")
            if src != source or dst != destination:
                continue
            raw_ts = row.get("timestamp", row.get("ts"))
            try:
                ts = float(raw_ts)
            except (TypeError, ValueError):
                continue
            items.append((ts, row))
    return sorted(_dedupe_request_response_pairs(items), key=lambda item: item[0])


def _dedupe_request_response_pairs(
    items: list[tuple[float, dict[str, Any]]]
) -> list[tuple[float, dict[str, Any]]]:
    """Collapse a logged request/response pair into a single poll observation.

    Zeek's modbus.log (and potentially other OT protocol logs using the same
    convention) writes one row per PDU, tagging each with a shared transaction
    id (``tid``) plus a ``pdu_type`` of ``REQ``/``RESP``. One request/response
    round trip is one poll, not two; counting both halves would double-count
    polling cadence and make a single-shot conversation look more granular
    than conn.log, incorrectly triggering the protocol-log timing fallback.
    Rows without this uid+tid+pdu_type signature are passed through unchanged.
    """
    paired: dict[tuple[Any, Any], tuple[float, dict[str, Any]]] = {}
    unpaired: list[tuple[float, dict[str, Any]]] = []
    for ts, row in items:
        uid = row.get("uid")
        tid = row.get("tid")
        pdu_type = str(row.get("pdu_type") or "").upper()
        if uid is None or tid is None or pdu_type not in {"REQ", "RESP"}:
            unpaired.append((ts, row))
            continue
        key = (uid, tid)
        if key not in paired or pdu_type == "REQ":
            paired[key] = (ts, row)
    return [*paired.values(), *unpaired]


def best_series(
    context: Any,
    source: str,
    destination: str,
    connection_items: list[tuple[float, dict[str, Any]]],
) -> tuple[list[tuple[float, dict[str, Any]]], str]:
    """Pick the more granular of conn.log rows vs. OT protocol-log rows for this pair.

    More rows means finer time resolution for baseline/cadence modeling, and a
    protocol log can only have more rows than conn.log when multiple application
    messages happened inside one persistent session conn.log collapsed to one row.
    """
    protocol_items = protocol_poll_series(context, source, destination)
    if len(protocol_items) > len(connection_items):
        return protocol_items, "protocol_log"
    return connection_items, "connection"
