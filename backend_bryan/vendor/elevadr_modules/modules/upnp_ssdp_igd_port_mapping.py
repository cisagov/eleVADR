from __future__ import annotations

from collections import defaultdict
from ipaddress import ip_address, ip_network
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata

MAX_EVIDENCE_FLOWS = 10

ADD_MAPPING_ACTIONS = {
    "addportmapping",
    "addanyportmapping",
    "add_port_mapping",
    "add_any_port_mapping",
}
DELETE_MAPPING_ACTIONS = {"deleteportmapping", "delete_port_mapping"}

ACTION_FIELDS = (
    "action",
    "soap_action",
    "soapaction",
    "igd_action",
    "request_action",
    "method",
    "operation",
)
EXTERNAL_PORT_FIELDS = (
    "external_port",
    "new_external_port",
    "wan_port",
    "public_port",
    "mapped_external_port",
)
INTERNAL_PORT_FIELDS = (
    "internal_port",
    "new_internal_port",
    "lan_port",
    "private_port",
)
INTERNAL_CLIENT_FIELDS = (
    "internal_client",
    "new_internal_client",
    "lan_host",
    "private_host",
    "target_host",
)
PROTOCOL_FIELDS = (
    "mapping_protocol",
    "new_protocol",
    "port_mapping_protocol",
    "transport_protocol",
)
ENABLED_FIELDS = ("enabled", "new_enabled", "mapping_enabled")
RESULT_FIELDS = ("success", "succeeded", "result", "status", "response_status", "error_code")

SSDP_METHOD_FIELDS = ("method", "message_type", "ssdp_method", "request_method")
SSDP_TARGET_FIELDS = ("st", "search_target", "nt", "notification_type", "target")

ROLE_KEYS = ("role", "zone", "trust_zone", "security_zone", "network_role", "type")
CIDR_KEYS = ("cidr", "subnet", "network", "prefix")
NAME_KEYS = ("name", "label", "segment")

OT_ROLE_TOKENS = {
    "ot", "control", "controls", "ics", "scada", "industrial", "process", "plc",
    "level0", "level1", "level2", "l0", "l1", "l2",
}


class UpnpSsdpIgdPortMappingModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="upnp_ssdp_igd_port_mapping",
        name="UPnP / SSDP Exposure & IGD Port Mapping",
        description=(
            "Detects explicit UPnP Internet Gateway Device port-mapping activity and "
            "unexpected SSDP exposure while avoiding port-only inference from UDP/1900."
        ),
        category="security_analysis",
        required_logs=(),
        required_any_logs=("upnp", "upnp_igd", "ssdp"),
        default_enabled=True,
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        upnp_rows = list(context.upnp) + list(context.upnp_igd)
        ssdp_rows = list(context.ssdp)
        conn_by_uid = {
            str(row.get("uid")): row
            for row in context.connections
            if row.get("uid") not in (None, "")
        }
        segments = _segments(context.metadata)

        mappings: list[dict[str, Any]] = []
        delete_events = 0
        unknown_actions = 0
        for row in upnp_rows:
            action = _action(row)
            if action in ADD_MAPPING_ACTIONS:
                mappings.append(_mapping_event(row, action, conn_by_uid, segments))
            elif action in DELETE_MAPPING_ACTIONS:
                delete_events += 1
            else:
                unknown_actions += 1

        ssdp_exposure = []
        ordinary_ssdp = 0
        for row in ssdp_rows:
            event = _ssdp_event(row, conn_by_uid, segments)
            if event["unexpected_exposure"]:
                ssdp_exposure.append(event)
            else:
                ordinary_ssdp += 1

        findings = _mapping_findings(mappings) + _ssdp_findings(ssdp_exposure)
        affected = {
            value
            for finding in findings
            for value in finding.devices
            if value
        }
        inspected = []
        if context.upnp:
            inspected.append("upnp")
        if context.upnp_igd:
            inspected.append("upnp_igd")
        if context.ssdp:
            inspected.append("ssdp")

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "upnp_igd_events_evaluated": len(upnp_rows),
                "port_mapping_events": len(mappings),
                "successful_or_enabled_mapping_events": sum(1 for event in mappings if event["mapping_active"] is True),
                "mapping_state_unknown_events": sum(1 for event in mappings if event["mapping_active"] is None),
                "delete_mapping_events": delete_events,
                "unclassified_upnp_events": unknown_actions,
                "ssdp_events_evaluated": len(ssdp_rows),
                "ordinary_ssdp_events": ordinary_ssdp,
                "unexpected_ssdp_exposure_events": len(ssdp_exposure),
                "upnp_ssdp_findings": len(findings),
                "affected_devices": len(affected),
            },
            evidence={
                "inspected_logs": inspected,
                "notes": _notes(),
            },
            warnings=[],
        )


def _mapping_event(
    row: dict[str, Any],
    action: str,
    conn_by_uid: dict[str, dict[str, Any]],
    segments: list[dict[str, Any]],
) -> dict[str, Any]:
    uid = _text(row.get("uid"))
    conn = conn_by_uid.get(uid, {}) if uid else {}
    source = _first_text(row, "source_ip", "id.orig_h") or _first_text(conn, "source_ip", "id.orig_h")
    gateway = _first_text(row, "destination_ip", "id.resp_h", "gateway", "igd_ip") or _first_text(conn, "destination_ip", "id.resp_h")
    internal_client = _first_text(row, *INTERNAL_CLIENT_FIELDS)
    if not internal_client:
        internal_client = source
    external_port = _first_int(row, *EXTERNAL_PORT_FIELDS)
    internal_port = _first_int(row, *INTERNAL_PORT_FIELDS)
    protocol = (_first_text(row, *PROTOCOL_FIELDS) or "").upper() or None
    active = _mapping_active(row)
    timestamp = _first_value(row, "timestamp", "ts")
    if timestamp is None:
        timestamp = _first_value(conn, "timestamp", "ts")

    source_segment = _segment_for_ip(source, segments)
    client_segment = _segment_for_ip(internal_client, segments)
    client_is_ot = _is_ot_segment(client_segment)

    return {
        "action": action,
        "source": source,
        "gateway": gateway,
        "internal_client": internal_client,
        "external_port": external_port,
        "internal_port": internal_port,
        "protocol": protocol,
        "mapping_active": active,
        "timestamp": timestamp,
        "uid": uid,
        "row": row,
        "connection": conn or None,
        "source_segment": source_segment,
        "client_segment": client_segment,
        "client_is_ot": client_is_ot,
    }


def _mapping_active(row: dict[str, Any]) -> bool | None:
    for field in ENABLED_FIELDS:
        if field in row and row.get(field) not in (None, ""):
            return _as_bool(row.get(field))

    for field in RESULT_FIELDS:
        if field not in row or row.get(field) in (None, ""):
            continue
        value = row.get(field)
        boolean = _as_bool(value)
        if boolean is not None:
            return boolean
        token = _norm(value)
        if token in {"ok", "success", "succeeded", "created", "active", "enabled", "200", "0"}:
            return True
        if token in {"failed", "failure", "error", "denied", "disabled", "inactive"}:
            return False
        try:
            code = int(str(value).strip())
        except (TypeError, ValueError):
            continue
        if field == "error_code":
            return code == 0
        if field in {"status", "response_status"} and 200 <= code < 300:
            return True
    return None


def _ssdp_event(
    row: dict[str, Any],
    conn_by_uid: dict[str, dict[str, Any]],
    segments: list[dict[str, Any]],
) -> dict[str, Any]:
    uid = _text(row.get("uid"))
    conn = conn_by_uid.get(uid, {}) if uid else {}
    source = _first_text(row, "source_ip", "id.orig_h") or _first_text(conn, "source_ip", "id.orig_h")
    destination = _first_text(row, "destination_ip", "id.resp_h") or _first_text(conn, "destination_ip", "id.resp_h")
    destination_port = _first_int(row, "destination_port", "id.resp_p")
    if destination_port is None:
        destination_port = _first_int(conn, "destination_port", "id.resp_p")
    method = (_first_text(row, *SSDP_METHOD_FIELDS) or "").upper() or None
    target = _first_text(row, *SSDP_TARGET_FIELDS)
    timestamp = _first_value(row, "timestamp", "ts")
    if timestamp is None:
        timestamp = _first_value(conn, "timestamp", "ts")

    source_segment = _segment_for_ip(source, segments)
    destination_segment = _segment_for_ip(destination, segments)
    standard_local = _is_standard_ssdp_destination(destination, destination_port)
    external = _is_global_ip(destination)
    cross_segment = bool(source_segment and destination_segment and source_segment["identity"] != destination_segment["identity"])
    unexpected = bool(destination and (external or cross_segment) and not standard_local)

    return {
        "source": source,
        "destination": destination,
        "port": destination_port,
        "method": method,
        "target": target,
        "timestamp": timestamp,
        "uid": uid,
        "row": row,
        "connection": conn or None,
        "source_segment": source_segment,
        "destination_segment": destination_segment,
        "unexpected_exposure": unexpected,
        "external_destination": external,
        "cross_segment": cross_segment,
    }


def _mapping_findings(events: list[dict[str, Any]]) -> list[Finding]:
    grouped: dict[tuple[str, str, int | None, int | None, str | None], list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        grouped[(
            event["source"] or "",
            event["internal_client"] or "",
            event["external_port"],
            event["internal_port"],
            event["protocol"],
        )].append(event)

    findings: list[Finding] = []
    for (_, _, external_port, internal_port, protocol), items in sorted(grouped.items(), key=lambda item: str(item[0])):
        active = [item for item in items if item["mapping_active"] is True]
        failed = [item for item in items if item["mapping_active"] is False]
        unknown = [item for item in items if item["mapping_active"] is None]
        ot_target = any(item["client_is_ot"] for item in items)

        if active and ot_target:
            severity = "high"
        elif active:
            severity = "medium"
        elif unknown:
            severity = "medium"
        else:
            severity = "low"

        confidence = "high" if active or failed else "medium"
        representative = items[:MAX_EVIDENCE_FLOWS]
        source_hosts = sorted({item["source"] for item in items if item["source"]})
        internal_clients = sorted({item["internal_client"] for item in items if item["internal_client"]})
        gateways = sorted({item["gateway"] for item in items if item["gateway"]})
        devices = sorted(set(source_hosts + internal_clients + gateways))
        segments = sorted({seg["name"] for item in items for seg in (item["source_segment"], item["client_segment"]) if seg and seg.get("name")})

        if active:
            state_phrase = f"{len(active)} mapping event(s) explicitly indicate the mapping was enabled or succeeded"
        elif unknown:
            state_phrase = f"{len(unknown)} AddPortMapping request event(s) were observed, but success state was not available"
        else:
            state_phrase = f"{len(failed)} mapping attempt(s) were explicitly unsuccessful"

        mapping_desc = _mapping_description(external_port, internal_port, protocol, internal_clients)
        summary = (
            f"UPnP Internet Gateway Device telemetry recorded {len(items)} AddPortMapping/AddAnyPortMapping event(s); {state_phrase}. "
            f"{mapping_desc} Automatic IGD mappings can expose an internal service to inbound WAN traffic without a manually managed firewall rule. "
            "Confirm that the mapping is authorized, required, time-bounded, and consistent with gateway/firewall policy."
        )
        if ot_target:
            summary += " The mapped internal client is in a segment identified as OT/control, which increases the consequence of unintended exposure."

        findings.append(
            Finding(
                title="UPnP IGD WAN port mapping observed",
                severity=severity,
                summary=summary,
                confidence=confidence,
                detection_basis="protocol_log",
                devices=devices,
                services=["UPnP IGD"],
                ports=sorted({port for port in (external_port, internal_port) if port is not None}),
                connection_pairs=_mapping_pairs(items),
                flows=[_mapping_flow(item) for item in representative],
                subnets=segments,
                timestamps=[item["timestamp"] for item in representative if item["timestamp"] is not None],
                tags=["upnp", "igd", "port-mapping", "wan-exposure"] + (["ot-exposure"] if ot_target else []),
                metadata={
                    "event_count": len(items),
                    "successful_or_enabled_count": len(active),
                    "failed_count": len(failed),
                    "unknown_result_count": len(unknown),
                    "external_port": external_port,
                    "internal_port": internal_port,
                    "mapping_protocol": protocol,
                    "internal_clients": internal_clients,
                    "gateway_devices": gateways,
                    "ot_control_target": ot_target,
                    "wan_exposure_confirmed": bool(active),
                    "evidence_event_count": len(representative),
                    "evidence_truncated": len(items) > len(representative),
                },
            )
        )
    return findings


def _ssdp_findings(events: list[dict[str, Any]]) -> list[Finding]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        grouped[(event["source"] or "", event["destination"] or "")].append(event)

    findings: list[Finding] = []
    for (source, destination), items in sorted(grouped.items()):
        representative = items[:MAX_EVIDENCE_FLOWS]
        external = any(item["external_destination"] for item in items)
        cross_segment = any(item["cross_segment"] for item in items)
        methods = sorted({item["method"] for item in items if item["method"]})
        targets = sorted({item["target"] for item in items if item["target"]})[:10]
        devices = sorted({value for item in items for value in (item["source"], item["destination"]) if value})
        segment_names = sorted({seg["name"] for item in items for seg in (item["source_segment"], item["destination_segment"]) if seg and seg.get("name")})
        context = "an external/global destination" if external else "a different configured network segment"
        summary = (
            f"Explicit SSDP telemetry shows {len(items)} event(s) from {source or 'an unknown source'} to {destination or 'an unknown destination'} reaching {context} "
            "instead of the normal link-local SSDP multicast destination. SSDP is generally intended for local discovery; routed or externally directed SSDP can expand discovery exposure and should be reviewed against network policy."
        )
        findings.append(
            Finding(
                title="Unexpected SSDP exposure beyond the local discovery scope",
                severity="low",
                summary=summary,
                confidence="high",
                detection_basis="protocol_log",
                devices=devices,
                services=["SSDP"],
                ports=sorted({item["port"] for item in items if item["port"] is not None}),
                connection_pairs=_ssdp_pairs(items),
                flows=[dict(item["row"]) for item in representative],
                subnets=segment_names,
                timestamps=[item["timestamp"] for item in representative if item["timestamp"] is not None],
                tags=["upnp", "ssdp", "discovery", "unexpected-exposure"],
                metadata={
                    "event_count": len(items),
                    "external_destination": external,
                    "cross_segment": cross_segment,
                    "methods": methods,
                    "search_or_notification_targets": targets,
                    "evidence_event_count": len(representative),
                    "evidence_truncated": len(items) > len(representative),
                },
            )
        )
    return findings


def _mapping_description(external_port: int | None, internal_port: int | None, protocol: str | None, clients: list[str]) -> str:
    pieces = []
    if external_port is not None:
        pieces.append(f"WAN port {external_port}")
    if protocol:
        pieces.append(protocol)
    if internal_port is not None:
        pieces.append(f"maps to internal port {internal_port}")
    if clients:
        pieces.append(f"on {', '.join(clients[:3])}")
    if not pieces:
        return "The available telemetry does not include the exact external/internal port tuple."
    return "Observed mapping: " + " ".join(pieces) + "."


def _mapping_pairs(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    pairs = []
    seen = set()
    for item in items:
        source = item["source"]
        gateway = item["gateway"]
        if not source and not gateway:
            continue
        key = (source, gateway)
        if key in seen:
            continue
        seen.add(key)
        pairs.append({
            "source": source or None,
            "destination": gateway or None,
            "port": None,
            "protocol": "tcp",
            "service": "UPnP IGD control",
        })
    return pairs


def _ssdp_pairs(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    pairs = []
    seen = set()
    for item in items:
        key = (item["source"], item["destination"], item["port"])
        if key in seen:
            continue
        seen.add(key)
        pairs.append({
            "source": item["source"] or None,
            "destination": item["destination"] or None,
            "port": item["port"],
            "protocol": "udp",
            "service": "SSDP",
        })
    return pairs


def _mapping_flow(item: dict[str, Any]) -> dict[str, Any]:
    flow = dict(item["row"])
    flow["igd_mapping_assessment"] = "active" if item["mapping_active"] is True else "failed" if item["mapping_active"] is False else "unknown"
    flow["normalized_internal_client"] = item["internal_client"]
    flow["normalized_external_port"] = item["external_port"]
    flow["normalized_internal_port"] = item["internal_port"]
    flow["normalized_mapping_protocol"] = item["protocol"]
    return flow


def _action(row: dict[str, Any]) -> str:
    for field in ACTION_FIELDS:
        value = _text(row.get(field))
        if not value:
            continue
        token = value.split("#")[-1].split("/")[-1].strip().lower()
        compact = token.replace("-", "_").replace(" ", "_")
        if compact in ADD_MAPPING_ACTIONS or compact in DELETE_MAPPING_ACTIONS:
            return compact
        # Common SOAPAction may include quotes or a full URN.
        compact = compact.strip('"\'')
        if compact in ADD_MAPPING_ACTIONS or compact in DELETE_MAPPING_ACTIONS:
            return compact
        if "addportmapping" in token.lower():
            return "addportmapping"
        if "addanyportmapping" in token.lower():
            return "addanyportmapping"
        if "deleteportmapping" in token.lower():
            return "deleteportmapping"
    return ""


def _segments(metadata: dict[str, Any]) -> list[dict[str, Any]]:
    raw = metadata.get("segments") if isinstance(metadata, dict) else None
    if not isinstance(raw, list):
        return []
    result = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            continue
        cidr = next((_text(item.get(key)) for key in CIDR_KEYS if _text(item.get(key))), "")
        if not cidr:
            continue
        try:
            network = ip_network(cidr, strict=False)
        except ValueError:
            continue
        name = next((_text(item.get(key)) for key in NAME_KEYS if _text(item.get(key))), cidr)
        role = next((_text(item.get(key)) for key in ROLE_KEYS if _text(item.get(key))), "")
        result.append({"network": network, "name": name, "role": role, "identity": f"{index}:{network}"})
    return result


def _segment_for_ip(value: str, segments: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not value:
        return None
    try:
        address = ip_address(value)
    except ValueError:
        return None
    matches = [segment for segment in segments if address.version == segment["network"].version and address in segment["network"]]
    return max(matches, key=lambda item: item["network"].prefixlen) if matches else None


def _is_ot_segment(segment: dict[str, Any] | None) -> bool:
    if not segment:
        return False
    token = _norm(segment.get("role"))
    if token in OT_ROLE_TOKENS:
        return True
    name = _norm(segment.get("name"))
    return any(part in name for part in ("ot", "control", "ics", "scada", "industrial"))


def _is_standard_ssdp_destination(destination: str, port: int | None) -> bool:
    if port != 1900 or not destination:
        return False
    token = destination.strip().lower()
    return token in {"239.255.255.250", "ff02::c", "ff05::c"}


def _is_global_ip(value: str) -> bool:
    if not value:
        return False
    try:
        return ip_address(value).is_global
    except ValueError:
        return False


def _first_text(row: dict[str, Any], *fields: str) -> str:
    for field in fields:
        value = _text(row.get(field))
        if value:
            return value
    return ""


def _first_value(row: dict[str, Any], *fields: str) -> Any:
    for field in fields:
        value = row.get(field)
        if value not in (None, ""):
            return value
    return None


def _first_int(row: dict[str, Any], *fields: str) -> int | None:
    for field in fields:
        value = row.get(field)
        if value in (None, ""):
            continue
        try:
            return int(value)
        except (TypeError, ValueError):
            try:
                return int(float(str(value)))
            except (TypeError, ValueError):
                continue
    return None


def _as_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in (0, 1):
        return bool(value)
    token = _norm(value)
    if token in {"true", "t", "yes", "y", "1", "enabled", "on", "success", "succeeded", "ok"}:
        return True
    if token in {"false", "f", "no", "n", "0", "disabled", "off", "failed", "failure", "error"}:
        return False
    return None


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _norm(value: Any) -> str:
    return _text(value).lower().replace("-", "").replace("_", "").replace(" ", "")


def _notes() -> list[str]:
    return [
        "SSDP/UPnP discovery is common on local networks; UDP/1900 presence alone never generates a finding.",
        "IGD port-mapping findings require explicit UPnP protocol telemetry identifying AddPortMapping or AddAnyPortMapping rather than inference from a gateway connection.",
        "A mapping request with unknown result state is reported with Medium confidence; explicit success/enabled or failure fields provide stronger state evidence.",
        "Successful UPnP IGD mappings are treated as WAN-exposure configuration findings, not proof that the mapped service was reachable from the public Internet or maliciously created.",
        "Mappings targeting a configured OT/control segment receive higher severity because automatic inbound exposure can bypass expected network-boundary controls.",
        "Unexpected SSDP exposure is reported only when explicit SSDP telemetry is directed beyond normal local multicast scope to an external/global destination or a different configured segment.",
        "Evidence is capped at 10 representative events while full event counts remain in finding metadata.",
    ]
