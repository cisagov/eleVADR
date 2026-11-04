from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import ipaddress
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata


DEFAULT_RUNTIME_TCP_PORTS = {11740, 11741, 11742, 11743}
DEFAULT_RUNTIME_UDP_PORTS = {1740, 1741, 1742, 1743}
DEFAULT_GATEWAY_TCP_PORTS = {1217}
CODESYS_RUNTIME_SERVICE_TOKENS = {
    "codesys",
    "codesys3",
    "codesys_v3",
    "codesys-runtime",
    "codesys_runtime",
}
CODESYS_GATEWAY_SERVICE_TOKENS = {"codesys-gateway", "codesys_gateway"}
OT_ROLE_TOKENS = {"ot", "control", "ics", "scada", "operations", "industrial", "process", "plc"}
MAX_EVIDENCE_FLOWS = 25


@dataclass(slots=True)
class _Segment:
    cidr: str
    name: str
    role: str
    network: ipaddress._BaseNetwork


class CodesysRuntimeExposureModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="codesys_runtime_exposure",
        name="CoDeSys Runtime Exposure",
        description=(
            "Identifies CODESYS programming/runtime and gateway communications using vendor-documented default "
            "ports or explicit service labels, with higher severity when runtime access reaches configured OT "
            "controllers from public or non-OT sources."
        ),
        category="security_analysis",
        required_logs=("conn",),
        default_enabled=True,
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        policy = _policy(context.metadata)
        runtime_tcp_ports = DEFAULT_RUNTIME_TCP_PORTS | _port_set(policy.get("additional_runtime_tcp_ports"))
        runtime_udp_ports = DEFAULT_RUNTIME_UDP_PORTS | _port_set(policy.get("additional_runtime_udp_ports"))
        gateway_tcp_ports = _port_set(policy.get("gateway_tcp_ports", sorted(DEFAULT_GATEWAY_TCP_PORTS)))
        report_gateway = _as_bool(policy.get("report_gateway", True), True)

        allowed_hosts = {_text(value) for value in policy.get("allowed_hosts", []) if _text(value)}
        allowed_pairs = _pair_set(policy.get("allowed_pairs", []))
        expected_engineering_hosts = {
            _text(value) for value in policy.get("expected_engineering_hosts", []) if _text(value)
        }
        expected_runtime_hosts = {
            _text(value) for value in policy.get("expected_runtime_hosts", []) if _text(value)
        }
        segments = _load_segments(context.metadata)

        groups: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
        skipped_allowlisted = 0
        skipped_non_codesys = 0

        for row in context.connections:
            protocol = _text(row.get("protocol", row.get("proto"))).lower()
            port = _as_int(row.get("destination_port", row.get("id.resp_p")))
            source = _text(row.get("source_ip", row.get("id.orig_h")))
            destination = _text(row.get("destination_ip", row.get("id.resp_h")))
            service_tokens = _service_tokens(row.get("service"))

            component = ""
            evidence_class = ""
            detection_basis = ""

            if service_tokens & CODESYS_RUNTIME_SERVICE_TOKENS:
                component = "runtime"
                evidence_class = "explicit_runtime_service"
                detection_basis = "zeek_service"
            elif service_tokens & CODESYS_GATEWAY_SERVICE_TOKENS:
                component = "gateway"
                evidence_class = "explicit_gateway_service"
                detection_basis = "zeek_service"
            elif protocol == "tcp" and port in runtime_tcp_ports:
                component = "runtime"
                if _tcp_established(row):
                    evidence_class = "established_runtime_tcp"
                    detection_basis = "port"
                else:
                    evidence_class = "runtime_tcp_attempt"
                    detection_basis = "port"
            elif protocol == "udp" and port in runtime_udp_ports:
                component = "runtime"
                evidence_class = "runtime_udp"
                detection_basis = "port"
            elif report_gateway and protocol == "tcp" and port in gateway_tcp_ports:
                component = "gateway"
                evidence_class = "gateway_tcp"
                detection_basis = "port"
            else:
                skipped_non_codesys += 1
                continue

            if component == "gateway" and not report_gateway:
                continue
            if source in allowed_hosts or destination in allowed_hosts or (source, destination) in allowed_pairs:
                skipped_allowlisted += 1
                continue

            scope = _exposure_scope(source, destination, segments)
            expectation = _expectation(source, destination, expected_engineering_hosts, expected_runtime_hosts)
            groups[(component, evidence_class, scope + ":" + expectation)].append(row)

        findings: list[Finding] = []
        for (component, evidence_class, scope_expectation), rows in sorted(groups.items()):
            scope, expectation = scope_expectation.split(":", 1)
            findings.append(
                _finding(
                    component=component,
                    evidence_class=evidence_class,
                    scope=scope,
                    expectation=expectation,
                    rows=rows,
                    runtime_tcp_ports=runtime_tcp_ports,
                    runtime_udp_ports=runtime_udp_ports,
                    gateway_tcp_ports=gateway_tcp_ports,
                )
            )

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "codesys_findings": len(findings),
                "runtime_flows": sum(len(rows) for (component, _, _), rows in groups.items() if component == "runtime"),
                "gateway_flows": sum(len(rows) for (component, _, _), rows in groups.items() if component == "gateway"),
                "skipped_allowlisted": skipped_allowlisted,
                "skipped_non_codesys": skipped_non_codesys,
            },
            evidence={
                "inspected_logs": ["conn"],
                "runtime_tcp_ports": sorted(runtime_tcp_ports),
                "runtime_udp_ports": sorted(runtime_udp_ports),
                "gateway_tcp_ports": sorted(gateway_tcp_ports),
                "segments_loaded": len(segments),
                "policy": policy,
                "notes": [
                    "CODESYS V3 runtime programming/client communication commonly uses TCP 11740-11743 and UDP 1740-1743; deployments can reconfigure TCP runtime ports.",
                    "TCP/1217 is a CODESYS Gateway service and is reported separately from the controller runtime.",
                    "conn.log can show communication to a programming/runtime service but does not establish whether authentication was required, bypassed, or successful.",
                    "Port-only detections identify traffic consistent with CODESYS. Explicit service identification is higher-confidence evidence when available.",
                    "Public-to-OT runtime access is treated as higher risk than internal or expected engineering access.",
                ],
            },
            warnings=[],
        )


def _finding(
    *,
    component: str,
    evidence_class: str,
    scope: str,
    expectation: str,
    rows: list[dict[str, Any]],
    runtime_tcp_ports: set[int],
    runtime_udp_ports: set[int],
    gateway_tcp_ports: set[int],
) -> Finding:
    devices: set[str] = set()
    services: set[str] = set()
    ports: set[int] = set()
    timestamps: list[Any] = []
    flows = rows[:MAX_EVIDENCE_FLOWS]
    connection_pairs: list[dict[str, Any]] = []
    seen_pairs: set[tuple[str, str, int | None, str]] = set()

    for row in rows:
        source = _text(row.get("source_ip", row.get("id.orig_h")))
        destination = _text(row.get("destination_ip", row.get("id.resp_h")))
        protocol = _text(row.get("protocol", row.get("proto"))).lower()
        port = _as_int(row.get("destination_port", row.get("id.resp_p")))
        if source:
            devices.add(source)
        if destination:
            devices.add(destination)
        services.update(_service_tokens(row.get("service")))
        if port is not None:
            ports.add(port)
        ts = row.get("timestamp", row.get("ts"))
        if ts not in (None, ""):
            timestamps.append(ts)
        pair = (source, destination, port, protocol)
        if pair not in seen_pairs and len(connection_pairs) < MAX_EVIDENCE_FLOWS:
            seen_pairs.add(pair)
            connection_pairs.append(
                {"source": source, "destination": destination, "port": port, "protocol": protocol}
            )

    if evidence_class.startswith("explicit_"):
        confidence = "high"
        detection_basis = "zeek_service"
    elif evidence_class == "established_runtime_tcp":
        confidence = "medium"
        detection_basis = "port"
    elif evidence_class in {"runtime_udp", "gateway_tcp"}:
        confidence = "medium"
        detection_basis = "port"
    else:
        confidence = "low"
        detection_basis = "port"

    if component == "runtime":
        if scope == "public_to_ot":
            severity = "high"
        elif scope == "cross_role_to_ot":
            severity = "medium"
        elif expectation == "expected_pair":
            severity = "low"
        else:
            severity = "medium" if evidence_class.startswith("explicit_") else "low"

        title = "CODESYS runtime programming service exposure observed"
        if scope == "public_to_ot":
            title = "CODESYS runtime exposed to public-source access"
        elif scope == "cross_role_to_ot":
            title = "CODESYS runtime accessed across OT boundary"

        summary = (
            f"Observed {len(rows)} flow(s) consistent with the CODESYS controller runtime programming/client interface. "
            f"Evidence class is {evidence_class.replace('_', ' ')}; exposure scope is {scope.replace('_', ' ')}. "
            "This indicates reachability/use of a remote programming interface, not proof that authentication was absent or bypassed."
        )
        tags = ["ot", "codesys", "plc-runtime", "remote-programming", "exposure"]
    else:
        severity = "low"
        title = "CODESYS Gateway service traffic observed"
        summary = (
            f"Observed {len(rows)} flow(s) consistent with the CODESYS Gateway service. TCP/1217 is used between "
            "CODESYS clients and the Gateway; it is not itself proof that a PLC runtime is directly exposed."
        )
        tags = ["ot", "codesys", "gateway", "engineering-access"]

    return Finding(
        title=title,
        severity=severity,
        summary=summary,
        confidence=confidence,
        detection_basis=detection_basis,
        devices=sorted(devices),
        services=sorted(services),
        ports=sorted(ports),
        connection_pairs=connection_pairs,
        flows=flows,
        timestamps=timestamps[:MAX_EVIDENCE_FLOWS],
        tags=tags,
        metadata={
            "protocol": "codesys",
            "component": component,
            "evidence_class": evidence_class,
            "exposure_scope": scope,
            "expectation": expectation,
            "flow_count": len(rows),
            "runtime_tcp_ports": sorted(runtime_tcp_ports),
            "runtime_udp_ports": sorted(runtime_udp_ports),
            "gateway_tcp_ports": sorted(gateway_tcp_ports),
            "evidence_truncated": len(rows) > len(flows),
        },
    )


def _policy(metadata: dict[str, Any]) -> dict[str, Any]:
    value = metadata.get("codesys_runtime_policy", {}) if isinstance(metadata, dict) else {}
    return value if isinstance(value, dict) else {}


def _load_segments(metadata: dict[str, Any]) -> list[_Segment]:
    raw = metadata.get("segments") if isinstance(metadata, dict) else None
    if not isinstance(raw, list):
        return []
    segments: list[_Segment] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        cidr = _text(item.get("cidr") or item.get("subnet"))
        if not cidr:
            continue
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        segments.append(
            _Segment(
                cidr=str(network),
                name=_text(item.get("name")) or str(network),
                role=_text(item.get("role")).lower(),
                network=network,
            )
        )
    return segments


def _segment_for_ip(value: str, segments: list[_Segment]) -> _Segment | None:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    for segment in segments:
        if address in segment.network:
            return segment
    return None


def _exposure_scope(source: str, destination: str, segments: list[_Segment]) -> str:
    dst_segment = _segment_for_ip(destination, segments)
    src_segment = _segment_for_ip(source, segments)
    dst_is_ot = bool(dst_segment and _is_ot_role(dst_segment.role))

    if dst_is_ot and _is_global_ip(source):
        return "public_to_ot"
    if dst_is_ot and src_segment and not _is_ot_role(src_segment.role):
        return "cross_role_to_ot"
    if dst_is_ot:
        return "internal_to_ot"
    if _is_global_ip(source):
        return "public_source"
    return "unscoped_internal"


def _expectation(
    source: str,
    destination: str,
    engineering_hosts: set[str],
    runtime_hosts: set[str],
) -> str:
    if source in engineering_hosts and destination in runtime_hosts:
        return "expected_pair"
    if source in engineering_hosts:
        return "expected_engineering_source"
    if destination in runtime_hosts:
        return "expected_runtime_destination"
    return "unclassified"


def _is_ot_role(role: str) -> bool:
    tokens = {token for token in role.replace("/", " ").replace("-", " ").split() if token}
    return bool(tokens & OT_ROLE_TOKENS)


def _is_global_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def _tcp_established(row: dict[str, Any]) -> bool:
    state = _text(row.get("conn_state")).upper()
    # Zeek states SF and S1 indicate that both endpoints exchanged traffic.
    return state in {"SF", "S1", "S2", "S3"}


def _service_tokens(value: Any) -> set[str]:
    text = _text(value).lower()
    if not text:
        return set()
    for separator in (",", ";", "|"):
        text = text.replace(separator, " ")
    return {token.strip() for token in text.split() if token.strip()}


def _pair_set(value: Any) -> set[tuple[str, str]]:
    if not isinstance(value, list):
        return set()
    pairs: set[tuple[str, str]] = set()
    for item in value:
        if not isinstance(item, dict):
            continue
        source = _text(item.get("source"))
        destination = _text(item.get("destination"))
        if source and destination:
            pairs.add((source, destination))
    return pairs


def _port_set(value: Any) -> set[int]:
    if not isinstance(value, (list, tuple, set)):
        return set()
    ports: set[int] = set()
    for item in value:
        port = _as_int(item)
        if port is not None and 0 < port <= 65535:
            ports.add(port)
    return ports


def _as_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes", "1", "on"}:
            return True
        if lowered in {"false", "no", "0", "off"}:
            return False
    return default


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
