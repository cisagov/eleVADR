from __future__ import annotations

from collections import defaultdict
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata

MAX_EVIDENCE_ROWS = 50
STANDARD_IRC_PORTS = {6667, 6697}
IRC_SERVICE_TOKENS = {"irc", "ircs", "irc-ssl", "irc_ssl"}


class IrcTrafficDetectedModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="irc_traffic_detected",
        name="IRC Traffic Detected",
        description=(
            "Identifies Internet Relay Chat traffic on standard IRC ports or on non-standard ports when Zeek explicitly identifies the service as IRC."
        ),
        category="security_analysis",
        required_logs=("conn",),
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        policy = _policy(context.metadata)
        standard_ports = _int_set(policy.get("standard_ports")) or set(STANDARD_IRC_PORTS)
        allowed_hosts = _string_set(policy.get("allowed_hosts"))
        allowed_pairs = _pair_set(policy.get("allowed_pairs"))

        groups: dict[tuple[str, str, int | None, str], list[dict[str, Any]]] = defaultdict(list)
        candidates = 0
        standard_port_candidates = 0
        explicit_service_candidates = 0
        nonstandard_explicit_candidates = 0
        skipped_allowlisted = 0

        for row in context.connections:
            src = _text(_first(row, "source_ip", "id.orig_h"))
            dst = _text(_first(row, "destination_ip", "id.resp_h"))
            if not src or not dst:
                continue
            if src in allowed_hosts or dst in allowed_hosts or (src, dst) in allowed_pairs:
                skipped_allowlisted += 1
                continue
            proto = _text(_first(row, "protocol", "proto")).lower()
            port = _as_int(_first(row, "destination_port", "id.resp_p"))
            service_tokens = _service_tokens(_text(row.get("service")))
            explicit = bool(service_tokens & IRC_SERVICE_TOKENS)
            standard = proto == "tcp" and port in standard_ports
            if not (standard or explicit):
                continue
            candidates += 1
            if standard:
                standard_port_candidates += 1
            if explicit:
                explicit_service_candidates += 1
            if explicit and not standard:
                nonstandard_explicit_candidates += 1
            basis = "zeek_service" if explicit else "port"
            groups[(src, dst, port, basis)].append(row)

        findings = [_finding(rows, key) for key, rows in sorted(groups.items())]
        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "irc_candidates": candidates,
                "standard_port_candidates": standard_port_candidates,
                "explicit_service_candidates": explicit_service_candidates,
                "nonstandard_explicit_candidates": nonstandard_explicit_candidates,
                "irc_findings": len(findings),
                "skipped_allowlisted": skipped_allowlisted,
            },
            evidence={
                "inspected_logs": ["conn"],
                "standard_ports": sorted(standard_ports),
                "policy": policy,
                "notes": [
                    "TCP/6667 and TCP/6697 are treated as standard IRC indicators.",
                    "A non-standard destination port is only reported when Zeek explicitly labels the service as IRC/IRCS.",
                    "Port-only matches are service-consistent evidence, not payload confirmation of IRC.",
                ],
            },
            warnings=[],
        )


def _finding(rows: list[dict[str, Any]], key: tuple[str, str, int | None, str]) -> Finding:
    src, dst, port, basis = key
    explicit = basis == "zeek_service"
    services: set[str] = set()
    timestamps: list[Any] = []
    pairs: list[dict[str, Any]] = []
    for row in rows:
        services.update(_service_tokens(_text(row.get("service"))))
        ts = _first(row, "timestamp", "ts")
        if ts not in (None, ""):
            timestamps.append(ts)
        if len(pairs) < MAX_EVIDENCE_ROWS:
            pairs.append({"source": src, "destination": dst, "protocol": _text(_first(row, "protocol", "proto")).lower(), "destination_port": port})

    if explicit and port not in STANDARD_IRC_PORTS:
        title = "IRC traffic detected on non-standard port"
        summary = f"Observed {len(rows)} connection(s) from {src} to {dst} where Zeek explicitly identified IRC service traffic on non-standard port {port}."
        severity = "medium"
    elif explicit:
        title = "IRC traffic detected"
        summary = f"Observed {len(rows)} connection(s) from {src} to {dst} with explicit IRC service identification on port {port}."
        severity = "medium"
    else:
        title = "Traffic observed on standard IRC port"
        summary = f"Observed {len(rows)} TCP connection(s) from {src} to {dst} on standard IRC port {port}. Validate whether IRC use is expected."
        severity = "low"

    return Finding(
        title=title,
        severity=severity,
        summary=summary,
        confidence="high" if explicit else "medium",
        detection_basis=basis,
        devices=sorted({src, dst}),
        services=sorted(s for s in services if s and s != "-"),
        ports=[port] if port is not None else [],
        connection_pairs=pairs,
        timestamps=timestamps[:MAX_EVIDENCE_ROWS],
        tags=["irc", "chat"] + (["non-standard-port"] if explicit and port not in STANDARD_IRC_PORTS else []),
        metadata={"flow_count": len(rows), "source": src, "destination": dst, "destination_port": port},
    )


def _policy(metadata: dict[str, Any]) -> dict[str, Any]:
    value = metadata.get("irc_traffic_policy", {}) if isinstance(metadata, dict) else {}
    return value if isinstance(value, dict) else {}


def _first(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in row and row[key] not in (None, "", "-"):
            return row[key]
    return None


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _service_tokens(value: str) -> set[str]:
    if not value or value == "-":
        return set()
    return {token.strip().lower() for token in value.replace(",", " ").split() if token.strip()}


def _string_set(value: Any) -> set[str]:
    if not isinstance(value, (list, tuple, set)):
        return set()
    return {_text(v) for v in value if _text(v)}


def _int_set(value: Any) -> set[int]:
    if not isinstance(value, (list, tuple, set)):
        return set()
    out: set[int] = set()
    for item in value:
        iv = _as_int(item)
        if iv is not None:
            out.add(iv)
    return out


def _pair_set(value: Any) -> set[tuple[str, str]]:
    out: set[tuple[str, str]] = set()
    if not isinstance(value, list):
        return out
    for item in value:
        if isinstance(item, dict):
            src = _text(item.get("source"))
            dst = _text(item.get("destination"))
            if src and dst:
                out.add((src, dst))
    return out
