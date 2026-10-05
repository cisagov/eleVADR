from __future__ import annotations

from collections import defaultdict
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata

MAX_EVIDENCE_FLOWS = 10
SMB_LOGS = ("smb_mapping", "smb_files", "smb_cmd", "smb")
ADMIN_SHARES = {"ADMIN$", "IPC$"}
SHARE_FIELDS = (
    "share",
    "share_name",
    "share_path",
    "path",
    "tree",
    "tree_name",
    "tree_path",
    "service",
    "resource",
    "resource_name",
    "filename",
    "name",
)
USER_FIELDS = (
    "username",
    "user",
    "account",
    "account_name",
    "client_user",
    "principal",
)


class SmbAdminShareAccessModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="smb_admin_share_access",
        name="SMB Admin-Share Access (IPC$/ADMIN$)",
        description=(
            "Identifies explicit SMB access to IPC$ or ADMIN$ and highlights repeated or multi-target patterns "
            "that can be consistent with remote administration or lateral movement."
        ),
        category="security_analysis",
        required_logs=(),
        required_any_logs=(),
        default_enabled=True,
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        conn_by_uid = {
            str(row.get("uid")): row
            for row in context.connections
            if row.get("uid") not in (None, "")
        }

        events: list[dict[str, Any]] = []
        for log_name in SMB_LOGS:
            for row in context.log(log_name):
                share = _extract_admin_share(row)
                if not share:
                    continue
                events.append(_event(row, log_name, share, conn_by_uid))

        findings = _build_findings(events)
        inspected = [name for name in SMB_LOGS if context.log(name)]
        skipped = [name for name in SMB_LOGS if not context.log(name)]

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "smb_admin_share_findings": len(findings),
                "admin_share_events": len(events),
                "admin_share_events_by_share": {
                    share: sum(1 for event in events if event["share"] == share)
                    for share in sorted(ADMIN_SHARES)
                },
                "distinct_sources": len({event["source"] for event in events if event["source"]}),
                "distinct_destinations": len({event["destination"] for event in events if event["destination"]}),
            },
            evidence={
                "inspected_logs": inspected,
                "skipped_optional_logs": skipped,
                "notes": [
                    "The detector requires explicit SMB protocol-log evidence that IPC$ or ADMIN$ was accessed; TCP/445 alone is never sufficient.",
                    "IPC$ is widely used for legitimate RPC, named-pipe, domain, and administration activity, so isolated IPC$ access remains low severity.",
                    "ADMIN$ is an administrative share and is more security-relevant, but its use can still be legitimate by management, backup, deployment, or support tooling.",
                    "Multi-target access from one source is highlighted as a lateral-movement-like pattern, but the module does not claim compromise without corroborating evidence.",
                    "Evidence is capped at 10 representative SMB events while full event and target counts remain in finding metadata.",
                ],
            },
            warnings=[],
        )


def _extract_admin_share(row: dict[str, Any]) -> str | None:
    for field in SHARE_FIELDS:
        value = row.get(field)
        if value in (None, ""):
            continue
        text = str(value).replace("/", "\\").upper()
        # Match standalone share names and UNC/path components, but do not
        # accept prefixes such as IPC$OLD.
        components = [part for part in text.split("\\") if part]
        for component in components:
            cleaned = component.strip().rstrip(":")
            if cleaned in ADMIN_SHARES:
                return cleaned
        cleaned = text.strip().rstrip(":")
        if cleaned in ADMIN_SHARES:
            return cleaned
    return None


def _event(
    row: dict[str, Any],
    log_name: str,
    share: str,
    conn_by_uid: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    uid = _text(row.get("uid"))
    conn = conn_by_uid.get(uid, {}) if uid else {}
    source = _first_text(row, "source_ip", "id.orig_h") or _first_text(conn, "source_ip", "id.orig_h")
    destination = _first_text(row, "destination_ip", "id.resp_h") or _first_text(conn, "destination_ip", "id.resp_h")
    port = _as_int(_first_value(row, "destination_port", "id.resp_p"))
    if port is None:
        port = _as_int(_first_value(conn, "destination_port", "id.resp_p"))
    timestamp = _first_value(row, "timestamp", "ts")
    if timestamp is None:
        timestamp = _first_value(conn, "timestamp", "ts")
    protocol = _first_text(row, "protocol", "proto") or _first_text(conn, "protocol", "proto") or "tcp"
    username = _first_text(row, *USER_FIELDS)
    if not username:
        username = _first_text(conn, *USER_FIELDS)
    return {
        "share": share,
        "source": source,
        "destination": destination,
        "port": port,
        "timestamp": timestamp,
        "protocol": protocol,
        "username": username,
        "uid": uid,
        "log_name": log_name,
        "row": row,
        "connection": conn or None,
    }


def _build_findings(events: list[dict[str, Any]]) -> list[Finding]:
    # Group by source and share so a single finding can expose fan-out to
    # multiple remote systems, which is more useful for lateral-movement review.
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        grouped[(event["source"], event["share"])].append(event)

    findings: list[Finding] = []
    for (source, share), items in sorted(grouped.items()):
        destinations = sorted({item["destination"] for item in items if item["destination"]})
        usernames = sorted({item["username"] for item in items if item["username"]})
        target_count = len(destinations)
        event_count = len(items)

        if share == "ADMIN$":
            severity = "high" if target_count >= 5 else "medium"
            title = (
                f"SMB ADMIN$ access from {source} to {target_count} hosts"
                if source and target_count > 1
                else "SMB ADMIN$ administrative-share access observed"
            )
            summary = (
                f"SMB protocol logs show {event_count} access event(s) to the ADMIN$ administrative share"
                + (f" from {source}" if source else "")
                + (f" across {target_count} destination hosts" if target_count > 1 else "")
                + ". ADMIN$ is commonly used by legitimate remote-management and software-deployment tools, but it is also frequently used during remote execution and lateral movement. Correlate with the initiating account, host role, process telemetry, and change/administration activity before treating the pattern as malicious."
            )
        else:
            severity = "medium" if target_count >= 5 else "low"
            title = (
                f"SMB IPC$ access from {source} to {target_count} hosts"
                if source and target_count > 1
                else "SMB IPC$ access observed"
            )
            summary = (
                f"SMB protocol logs show {event_count} access event(s) to IPC$"
                + (f" from {source}" if source else "")
                + (f" across {target_count} destination hosts" if target_count > 1 else "")
                + ". IPC$ is routinely used for legitimate SMB/RPC and named-pipe activity, so isolated access is not itself suspicious. Broad multi-target IPC$ use can nevertheless be consistent with remote administration, discovery, or lateral-movement workflows and should be correlated with surrounding authentication and execution evidence."
            )

        representative = items[:MAX_EVIDENCE_FLOWS]
        devices = sorted({value for item in items for value in (item["source"], item["destination"]) if value})
        ports = sorted({item["port"] for item in items if item["port"] is not None})
        pairs = _pairs(items)
        timestamps = [item["timestamp"] for item in representative if item["timestamp"] is not None]
        flows = [_flow(item) for item in representative]

        tags = ["smb", "admin-share", "lateral-movement-review", share.lower().replace("$", "_share")]
        if target_count >= 5:
            tags.append("multi-target")

        findings.append(
            Finding(
                title=title,
                severity=severity,
                summary=summary,
                confidence="high",
                detection_basis="protocol_log",
                devices=devices,
                services=[f"SMB {share}"],
                ports=ports,
                connection_pairs=pairs,
                flows=flows,
                subnets=[],
                timestamps=timestamps,
                tags=tags,
                metadata={
                    "share": share,
                    "source": source or None,
                    "event_count": event_count,
                    "target_count": target_count,
                    "destinations": destinations,
                    "usernames": usernames,
                    "evidence_event_count": len(representative),
                    "evidence_truncated": event_count > len(representative),
                    "lateral_movement_confirmed": False,
                },
            )
        )
    return findings


def _pairs(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[Any, ...]] = set()
    pairs: list[dict[str, Any]] = []
    for item in items:
        if not item["source"] or not item["destination"]:
            continue
        key = (item["source"], item["destination"], item["port"], item["protocol"])
        if key in seen:
            continue
        seen.add(key)
        pairs.append(
            {
                "source": item["source"],
                "destination": item["destination"],
                "port": item["port"],
                "protocol": item["protocol"],
                "service": f"SMB {item['share']}",
            }
        )
        if len(pairs) >= MAX_EVIDENCE_FLOWS:
            break
    return pairs


def _flow(item: dict[str, Any]) -> dict[str, Any]:
    row = dict(item["row"])
    row.setdefault("share", item["share"])
    if item["username"]:
        row.setdefault("username", item["username"])
    if item["source"]:
        row.setdefault("source_ip", item["source"])
    if item["destination"]:
        row.setdefault("destination_ip", item["destination"])
    if item["port"] is not None:
        row.setdefault("destination_port", item["port"])
    return row


def _first_value(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = row.get(key)
        if value not in (None, ""):
            return value
    return None


def _first_text(row: dict[str, Any], *keys: str) -> str:
    value = _first_value(row, *keys)
    return _text(value)


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _as_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
