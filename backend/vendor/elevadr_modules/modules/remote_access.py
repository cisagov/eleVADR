from __future__ import annotations

from collections import defaultdict
from typing import Any

from elevadr_modules.models import AnalysisContext, Finding, ModuleResult
from elevadr_modules.modules.base import AnalysisModule, ModuleMetadata


REMOTE_ACCESS_PORTS: dict[int, tuple[str, str]] = {
    22: ("SSH", "medium"),
    23: ("Telnet", "high"),
    3389: ("RDP", "high"),
    5900: ("VNC", "high"),
    5985: ("WinRM HTTP", "medium"),
    5986: ("WinRM HTTPS", "medium"),
}


class RemoteAccessModule(AnalysisModule):
    metadata = ModuleMetadata(
        id="remote_access",
        name="Remote Access Detection",
        description="Identifies observed remote-access protocols and groups repeated flows into unique connection findings.",
        category="security_analysis",
        required_logs=("conn",),
        default_enabled=True,
    )

    def analyze(self, context: AnalysisContext) -> ModuleResult:
        missing = self.validate_context(context)
        if missing:
            return ModuleResult(
                module_id=self.metadata.id,
                warnings=[f"Missing required Zeek logs: {', '.join(missing)}"],
            )

        grouped: dict[tuple[str, str, int, str], list[dict[str, Any]]] = defaultdict(list)
        for flow in context.connections:
            port = _as_int(flow.get("destination_port"))
            if port not in REMOTE_ACCESS_PORTS:
                continue
            source = str(flow.get("source_ip") or "")
            destination = str(flow.get("destination_ip") or "")
            proto = str(flow.get("protocol") or "").lower()
            if not source or not destination:
                continue
            grouped[(source, destination, port, proto)].append(flow)

        findings: list[Finding] = []
        service_counts: dict[str, int] = defaultdict(int)
        for (source, destination, port, proto), flows in sorted(grouped.items()):
            service, severity = REMOTE_ACCESS_PORTS[port]
            service_counts[service] += len(flows)
            timestamps = [flow["timestamp"] for flow in flows if flow.get("timestamp") not in (None, "")]
            findings.append(
                Finding(
                    title=f"{service} remote-access activity observed",
                    severity=severity,
                    summary=(
                        f"Observed {len(flows)} Zeek connection flow(s) from {source} to "
                        f"{destination} using {service} on port {port}."
                    ),
                    devices=[source, destination],
                    services=[service],
                    ports=[port],
                    connection_pairs=[
                        {
                            "source": source,
                            "destination": destination,
                            "protocol": proto,
                            "service": service,
                            "port": port,
                        }
                    ],
                    flows=flows,
                    timestamps=timestamps,
                    tags=["remote-access"],
                    metadata={"flow_count": len(flows)},
                )
            )

        return ModuleResult(
            module_id=self.metadata.id,
            findings=findings,
            metrics={
                "unique_remote_access_connections": len(grouped),
                "remote_access_flows": sum(len(flows) for flows in grouped.values()),
                "flows_by_service": dict(sorted(service_counts.items())),
            },
            evidence={
                "matched_ports": sorted({key[2] for key in grouped}),
            },
        )


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
