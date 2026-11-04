from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "frontend" / "src" / "tests" / "fixtures" / "topology_dense_report.json"


def device(ip: str, subnet: str, service: str, is_ot: bool = False, is_edge: bool = False) -> dict:
    return {
        "manufacturer": "Regression Labs",
        "mac": None,
        "ip_addresses": [ip],
        "ipv4_ips": [ip],
        "ipv6_ips": [],
        "subnets": [subnet],
        "ipv4_subnets": [subnet],
        "ipv6_subnets": [],
        "incoming_services": [service],
        "sent_services": [],
        "is_ot": is_ot,
        "is_edge": is_edge,
    }


def build() -> dict:
    it_devices, edge_devices, ot_devices = [], [], []
    all_devices: list[tuple[str, str, str, str, str]] = []

    for i in range(1, 33):
        ip = f"10.10.0.{i}"
        all_devices.append((ip, "10.10.0.0/24", "http", "IT", "5"))
        it_devices.append(device(ip, "10.10.0.0/24", "http"))
    for i in range(1, 9):
        ip = f"10.20.0.{i}"
        all_devices.append((ip, "10.20.0.0/24", "dns", "Network", "3.5"))
        edge_devices.append(device(ip, "10.20.0.0/24", "dns", is_edge=True))
    for i in range(1, 57):
        third = 30 if i <= 28 else 31
        host = i if i <= 28 else i - 28
        ip = f"10.{third}.0.{host}"
        subnet = f"10.{third}.0.0/24"
        service = "modbus" if i % 2 else "s7comm"
        purdue = "2" if i <= 28 else "1"
        all_devices.append((ip, subnet, service, "OT", purdue))
        ot_devices.append(device(ip, subnet, service, is_ot=True))

    connections = []
    services = ["http", "dns", "modbus", "s7comm", "ntp", "ssh"]
    n = len(all_devices)
    for i in range(180):
        src = all_devices[i % n][0]
        dst = all_devices[(i * 7 + 11) % n][0]
        if src == dst:
            dst = all_devices[(i * 7 + 12) % n][0]
        service = services[i % len(services)]
        port = {"http": 80, "dns": 53, "modbus": 502, "s7comm": 102, "ntp": 123, "ssh": 22}[service]
        connections.append({
            "src_endpoint.ip": src,
            "src_endpoint.port": 40000 + (i % 1000),
            "dst_endpoint.ip": dst,
            "dst_endpoint.port": port,
            "service.name": service,
            "connection_info.protocol_name": "udp" if service in {"dns", "ntp"} else "tcp",
            "connection_info.direction_name": None,
            "duration": 0.1,
            "orig_bytes": 120 + i,
            "resp_bytes": 80 + i,
            "state": "SF",
            "history": "ShADadFf",
            "success": True,
        })

    suspicious = []
    for i in range(8):
        row = connections[20 + i * 9]
        suspicious.append({
            "src_endpoint.ip": row["src_endpoint.ip"],
            "dst_endpoint.ip": row["dst_endpoint.ip"],
            "dst_endpoint.port": row["dst_endpoint.port"],
            "service.name": row["service.name"],
            "count": 2 + i,
        })

    findings = []
    for i in range(12):
        row = connections[5 + i * 11]
        findings.append({
            "module_id": "topology_dense_regression",
            "severity": "medium" if i % 3 else "high",
            "title": f"Dense topology regression finding {i + 1}",
            "summary": "Synthetic finding used only for topology interaction regression.",
            "confidence": "high",
            "detection_basis": "synthetic regression fixture",
            "devices": [row["src_endpoint.ip"], row["dst_endpoint.ip"]],
            "services": [row["service.name"]],
            "connection_pairs": [{
                "source": row["src_endpoint.ip"],
                "destination": row["dst_endpoint.ip"],
                "port": row["dst_endpoint.port"],
                "protocol": row["service.name"],
            }],
            "flows": [],
            "tags": ["regression", "topology"],
        })

    assets = []
    for ip, subnet, _service, role, purdue in all_devices:
        assets.append({
            "id": f"asset-{ip.replace('.', '-')}",
            "ip": ip,
            "role": role,
            "segment": subnet,
            "purdueLevel": purdue,
            "source": "regression",
            "confidence": "high",
        })

    report = {
        "report_version": "2.0.0",
        "report_id": "topology-dense-regression",
        "executive_summary": {
            "analysis_summary": "Synthetic dense topology interaction regression fixture.",
            "device_summary": f"Observed {n} synthetic devices.",
            "service_summary": "Observed six synthetic services.",
        },
        "modules": {
            "service_panel": {"num_known_services": 6, "num_ot_services": 2, "num_risky_services": 2, "num_unknown_services": 0},
            "device_panel": {"hosts": n, "ot_hosts": len(ot_devices), "it_hosts": len(it_devices), "edge_hosts": len(edge_devices), "ot_cross_segment": 0},
            "service_risk_breakdown_panel": {"risk_category_counts": {}, "risk_category_services": {}},
            "service_count_panel": {"service_count": 6, "service_connections_count": {"known_services": [], "unknown_services": {}}},
            "connection_success_panel": {"summary": {"successful_count": len(connections), "unsuccessful_count": 0, "by_state": {"SF": len(connections)}}, "connections": connections},
            "suspicious_outbound_connections_panel": suspicious,
            "ot_cross_segment_lines_panel": {"lines": [], "subnet_pair_counts": [], "dst_subnet_counts": [], "ot_device_counts": []},
            "ot_devices": ot_devices,
            "it_devices": it_devices,
            "edge_devices": edge_devices,
        },
        "arch_insights": {
            "detection_context_snapshot": {
                "name": "Dense topology regression context",
                "assets": assets,
                "segments": [
                    {"id": "it", "name": "IT", "cidr": "10.10.0.0/24", "role": "IT", "purdueLevel": "5"},
                    {"id": "edge", "name": "Edge", "cidr": "10.20.0.0/24", "role": "Network", "purdueLevel": "3.5"},
                    {"id": "ot-a", "name": "OT A", "cidr": "10.30.0.0/24", "role": "OT", "purdueLevel": "2"},
                    {"id": "ot-b", "name": "OT B", "cidr": "10.31.0.0/24", "role": "OT", "purdueLevel": "1"},
                ],
            },
            "detector_findings": findings,
        },
        "section_notes": {},
    }
    return report


def main() -> None:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(build(), indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {OUTPUT}")


if __name__ == "__main__":
    main()
