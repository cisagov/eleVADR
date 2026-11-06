import { ElevadrReport } from "../app/types/Report";

export function createMockReport(
  overrides: Partial<ElevadrReport> = {},
): ElevadrReport {
  return {
    report_version: "2.0.0",
    report_id: "report-123",
    executive_summary: {
      risky_services_alert: "Detected <strong>risky</strong> services.",
    },
    arch_insights: {},
    modules: {
      service_panel: {
        num_known_services: 2,
        num_ot_services: 1,
        num_risky_services: 1,
        num_unknown_services: 1,
      },
      device_panel: {
        hosts: 3,
        ot_hosts: 1,
        it_hosts: 1,
        edge_hosts: 1,
        ot_cross_segment: 1,
      },
      service_risk_breakdown_panel: {
        risk_category_counts: {
          insecure_protocol: 1,
        },
        risk_category_services: {
          insecure_protocol: ["telnet"],
        },
      },
      service_count_panel: {
        service_count: 3,
        service_connections_count: {
          known_services: [
            { name: "http", port: 80, count: 12 },
            { name: "modbus", port: 502, count: 4 },
          ],
          unknown_services: {
            unknown_1337: 2,
          },
        },
      },
      connection_success_panel: {
        summary: {
          successful_count: 10,
          unsuccessful_count: 2,
          by_state: {
            SF: 10,
            REJ: 2,
          },
        },
        connections: [],
      },
      suspicious_outbound_connections_panel: [
        {
          "src_endpoint.ip": "10.0.0.10",
          "dst_endpoint.ip": "8.8.8.8",
          "dst_endpoint.port": 53,
          "service.name": "dns",
          count: 3,
        },
      ],
      ot_cross_segment_lines_panel: {
        lines: [],
        subnet_pair_counts: [],
        dst_subnet_counts: [],
        ot_device_counts: [],
      },
      ot_devices: [],
      it_devices: [],
      edge_devices: [],
      ot_services: [
        {
          "service.name": "modbus",
          "service.description": "Industrial protocol",
          "service.information_categories": "control",
          "service.risk_categories": "insecure_protocol",
        },
      ],
    },
    ...overrides,
  };
}
