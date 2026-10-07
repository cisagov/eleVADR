import { describe, expect, it } from "vitest";
import { normalizeElevadrReport } from "../app/utils/reportCompatibility";

describe("report compatibility normalization", () => {
  it("normalizes legacy v1 reports without inventing findings or devices", () => {
    const result = normalizeElevadrReport({
      report_version: "1.3.0",
      report_id: "legacy-1",
      executive_summary: { summary: "old report" },
      modules: {
        service_panel: { num_known_services: 2, num_ot_services: 1 },
        device_panel: { hosts: 1, ot_hosts: 1 },
      },
    });
    expect(result.migrated).toBe(true);
    expect(result.report.report_version).toBe("2.0.0");
    expect(result.report.modules.service_panel.num_known_services).toBe(2);
    expect(result.report.modules.ot_devices).toEqual([]);
    expect(result.report.modules.suspicious_outbound_connections_panel).toEqual(
      [],
    );
  });

  it("accepts legacy camelCase aliases and fills only structural defaults", () => {
    const result = normalizeElevadrReport({
      reportId: "legacy-camel",
      executiveSummary: { summary: "camel" },
      modules: {
        devicePanel: { hosts: 1, otHosts: 1 },
        otDevices: [
          {
            manufacturer: null,
            ip_addresses: ["10.0.0.10"],
            subnets: [],
            incoming_services: [],
            sent_services: [],
          },
        ],
      },
    });
    expect(result.sourceVersion).toBe("legacy-unversioned");
    expect(result.report.report_id).toBe("legacy-camel");
    expect(result.report.modules.device_panel.ot_hosts).toBe(1);
    expect(result.report.modules.ot_devices).toHaveLength(1);
  });

  it("rejects unsupported future major versions rather than guessing", () => {
    expect(() =>
      normalizeElevadrReport({
        report_version: "3.0.0",
        modules: {},
        executive_summary: {},
      }),
    ).toThrow(/Unsupported eleVADR report version/);
  });
});
