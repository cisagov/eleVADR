import { describe, expect, it } from "vitest";
import { deriveFindings } from "../app/components/FindingsPanel/FindingsPanel";
import { createMockReport } from "./reportFactory";

describe("PCAP-generated canonical report", () => {
  it("surfaces backend detector findings through the normal report findings view", () => {
    const report = createMockReport({
      arch_insights: {
        detector_findings: [
          {
            module_id: "unknown_rogue_devices",
            title: "Unknown device observed",
            severity: "high",
            summary: "10.0.0.99 is not in inventory",
            confidence: "high",
            detection_basis: "derived",
            devices: ["10.0.0.99"],
            services: [],
            connection_pairs: [],
          },
        ],
      },
      modules: {
        ...createMockReport().modules,
        service_risk_breakdown_panel: { risk_category_counts: {}, risk_category_services: {} },
        suspicious_outbound_connections_panel: [],
        ot_cross_segment_lines_panel: { lines: [], subnet_pair_counts: [], dst_subnet_counts: [], ot_device_counts: [] },
      },
    });
    const findings = deriveFindings(report);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      title: "Unknown device observed",
      severity: "high",
      ip: "10.0.0.99",
      moduleId: "unknown_rogue_devices",
      confidence: "high",
      detectionBasis: "derived",
    });
    expect(findings[0].observedEvidence?.join(" ")).toContain("10.0.0.99");
    expect(findings[0].suppressionGuidance?.join(" ")).toContain("authoritative asset inventory");
  });
});
