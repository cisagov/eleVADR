import React from "react";
import { fireEvent, render, screen } from "@testing-library/react";
import "@testing-library/jest-dom";
import { describe, expect, it, vi } from "vitest";
import EntityDrawer from "../app/components/EntityDrawer/EntityDrawer";
import FindingsPanel, { deriveFindings } from "../app/components/FindingsPanel/FindingsPanel";
import { ElevadrReport } from "../app/types/Report";
import { createMockReport } from "./reportFactory";

function explainabilityReport(): ElevadrReport {
  const base = createMockReport();
  return {
    ...base,
    arch_insights: {
      detection_context_snapshot: {
        name: "Regression Explainability Context",
        captureScope: {
          internalIcsOnlyExpected: true,
          dedicatedOtSensor: true,
          ipv4OnlyExpected: false,
        },
        assets: [
          {
            id: "observed-rogue",
            ip: "10.30.0.99",
            role: "OT",
            segment: "Cell A",
            source: "zeek",
            confidence: "medium",
          },
        ],
        communicationPairs: [],
        approvedExternalDestinations: [],
        authorizedControlActions: [],
      },
      detector_findings: [
        {
          module_id: "unknown_rogue_devices",
          severity: "high",
          title: "Unknown device observed in OT segment",
          summary: "10.30.0.99 was observed but is not present in the authoritative inventory.",
          confidence: "high",
          detection_basis: "asset inventory comparison",
          devices: ["10.30.0.99"],
          services: ["modbus"],
          connection_pairs: [
            {
              source: "10.30.0.99",
              destination: "10.30.0.10",
              port: 502,
              protocol: "modbus",
            },
          ],
          flows: [{ uid: "rogue-1" }],
          provenance: {
            schema_version: 1,
            resolution: "representative_flow",
            sources: [
              {
                log_type: "conn.log",
                record_index: 12,
                fields: {
                  "id.orig_h": "10.30.0.99",
                  "id.resp_h": "10.30.0.10",
                  "id.resp_p": 502,
                  service: "modbus",
                },
              },
            ],
          },
          tags: ["inventory", "ot"],
        },
      ],
    },
    modules: {
      ...base.modules,
      service_risk_breakdown_panel: {
        risk_category_counts: {},
        risk_category_services: {},
      },
      suspicious_outbound_connections_panel: [],
      ot_cross_segment_lines_panel: {
        lines: [],
        subnet_pair_counts: [],
        dst_subnet_counts: [],
        ot_device_counts: [],
      },
      connection_success_panel: {
        ...base.modules.connection_success_panel,
        connections: [
          {
            "src_endpoint.ip": "10.30.0.99",
            "dst_endpoint.ip": "10.30.0.10",
            "dst_endpoint.port": 502,
            "service.name": "modbus",
            "connection_info.protocol_name": "tcp",
            state: "SF",
            success: true,
          },
        ],
      },
    },
  };
}

describe("findings explainability UX", () => {
  it("keeps observed evidence separate from authoritative Detection Context policy", () => {
    const [finding] = deriveFindings(explainabilityReport());

    expect(finding.title).toBe("Unknown device observed in OT segment");
    expect(finding.confidence).toBe("high");
    expect(finding.detectionBasis).toBe("asset inventory comparison");
    expect(finding.observedEvidence).toContain("10.30.0.99 → 10.30.0.10:502 (modbus)");
    expect(finding.provenanceEvidence?.[0]).toContain("conn.log record 12");
    expect(finding.provenanceEvidence?.[0]).toContain("id.orig_h=10.30.0.99");
    expect(finding.contextEvidence).toContain("Profile: Regression Explainability Context");
    expect(finding.contextEvidence).toContain("10.30.0.99: observed-only, role OT, segment Cell A");
    expect(finding.suppressionGuidance?.join(" ")).toMatch(/Zeek-discovered asset alone must remain observed-only/i);
  });

  it("renders the five explainability sections and the evidence/policy separation warning", () => {
    const report = explainabilityReport();
    const onClose = vi.fn();

    render(
      <EntityDrawer
        report={report}
        entity={{ type: "finding", id: "detector:unknown_rogue_devices:0" }}
        filters={[]}
        onClose={onClose}
        onFilter={vi.fn()}
      />,
    );

    expect(screen.getByText("Why was this flagged?")).toBeInTheDocument();
    expect(screen.getByText("What was observed")).toBeInTheDocument();
    expect(screen.getByText("What rule evaluated it")).toBeInTheDocument();
    expect(screen.getByText("What context affected the decision")).toBeInTheDocument();
    expect(screen.getByText("Why the result became a finding")).toBeInTheDocument();
    expect(screen.getByText(/Observed traffic is evidence, not authorization/i)).toBeInTheDocument();
    expect(screen.getByText("Observed evidence")).toBeInTheDocument();
    expect(screen.getByText("Zeek provenance")).toBeInTheDocument();
    expect(screen.getByText(/conn\.log record 12/)).toBeInTheDocument();
    expect(screen.getByText("Detection Context / policy")).toBeInTheDocument();
    expect(screen.getByText("Detector inference")).toBeInTheDocument();
    expect(screen.getByText("Legitimate context changes")).toBeInTheDocument();
    expect(screen.getByText("Recommended response")).toBeInTheDocument();
    expect(screen.getByText(/A Zeek observation does not itself create an allowlist/i)).toBeInTheDocument();
    expect(screen.getByText("asset inventory comparison")).toBeInTheDocument();
    expect(screen.getByText("high", { selector: ".finding-confidence" })).toBeInTheDocument();

    fireEvent.click(screen.getAllByRole("button", { name: "Close details" })[0]);
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("degrades gracefully when an older detector finding lacks explainability metadata", () => {
    const base = createMockReport();
    const report: ElevadrReport = {
      ...base,
      arch_insights: {
        detector_findings: [
          {
            module_id: "legacy_detector",
            severity: "medium",
            title: "Legacy detector finding",
            summary: "Older report without confidence or Detection Context snapshot.",
          },
        ],
      },
      modules: {
        ...base.modules,
        service_risk_breakdown_panel: { risk_category_counts: {}, risk_category_services: {} },
        suspicious_outbound_connections_panel: [],
        ot_cross_segment_lines_panel: { lines: [], subnet_pair_counts: [], dst_subnet_counts: [], ot_device_counts: [] },
      },
    };

    render(
      <EntityDrawer
        report={report}
        entity={{ type: "finding", id: "detector:legacy_detector:0" }}
        filters={[]}
        onClose={vi.fn()}
        onFilter={vi.fn()}
      />,
    );

    expect(screen.getByText("unspecified", { selector: ".finding-confidence" })).toBeInTheDocument();
    expect(screen.getByText("derived", { selector: ".finding-explain-grid strong" })).toBeInTheDocument();
    expect(screen.getByText("No Detection Context snapshot is embedded in this report.")).toBeInTheDocument();
    expect(screen.getByText(/did not retain flow-level evidence/i)).toBeInTheDocument();
  });

  it("surfaces confidence and detection basis in the findings table and preserves selection behavior", () => {
    const onSelect = vi.fn();

    render(
      <FindingsPanel
        report={explainabilityReport()}
        filters={[]}
        onFilter={vi.fn()}
        onSelect={onSelect}
      />,
    );

    expect(screen.getByText("asset inventory comparison")).toBeInTheDocument();
    expect(screen.getByText("high confidence")).toBeInTheDocument();

    expect(screen.getByRole("button", { name: "Why flagged?" })).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Why flagged?" }));
    expect(onSelect).toHaveBeenCalledWith({ type: "finding", id: "detector:unknown_rogue_devices:0" });
  });
});
