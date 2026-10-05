import { describe, expect, it } from "vitest";
import { contextTabForModule, findingEvidenceSummary, findingHosts, formatModuleTitle, highestSeverity } from "../app/components/DetectionConfiguration/analysisPresentation";

describe("analysis result presentation", () => {
  it("uses analyst-friendly detector labels while retaining stable module ids elsewhere", () => {
    expect(formatModuleTitle("protocol_unexpected_high_risk_port")).toBe("Unexpected High-Risk Port");
    expect(formatModuleTitle("netbios_smbv1_exposure")).toBe("NetBIOS / SMBv1 Exposure");
    expect(formatModuleTitle("ot_external_dns_resolver")).toBe("External DNS Resolver Used by OT");
  });

  it("sorts module severity by the most important finding", () => {
    expect(highestSeverity([
      { title: "a", severity: "low", summary: "", confidence: "high", detection_basis: "derived" },
      { title: "b", severity: "critical", summary: "", confidence: "high", detection_basis: "derived" },
    ])).toBe("critical");
  });

  it("extracts hosts and compact evidence from detector findings", () => {
    const finding = {
      title: "Unexpected SMB",
      severity: "high",
      summary: "test",
      confidence: "high",
      detection_basis: "port",
      devices: ["10.0.0.5"],
      services: ["smb"],
      ports: [445],
      connection_pairs: [{ source: "10.0.0.5", destination: "10.0.0.20" }],
    };
    expect(findingHosts(finding)).toEqual(["10.0.0.5", "10.0.0.20"]);
    expect(findingEvidenceSummary(finding).join(" ")).toContain("10.0.0.5");
    expect(findingEvidenceSummary(finding).join(" ")).toContain("445");
  });

  it("links detector families to the relevant Detection Context area", () => {
    expect(contextTabForModule("unknown_rogue_devices")).toBe("assets");
    expect(contextTabForModule("s7comm_unauthorized_write_stop")).toBe("controlActions");
    expect(contextTabForModule("ot_external_dns_resolver")).toBe("infrastructure");
  });
});
