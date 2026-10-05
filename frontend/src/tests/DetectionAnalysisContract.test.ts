import { describe, expect, it } from "vitest";
import {
  buildDetectionAnalysisRequest,
  DETECTION_ANALYSIS_CONTRACT_VERSION,
} from "../app/components/DetectionConfiguration/analysisRequest";
import { ALL_DETECTION_MODULES } from "../app/components/DetectionConfiguration/moduleCatalog";
import { createEmptyProfile } from "../app/components/DetectionConfiguration/profile";

describe("Detection Context frontend -> backend contract", () => {
  it("keeps the exact 75-module catalog while sending one versioned profile contract", () => {
    expect(ALL_DETECTION_MODULES).toHaveLength(75);
    const request = buildDetectionAnalysisRequest(createEmptyProfile());
    expect(request.contractVersion).toBe(DETECTION_ANALYSIS_CONTRACT_VERSION);
    expect(request.profile.schemaVersion).toBe(3);
    expect(request.profile.selectedModules).toHaveLength(75);
  });

  it("sends frontend profile fields without compiling backend detector policy namespaces", () => {
    const profile = createEmptyProfile();
    profile.captureScope.internalIcsOnlyExpected = true;
    profile.infrastructure = [
      { id: "dns", kind: "dns", value: "10.0.0.53", source: "user", confidence: "high" },
    ];
    profile.segments = [{
      id: "seg", name: "Control", cidr: "10.10.0.0/16", role: "ot", purdueLevel: "Level 2",
      vlanId: 120, addressing: "static", dhcpAllowed: false, ipv6Allowed: false,
      source: "user", confidence: "high",
    }];

    const request = buildDetectionAnalysisRequest(profile) as any;
    expect(request.profile.captureScope.internalIcsOnlyExpected).toBe(true);
    expect(request.profile.infrastructure[0]).toMatchObject({ kind: "dns", value: "10.0.0.53" });
    expect(request.profile.segments[0]).toMatchObject({ purdueLevel: "Level 2", vlanId: 120, dhcpAllowed: false });

    // These are backend-owned metadata namespaces and must never appear at the request root.
    for (const backendOnlyKey of [
      "public_to_public_policy",
      "ipv6_ot_policy",
      "ot_dns_policy",
      "ics_write_policy",
      "s7comm_control_policy",
      "enip_cip_policy",
      "segments",
      "asset_inventory",
    ]) {
      expect(request[backendOnlyKey]).toBeUndefined();
    }
  });

  it("preserves observations as observations rather than authorization", () => {
    const profile = createEmptyProfile();
    profile.communicationPairs = [{
      id: "observed",
      sourceIp: "10.1.1.10",
      destinationIp: "10.1.1.20",
      protocol: "s7comm",
      destinationPort: 102,
      source: "zeek",
      confidence: "high",
    }];

    const request = buildDetectionAnalysisRequest(profile) as any;
    expect(request.profile.communicationPairs).toHaveLength(1);
    expect(request.profile.authorizedControlActions).toEqual([]);
    expect(request.s7comm_control_policy).toBeUndefined();
    expect(request.ics_write_policy).toBeUndefined();
  });

  it("preserves explicit policy fields for authoritative backend compilation", () => {
    const profile = createEmptyProfile();
    profile.allowedSegmentPairs = [{ id: "pair", sourceSegment: "Enterprise", destinationSegment: "Control" }];
    profile.approvedExternalDestinations = ["198.51.100.0/24"];
    profile.authorizedControlActions = [{
      id: "modbus",
      protocol: "modbus",
      source: "10.0.0.10",
      destination: "10.0.0.20",
      allowedOperations: ["write"],
      allowedFunctionCodes: [5, 6, 16],
    }];

    const request = buildDetectionAnalysisRequest(profile);
    expect(request.profile.allowedSegmentPairs).toEqual(profile.allowedSegmentPairs);
    expect(request.profile.approvedExternalDestinations).toEqual(profile.approvedExternalDestinations);
    expect(request.profile.authorizedControlActions).toEqual(profile.authorizedControlActions);
  });
});
