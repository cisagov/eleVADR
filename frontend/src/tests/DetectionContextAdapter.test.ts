import { describe, expect, it } from "vitest";
import {
  compileDetectionContextMetadata,
  MODULE_POLICY_NAMESPACE,
} from "../app/components/DetectionConfiguration/analysisContextAdapter";
import { ALL_DETECTION_MODULES } from "../app/components/DetectionConfiguration/moduleCatalog";
import { createEmptyProfile } from "../app/components/DetectionConfiguration/profile";

type TestRecord = Record<string, unknown>;

function record(value: unknown): TestRecord {
  expect(value).toBeTruthy();
  expect(typeof value).toBe("object");
  expect(Array.isArray(value)).toBe(false);
  return value as TestRecord;
}

function records(value: unknown): TestRecord[] {
  expect(Array.isArray(value)).toBe(true);
  return value as TestRecord[];
}

function compileTestMetadata(
  profile: Parameters<typeof compileDetectionContextMetadata>[0],
): TestRecord {
  return compileDetectionContextMetadata(profile);
}

const ALL_60 = [...ALL_DETECTION_MODULES];

describe("Detection Context -> AnalysisContext.metadata adapter", () => {
  it("tracks the exact 75-module registry contract", () => {
    expect(ALL_60).toHaveLength(75);
    expect(new Set(ALL_60).size).toBe(75);
  });

  it("compiles shared segment and asset aliases to detector shapes", () => {
    const p = createEmptyProfile();
    p.segments = [
      {
        id: "s",
        name: "Control",
        cidr: "10.10.0.0/16",
        role: "ot",
        purdueLevel: "2",
        vlanId: 120,
        addressing: "static",
        dhcpAllowed: false,
        ipv6Allowed: false,
        observedDhcp: true,
        observedOtProtocols: ["modbus"],
        observedVlanIds: [120],
        source: "zeek",
        confidence: "high",
      },
    ];
    p.assets = [
      {
        id: "a",
        ip: "10.10.1.5",
        hostname: "PLC-1",
        macAddresses: ["00:11:22:33:44:55"],
        assetType: "PLC",
        role: "OT",
        segment: "Control",
        purdueLevel: "1",
        services: ["modbus"],
        ports: [502],
        source: "user",
        confidence: "high",
      },
    ];
    const m = compileTestMetadata(p);
    expect(records(m.segments)[0]).toMatchObject({
      purdue_level: "2",
      vlan_id: 120,
      dhcp_allowed: false,
      ipv6_allowed: false,
      ipv4_only: true,
    });
    expect(records(m.segments)[0].observedOtProtocols).toBeUndefined();
    expect(records(m.asset_inventory)[0]).toMatchObject({
      ip: "10.10.1.5",
      asset_type: "PLC",
      purdue_level: "1",
    });
    expect(records(m.asset_inventory)[0].macs).toContain("00:11:22:33:44:55");
    expect(
      records(record(m.detection_context_observations).segments)[0]
        .ot_protocols_observed,
    ).toContain("modbus");
  });

  it("maps capture scope and trusted infrastructure only to deliberate policy blocks", () => {
    const p = createEmptyProfile();
    p.captureScope = {
      internalIcsOnlyExpected: true,
      dedicatedOtSensor: true,
      ipv4OnlyExpected: true,
    };
    p.infrastructure = [
      {
        id: "d",
        kind: "dns",
        value: "10.0.0.53",
        source: "user",
        confidence: "high",
      },
      {
        id: "n",
        kind: "ntp",
        value: "10.0.0.123",
        source: "user",
        confidence: "high",
      },
      {
        id: "h",
        kind: "dhcp",
        value: "10.0.0.5",
        source: "user",
        confidence: "high",
      },
      {
        id: "m",
        kind: "management",
        value: "10.0.0.20",
        source: "user",
        confidence: "high",
      },
    ];
    const m = compileTestMetadata(p);
    expect(record(m.public_to_public_policy).internal_ics_only_expected).toBe(
      true,
    );
    expect(m.ipv6_ot_policy).toMatchObject({
      ipv4_only_expected: true,
      scope_all_connections: true,
    });
    expect(record(m.ot_dns_policy).trusted_resolvers).toEqual(["10.0.0.53"]);
    expect(record(m.ntp_ot_policy).trusted_servers).toEqual(["10.0.0.123"]);
    expect(record(m.dhcp_ot_policy).expected_servers).toEqual(["10.0.0.5"]);
    expect(record(m.ot_certificate_policy).management_hosts).toEqual([
      "10.0.0.20",
    ]);
  });

  it("does not turn observed Communications into authorization or allowed-pair policy", () => {
    const p = createEmptyProfile();
    p.communicationPairs = [
      {
        id: "c",
        sourceIp: "10.1.1.10",
        destinationIp: "10.1.1.20",
        protocol: "s7comm",
        destinationPort: 102,
        source: "zeek",
        confidence: "high",
      },
    ];
    const m = compileTestMetadata(p);
    expect(m.s7comm_control_policy).toBeUndefined();
    expect(m.ics_write_policy).toBeUndefined();
    expect(m.enip_cip_policy).toBeUndefined();
    expect(m.control_system_enterprise_policy).toBeUndefined();
    expect(
      records(record(m.detection_context_observations).communications)[0],
    ).toMatchObject({
      source: "10.1.1.10",
      destination: "10.1.1.20",
    });
  });

  it("maps explicit segment exceptions and external destinations only to consumers", () => {
    const p = createEmptyProfile();
    p.allowedSegmentPairs = [
      { id: "x", sourceSegment: "Enterprise", destinationSegment: "Control" },
    ];
    p.approvedExternalDestinations = ["198.51.100.0/24"];
    const m = compileTestMetadata(p);
    for (const key of [
      "control_system_enterprise_policy",
      "database_exposure_policy",
      "netbios_smbv1_policy",
    ]) {
      expect(record(m[key]).allowed_segment_pairs).toEqual([
        { source: "Enterprise", destination: "Control" },
      ]);
    }
    expect(
      record(m.ot_outbound_internet_policy).allowed_external_destinations,
    ).toEqual(["198.51.100.0/24"]);
    expect(
      record(m.internet_exposed_ics_policy).allowed_external_destinations,
    ).toEqual(["198.51.100.0/24"]);
    expect(
      record(m.file_transfer_policy).approved_external_destinations,
    ).toEqual(["198.51.100.0/24"]);
  });

  it("compiles protocol-specific Authorized Control Actions to exact detector fields", () => {
    const p = createEmptyProfile();
    p.authorizedControlActions = [
      {
        id: "m",
        protocol: "modbus",
        source: "10.0.0.10",
        destination: "10.0.0.20",
        allowedOperations: ["write"],
        allowedFunctionCodes: [5, 6, 16],
      },
      {
        id: "s",
        protocol: "s7comm",
        source: "10.0.0.11",
        destination: "10.0.0.21",
        allowedOperations: ["write", "stop"],
        allowedFunctionCodes: ["0x05"],
      },
      {
        id: "e",
        protocol: "enip",
        source: "10.0.0.12",
        destination: "10.0.0.22",
        allowedOperations: ["write"],
        allowedFunctionCodes: [16],
      },
    ];
    const m = compileTestMetadata(p);
    expect(records(record(m.ics_write_policy).allowed_paths)[0]).toMatchObject({
      protocol: "modbus",
      source: "10.0.0.10",
      destination: "10.0.0.20",
      allowed_function_codes: [5, 6, 16],
    });
    expect(
      records(record(m.s7comm_control_policy).allowed_paths)[0],
    ).toMatchObject({
      source: "10.0.0.11",
      destination: "10.0.0.21",
      allowed_operations: ["write", "stop"],
    });
    expect(
      records(record(m.enip_cip_policy).allowed_write_paths)[0],
    ).toMatchObject({
      source: "10.0.0.12",
      destination: "10.0.0.22",
      allowed_service_codes: [16],
    });
    expect(record(m.plc_program_firmware_policy).allowed_pairs).toHaveLength(3);
  });

  it("routes Advanced Module Overrides to detector namespaces and lets explicit overrides win", () => {
    const p = createEmptyProfile();
    p.captureScope.internalIcsOnlyExpected = true;
    p.modulePolicies.public_to_public_traffic = {
      internal_ics_only_expected: false,
      min_flows: 3,
    };
    p.modulePolicies.control_system_enterprise_non_dmz = {
      require_observed_communication: false,
    };
    const m = compileTestMetadata(p);
    expect(m.public_to_public_policy).toMatchObject({
      internal_ics_only_expected: false,
      min_flows: 3,
    });
    expect(
      record(m.control_system_enterprise_policy).require_observed_communication,
    ).toBe(false);
  });

  it.each(ALL_60)("has a stable adapter contract for module %s", (moduleId) => {
    const p = createEmptyProfile();
    p.selectedModules = [moduleId];
    p.modulePolicies[moduleId] = { contract_probe: true };
    const m = compileTestMetadata(p);
    expect(Array.isArray(m.segments)).toBe(true);
    expect(Array.isArray(m.asset_inventory)).toBe(true);
    const namespace =
      MODULE_POLICY_NAMESPACE[moduleId as keyof typeof MODULE_POLICY_NAMESPACE];
    if (namespace) expect(record(m[namespace]).contract_probe).toBe(true);
  });
});
