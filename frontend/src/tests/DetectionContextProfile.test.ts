import { describe, expect, it } from "vitest";
import { createEmptyProfile, migrateProfile, moduleReadiness } from "../app/components/DetectionConfiguration/profile";
import { validateProfile } from "../app/components/DetectionConfiguration/validation";
import { assetsFromCsv, assetsToCsv, communicationsFromCsv, communicationsToCsv, controlActionsFromCsv, controlActionsToCsv, segmentPairsFromCsv, segmentPairsToCsv } from "../app/components/DetectionConfiguration/csv";
import { mergeScanIntoProfile } from "../app/components/DetectionConfiguration/zeekScanner";

describe("Detection Context profile hardening", () => {
  it("migrates schema v1/v2 profiles to schema v3", () => {
    const legacy = { ...createEmptyProfile(), schemaVersion: 2, captureScope: undefined, authorizedControlActions: undefined } as unknown;
    const result = migrateProfile(legacy);
    expect(result.profile?.schemaVersion).toBe(3);
    expect(result.profile?.captureScope.internalIcsOnlyExpected).toBe(false);
    expect(result.profile?.authorizedControlActions).toEqual([]);
    expect(result.migrated).toBe(true);
  });

  it("detects duplicate and invalid profile fields", () => {
    const profile = createEmptyProfile();
    profile.assets = [
      { id:"a", ip:"10.0.0.1", macAddresses:["00:11:22:33:44:55"], assetType:"Host", role:"Unknown", services:[], ports:[], source:"user", confidence:"high" },
      { id:"b", ip:"10.0.0.1", macAddresses:["not-a-mac"], assetType:"Host", role:"Unknown", services:[], ports:[], source:"user", confidence:"high" },
    ];
    profile.approvedExternalDestinations = ["not a destination!"];
    const issues = validateProfile(profile);
    expect(issues.some((x) => /Duplicate asset/.test(x.message))).toBe(true);
    expect(issues.some((x) => /MAC address/.test(x.message))).toBe(true);
    expect(issues.some((x) => /valid IP address, hostname, or CIDR/.test(x.message))).toBe(true);
  });

  it("round-trips asset, communication, segment-pair, and control-action CSV", () => {
    const profile=createEmptyProfile();
    profile.assets=[{id:"a",ip:"10.0.0.1",hostname:"plc-1",macAddresses:["00:11:22:33:44:55"],assetType:"PLC",role:"OT",services:["modbus"],ports:[502],source:"user",confidence:"high"}];
    profile.communicationPairs=[{id:"p",sourceIp:"10.0.0.2",destinationIp:"10.0.0.1",protocol:"tcp",destinationPort:502,service:"modbus",source:"user",confidence:"high"}];
    profile.allowedSegmentPairs=[{id:"s",sourceSegment:"Engineering",destinationSegment:"Control",description:"Expected"}];
    profile.authorizedControlActions=[{id:"c",protocol:"modbus",source:"10.0.0.2",destination:"10.0.0.1",allowedOperations:["write"],allowedFunctionCodes:[5,6,16]}];
    expect(assetsFromCsv(assetsToCsv(profile.assets))[0].macAddresses[0]).toBe("00:11:22:33:44:55");
    expect(communicationsFromCsv(communicationsToCsv(profile.communicationPairs))[0].destinationPort).toBe(502);
    expect(segmentPairsFromCsv(segmentPairsToCsv(profile.allowedSegmentPairs))[0].destinationSegment).toBe("Control");
    expect(controlActionsFromCsv(controlActionsToCsv(profile.authorizedControlActions))[0].allowedFunctionCodes).toContain(16);
  });

  it("preserves user-edited values when rescanning an existing key while merging MAC evidence", () => {
    const profile=createEmptyProfile();
    profile.assets=[{id:"a",ip:"10.0.0.1",hostname:"PLC-A",macAddresses:[],assetType:"PLC",role:"Controller",services:[],ports:[],source:"user",confidence:"high"}];
    const merged=mergeScanIntoProfile(profile,{segments:[],assets:[{id:"z",ip:"10.0.0.1",hostname:"",macAddresses:["00:11:22:33:44:55"],assetType:"OT/ICS candidate",role:"OT",services:["modbus"],ports:[502],source:"zeek",confidence:"medium",observedCount:3}],infrastructure:[],pairs:[],filesScanned:1,selectedFileCount:1,sourceLabel:"logs",fileNames:["conn.log"],recordsParsed:3,logTypes:{conn:3},warnings:[]});
    expect(merged.assets[0].hostname).toBe("PLC-A");
    expect(merged.assets[0].role).toBe("Controller");
    expect(merged.assets[0].services).toContain("modbus");
    expect(merged.assets[0].macAddresses).toContain("00:11:22:33:44:55");
  });

  it("requires explicit capture scope for public-to-public readiness", () => {
    const profile=createEmptyProfile();
    profile.segments=[{id:"s",name:"OT",cidr:"10.0.0.0/24",role:"ot",addressing:"static",source:"user",confidence:"high"}];
    const before=moduleReadiness(profile).find((x)=>x.id==="public_to_public_traffic");
    expect(before?.level).toBe("warning");
    expect(before?.canRun).toBe(true);
    expect(before?.contextComplete).toBe(false);
    profile.captureScope.internalIcsOnlyExpected=true;
    const after=moduleReadiness(profile).find((x)=>x.id==="public_to_public_traffic");
    expect(after?.level).toBe("ready");
    expect(after?.canRun).toBe(true);
    expect(after?.contextComplete).toBe(true);
  });
});
