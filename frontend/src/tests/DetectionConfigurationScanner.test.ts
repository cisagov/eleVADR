import { mergeScanIntoProfile, scanZeekFiles } from "../app/components/DetectionConfiguration/zeekScanner";
import { createEmptyProfile } from "../app/components/DetectionConfiguration/profile";

describe("Detection Configuration Zeek scanner", () => {
  it("discovers factual context and adds observed communication to the active profile", async () => {
    const conn = [
      "#separator \\x09",
      "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tvlan\tinner_vlan",
      "1\tC1\t10.10.10.20\t40000\t10.10.10.10\t502\ttcp\tmodbus\t120\t-",
      "2\tC2\t10.10.10.20\t40001\t10.10.10.10\t502\ttcp\tmodbus\t120\t-",
    ].join("\n");
    const dns = [
      "#separator \\x09",
      "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tquery",
      "1\tD1\t10.10.10.20\t53000\t10.10.100.53\t53\tudp\texample.com",
    ].join("\n");

    const dhcp = [
      "#separator \\x09",
      "#fields\tts\tclient_addr\tclient_mac\tserver_addr",
      "1\t10.10.10.10\t00:11:22:33:44:55\t10.10.100.5",
    ].join("\n");

    const result = await scanZeekFiles([
      new File([conn], "conn.log"),
      new File([dns], "dns.log"),
      new File([dhcp], "dhcp.log"),
    ]);

    expect(result.assets.some((asset) => asset.ip === "10.10.10.10" && asset.role === "OT")).toBe(true);
    expect(result.segments.some((segment) => segment.cidr === "10.10.10.0/24" && segment.vlanId === 120)).toBe(true);
    const observedSegment = result.segments.find((segment) => segment.cidr === "10.10.10.0/24");
    expect(observedSegment?.role).toBe("ot");
    expect(observedSegment?.addressing).toBe("dhcp");
    expect(observedSegment?.observedDhcp).toBe(true);
    expect(observedSegment?.observedOtProtocols).toContain("modbus");
    expect(observedSegment?.observedVlanIds).toContain(120);
    expect(observedSegment?.suggestedPurdueLevel).toBe("2");
    expect(result.infrastructure.some((entry) => entry.kind === "dns" && entry.value === "10.10.100.53")).toBe(true);
    expect(result.assets.find((asset) => asset.ip === "10.10.10.10")?.macAddresses).toContain("00:11:22:33:44:55");
    expect(result.pairs.length).toBeGreaterThan(0);
    expect(result.logs.connections).toHaveLength(2);
    expect(result.logs.dns).toHaveLength(1);
    expect(result.logs.dhcp).toHaveLength(1);

    const merged = mergeScanIntoProfile(createEmptyProfile(), result);
    expect(merged.assets.some((asset) => asset.ip === "10.10.10.10")).toBe(true);
    expect(merged.infrastructure.some((entry) => entry.kind === "dns" && entry.value === "10.10.100.53")).toBe(true);
    expect(merged.communicationPairs.length).toBeGreaterThan(0);

    const stale = createEmptyProfile();
    stale.segments = [{
      ...result.segments.find((segment) => segment.cidr === "10.10.10.0/24")!,
      id: "existing-zeek-segment",
      role: "unknown",
      addressing: "unknown",
      vlanId: undefined,
      observedDhcp: undefined,
      observedOtProtocols: [],
      observedVlanIds: [],
      source: "zeek",
    }];
    const refreshed = mergeScanIntoProfile(stale, result).segments[0];
    expect(refreshed.role).toBe("ot");
    expect(refreshed.addressing).toBe("dhcp");
    expect(refreshed.vlanId).toBe(120);
    expect(refreshed.observedOtProtocols).toContain("modbus");
  });
  it("merges protocol-log evidence into existing communication pairs without duplicates", async () => {
    const conn = [
      "#separator \x09",
      "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice",
      "1\tC1\t10.10.0.10\t40001\t10.20.0.30\t80\ttcp\thttp",
    ].join("\n");
    const http = [
      "#separator \x09",
      "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tmethod\thost\turi",
      "1\tC1\t10.10.0.10\t40001\t10.20.0.30\t80\tGET\thmi.local\t/",
    ].join("\n");

    const result = await scanZeekFiles([new File([conn], "conn.log"), new File([http], "http.log")]);
    const observed = result.pairs.filter((pair) => pair.sourceIp === "10.10.0.10" && pair.destinationIp === "10.20.0.30" && pair.destinationPort === 80);
    expect(observed).toHaveLength(1);
    expect(observed[0].protocol).toBe("tcp");
    expect(observed[0].service).toBe("http");

    const profile = createEmptyProfile();
    profile.communicationPairs = [{
      id: "imported-http", sourceIp: "10.10.0.10", destinationIp: "10.20.0.30", protocol: "tcp",
      destinationPort: 80, service: "http", source: "imported", confidence: "high", observedCount: 1,
    }];
    const merged = mergeScanIntoProfile(profile, result);
    const pairs = merged.communicationPairs.filter((pair) => pair.sourceIp === "10.10.0.10" && pair.destinationIp === "10.20.0.30" && pair.destinationPort === 80);
    expect(pairs).toHaveLength(1);
    expect(pairs[0].protocol).toBe("tcp");
    expect(pairs[0].service).toBe("http");
    expect(pairs[0].source).toBe("imported");
    expect(pairs[0].observedCount).toBeGreaterThanOrEqual(2);
  });

  it("repairs stale Zeek duplicate communication rows from older profiles", () => {
    const profile = createEmptyProfile();
    profile.communicationPairs = [
      { id: "imported-http", sourceIp: "10.10.0.10", destinationIp: "10.20.0.30", protocol: "tcp", destinationPort: 80, service: "http", source: "imported", confidence: "high", observedCount: 2 },
      { id: "stale-zeek-http", sourceIp: "10.10.0.10", destinationIp: "10.20.0.30", protocol: "", destinationPort: 80, service: "", source: "zeek", confidence: "low", observedCount: 2 },
      { id: "imported-ntp", sourceIp: "10.10.0.10", destinationIp: "10.10.0.123", protocol: "udp", destinationPort: 123, service: "ntp", source: "imported", confidence: "high", observedCount: 2 },
      { id: "stale-zeek-ntp", sourceIp: "10.10.0.10", destinationIp: "10.10.0.123", protocol: "", destinationPort: 123, service: "", source: "zeek", confidence: "low", observedCount: 2 },
    ];
    const scan = { segments: [], assets: [], infrastructure: [], pairs: [], filesScanned: 1, selectedFileCount: 1, sourceLabel: "capture.pcap", fileNames: ["conn.log"], recordsParsed: 0, logTypes: {}, warnings: [], dhcpAssignmentsObserved: 0, ipv6AddressesObserved: 0, logs: {} };
    const merged = mergeScanIntoProfile(profile, scan);
    expect(merged.communicationPairs).toHaveLength(2);
    const http = merged.communicationPairs.find((pair) => pair.destinationPort === 80);
    expect(http?.id).toBe("imported-http");
    expect(http?.source).toBe("imported");
    expect(http?.protocol).toBe("tcp");
    expect(http?.service).toBe("http");
    const ntp = merged.communicationPairs.find((pair) => pair.destinationPort === 123);
    expect(ntp?.id).toBe("imported-ntp");
    expect(ntp?.protocol).toBe("udp");
    expect(ntp?.service).toBe("ntp");
  });

  it("deduplicates ICMP when imported context omits the synthetic Zeek destination port", () => {
    const profile = createEmptyProfile();
    profile.communicationPairs = [
      { id: "imported-icmp", sourceIp: "10.50.0.25", destinationIp: "8.8.8.8", protocol: "icmp", service: "icmp", source: "imported", confidence: "high" },
      { id: "stale-zeek-icmp", sourceIp: "10.50.0.25", destinationIp: "8.8.8.8", protocol: "icmp", destinationPort: 0, service: "", source: "zeek", confidence: "low", observedCount: 1 },
    ];
    const scan = { segments: [], assets: [], infrastructure: [], pairs: [
      { id: "fresh-zeek-icmp", sourceIp: "10.50.0.25", destinationIp: "8.8.8.8", protocol: "icmp", destinationPort: 0, service: "", source: "zeek", confidence: "low", observedCount: 12 },
    ], filesScanned: 1, selectedFileCount: 1, sourceLabel: "capture.pcap", fileNames: ["conn.log"], recordsParsed: 12, logTypes: { conn: 12 }, warnings: [], dhcpAssignmentsObserved: 0, ipv6AddressesObserved: 0, logs: {} };
    const merged = mergeScanIntoProfile(profile, scan);
    expect(merged.communicationPairs).toHaveLength(1);
    expect(merged.communicationPairs[0].id).toBe("imported-icmp");
    expect(merged.communicationPairs[0].source).toBe("imported");
    expect(merged.communicationPairs[0].protocol).toBe("icmp");
    expect(merged.communicationPairs[0].service).toBe("icmp");
    expect(merged.communicationPairs[0].destinationPort).toBeUndefined();
    expect(merged.communicationPairs[0].observedCount).toBe(12);
  });

  it("does not collapse explicit TCP and UDP communications that share a destination port", () => {
    const profile = createEmptyProfile();
    profile.communicationPairs = [
      { id: "tcp-row", sourceIp: "10.0.0.1", destinationIp: "10.0.0.2", protocol: "tcp", destinationPort: 9999, service: "svc-tcp", source: "user", confidence: "high" },
      { id: "udp-row", sourceIp: "10.0.0.1", destinationIp: "10.0.0.2", protocol: "udp", destinationPort: 9999, service: "svc-udp", source: "user", confidence: "high" },
    ];
    const scan = { segments: [], assets: [], infrastructure: [], pairs: [], filesScanned: 1, selectedFileCount: 1, sourceLabel: "capture.pcap", fileNames: ["conn.log"], recordsParsed: 0, logTypes: {}, warnings: [], dhcpAssignmentsObserved: 0, ipv6AddressesObserved: 0, logs: {} };
    const merged = mergeScanIntoProfile(profile, scan);
    expect(merged.communicationPairs).toHaveLength(2);
    expect(merged.communicationPairs.map((pair) => pair.protocol).sort()).toEqual(["tcp", "udp"]);
  });

});
