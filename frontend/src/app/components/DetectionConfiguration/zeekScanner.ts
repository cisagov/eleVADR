import { AssetRecord, CommunicationPair, DetectionConfigurationProfile, InfrastructureEntry, NetworkSegment } from "./types";

interface ParsedLog { type: string; rows: Record<string, unknown>[]; warning?: string; }

const ANALYSIS_LOG_TYPES = new Set([
  "conn", "connections", "dns", "http", "quic", "socks", "ftp", "tftp", "smtp", "telnet", "login",
  "ssl", "x509", "ssh", "kerberos", "ntlm", "ldap", "ldap_bind", "ldap_search", "smb", "smb_mapping",
  "smb_files", "smb_cmd", "rdp", "ssdp", "upnp", "upnp_igd", "vnc", "modbus", "dnp3", "enip", "bacnet",
  "s7comm", "mms", "iec61850", "dhcp", "ntp", "snmp", "arp", "files", "weird",
]);

function analysisLogName(type: string): string | undefined {
  const normalized = type.toLowerCase();
  if (!ANALYSIS_LOG_TYPES.has(normalized)) return undefined;
  return normalized === "conn" ? "connections" : normalized;
}
interface HostEvidence { ip: string; services: Set<string>; ports: Set<number>; macs: Set<string>; otScore: number; count: number; }

const OT_PORTS: Record<number, string> = {
  102: "s7comm", 502: "modbus", 1911: "niagara-fox", 2222: "enip", 44818: "enip/cip",
  47808: "bacnet", 20000: "dnp3", 11740: "codesys", 11741: "codesys", 11742: "codesys", 11743: "codesys",
};
const OT_TOKENS = /\b(modbus|s7|s7comm|dnp3|bacnet|enip|cip|ethernet\/ip|fox|niagara|codesys|iccp|tase2|snmp)\b/i;
const OT_LOG_SERVICES: Record<string, string> = {
  s7comm: "s7comm",
  modbus: "modbus",
  dnp3: "dnp3",
  enip: "enip/cip",
  cip: "enip/cip",
  bacnet: "bacnet",
  snmp: "snmp",
  mms: "iccp/tase2",
  tftp: "tftp",
};

function serviceFromLogType(type: string): string {
  const normalized = type.toLowerCase();
  for (const [token, service] of Object.entries(OT_LOG_SERVICES)) {
    if (normalized === token || normalized.startsWith(`${token}_`) || normalized.includes(token)) return service;
  }
  return "";
}

function text(value: unknown): string { return value == null ? "" : String(value).trim(); }
function numberValue(value: unknown): number | undefined { const valueNumber = Number(value); return Number.isFinite(valueNumber) ? valueNumber : undefined; }
function first(row: Record<string, unknown>, ...keys: string[]): unknown { for (const key of keys) if (row[key] !== undefined && row[key] !== null && row[key] !== "-") return row[key]; return undefined; }
function isIpv4(value: string): boolean { return /^(\d{1,3}\.){3}\d{1,3}$/.test(value); }
function isIpv6(value: string): boolean { return value.includes(":") && /^[0-9a-f:.%]+$/i.test(value); }
function isPrivateIpv4(value: string): boolean {
  if (!isIpv4(value)) return false;
  const [a, b] = value.split(".").map(Number);
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}
function slash24(ip: string): string | undefined { if (!isPrivateIpv4(ip)) return undefined; const parts = ip.split("."); return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`; }
function logType(file: File): string {
  const name = file.name.toLowerCase().replace(/\.jsonl?$|\.log$/g, "");
  return name.replace(/[^a-z0-9_]+/g, "_");
}
function decodeSeparator(value: string): string { return value.replace(/\\x09/gi, "\t").replace(/\\x20/gi, " "); }

function parseZeekTsv(contents: string, type: string): ParsedLog {
  const lines = contents.split(/\r?\n/);
  let separator = "\t";
  let fields: string[] = [];
  const rows: Record<string, unknown>[] = [];
  for (const line of lines) {
    if (!line) continue;
    if (line.startsWith("#separator ")) { separator = decodeSeparator(line.slice("#separator ".length)); continue; }
    if (line.startsWith("#fields")) { fields = line.split(separator).slice(1); continue; }
    if (line.startsWith("#")) continue;
    if (!fields.length) continue;
    const values = line.split(separator);
    const row: Record<string, unknown> = {};
    fields.forEach((field, index) => { row[field] = values[index]; });
    rows.push(row);
  }
  return { type, rows, warning: fields.length ? undefined : `${type}: no Zeek #fields header found.` };
}

function parseJsonLines(contents: string, type: string): ParsedLog {
  const trimmed = contents.trim();
  if (!trimmed) return { type, rows: [] };
  try {
    const parsed = JSON.parse(trimmed) as unknown;
    if (Array.isArray(parsed)) return { type, rows: parsed.filter((item): item is Record<string, unknown> => Boolean(item) && typeof item === "object") };
    if (parsed && typeof parsed === "object") return { type, rows: [parsed as Record<string, unknown>] };
  } catch { /* fall through to JSONL */ }
  const rows: Record<string, unknown>[] = [];
  for (const line of contents.split(/\r?\n/)) {
    if (!line.trim()) continue;
    try { const value = JSON.parse(line); if (value && typeof value === "object") rows.push(value); } catch { /* ignore bad line */ }
  }
  return { type, rows, warning: rows.length ? undefined : `${type}: JSON content could not be parsed.` };
}

async function parseFile(file: File): Promise<ParsedLog> {
  const contents = await file.text();
  const type = logType(file);
  const firstNonWhitespace = contents.trimStart()[0];
  if (file.name.toLowerCase().endsWith(".json") || firstNonWhitespace === "{" || firstNonWhitespace === "[") return parseJsonLines(contents, type);
  return parseZeekTsv(contents, type);
}

function normalizeMac(value: unknown): string | undefined {
  const compact = text(value).toLowerCase().replace(/[^0-9a-f]/g, "");
  if (!/^[0-9a-f]{12}$/.test(compact)) return undefined;
  return compact.match(/.{2}/g)?.join(":");
}

function upsertHost(hosts: Map<string, HostEvidence>, ip: string, service = "", port?: number, weight = 0, mac?: string): void {
  if (!ip) return;
  const current = hosts.get(ip) || { ip, services: new Set<string>(), ports: new Set<number>(), macs: new Set<string>(), otScore: 0, count: 0 };
  if (service && service !== "-") current.services.add(service);
  if (port !== undefined) current.ports.add(port);
  if (mac) current.macs.add(mac);
  current.otScore += weight;
  current.count += 1;
  hosts.set(ip, current);
}

function mergeUnique<T extends { id: string }>(existing: T[], incoming: T[], key: (item: T) => string): T[] {
  const result = [...existing];
  const seen = new Set(existing.map(key));
  incoming.forEach((item) => { if (!seen.has(key(item))) { result.push(item); seen.add(key(item)); } });
  return result;
}

export interface ZeekScanResult {
  segments: NetworkSegment[];
  assets: AssetRecord[];
  infrastructure: InfrastructureEntry[];
  pairs: CommunicationPair[];
  filesScanned: number;
  selectedFileCount: number;
  sourceLabel: string;
  fileNames: string[];
  recordsParsed: number;
  logTypes: Record<string, number>;
  warnings: string[];
  dhcpAssignmentsObserved: number;
  ipv6AddressesObserved: number;
  /** Parsed Zeek rows ready for the analysis API. Kept separate from profile policy. */
  logs: Record<string, Array<Record<string, unknown>>>;
}

export async function scanZeekFiles(files: FileList | File[]): Promise<ZeekScanResult> {
  const selected = Array.from(files);
  const candidates = selected.filter((file) => /\.(log|json|jsonl)$/i.test(file.name));
  const relativePaths = selected.map((file) => (file as File & { webkitRelativePath?: string }).webkitRelativePath || file.name);
  const roots = relativePaths.map((path) => path.split("/")[0]).filter(Boolean);
  const sourceLabel = roots.length && roots.every((root) => root === roots[0]) ? roots[0] : "Selected Zeek logs";
  const fileNames = candidates.slice(0, 100).map((file) => (file as File & { webkitRelativePath?: string }).webkitRelativePath || file.name);
  if (!candidates.length) {
    throw new Error(`The selected folder contained ${selected.length} file(s), but none were recognized as Zeek .log, .json, or .jsonl files.`);
  }
  const parsed = await Promise.all(candidates.map(parseFile));
  const analysisLogs: Record<string, Array<Record<string, unknown>>> = {};
  parsed.forEach(({ type, rows }) => {
    const target = analysisLogName(type);
    if (!target) return;
    analysisLogs[target] = [...(analysisLogs[target] || []), ...rows];
  });
  const hosts = new Map<string, HostEvidence>();
  const pairs = new Map<string, { src: string; dst: string; proto: string; port?: number; service: string; count: number }>();
  const infra = new Map<string, { kind: "dns" | "ntp" | "dhcp"; value: string; count: number; reason: string }>();
  const vlans = new Map<string, Set<number>>();
  const dhcpSubnets = new Set<string>();
  const ipv6Addresses = new Set<string>();
  let dhcpAssignmentsObserved = 0;
  const warnings = parsed.flatMap((item) => item.warning ? [item.warning] : []);
  const logTypes: Record<string, number> = {};
  let recordsParsed = 0;

  const markInfra = (kind: "dns" | "ntp" | "dhcp", value: string, reason: string) => {
    if (!value) return;
    const key = `${kind}|${value}`;
    const prior = infra.get(key);
    infra.set(key, prior ? { ...prior, count: prior.count + 1 } : { kind, value, count: 1, reason });
  };

  parsed.forEach(({ type, rows }) => {
    logTypes[type] = (logTypes[type] || 0) + rows.length;
    recordsParsed += rows.length;
    rows.forEach((row) => {
      const src = text(first(row, "id.orig_h", "source_ip", "src_ip", "src"));
      const dst = text(first(row, "id.resp_h", "destination_ip", "dst_ip", "dst"));
      const proto = text(first(row, "proto", "protocol")).toLowerCase();
      const port = numberValue(first(row, "id.resp_p", "destination_port", "dst_port"));
      const service = text(first(row, "service", "protocol_name", "application")).toLowerCase();
      const portService = port !== undefined ? OT_PORTS[port] : undefined;
      const logService = serviceFromLogType(type);
      const inferredService = service || portService || logService || "";
      [src, dst].filter(Boolean).forEach((ip) => { if (isIpv6(ip)) ipv6Addresses.add(ip); });
      const otWeight = OT_TOKENS.test(inferredService) || Boolean(portService) || Boolean(logService) ? 3 : 0;
      // For client/server OT protocol logs, the responder is normally the controlled/served endpoint.
      // Keep service evidence on both endpoints, but weight the responder for OT asset/segment inference.
      if (src) upsertHost(hosts, src, inferredService, undefined, 0);
      if (dst) upsertHost(hosts, dst, inferredService, port, otWeight);

      const vlanValues = [numberValue(first(row, "vlan")), numberValue(first(row, "inner_vlan"))].filter((value): value is number => value !== undefined);
      [src, dst].filter(Boolean).forEach((ip) => {
        const subnet = slash24(ip);
        if (!subnet || !vlanValues.length) return;
        const set = vlans.get(subnet) || new Set<number>();
        vlanValues.forEach((value) => set.add(value));
        vlans.set(subnet, set);
      });

      if (src && dst) {
        // Merge evidence for the same observed endpoint/port path across conn.log
        // and protocol-specific logs.  Protocol logs often omit `proto` or `service`;
        // keeping those fields in the key created duplicate communication rows.
        const key = `${src}|${dst}|${port ?? ""}`;
        const prior = pairs.get(key);
        pairs.set(key, prior
          ? {
              ...prior,
              proto: prior.proto || proto,
              service: prior.service || inferredService,
              port: prior.port ?? port,
              count: prior.count + 1,
            }
          : { src, dst, proto, port, service: inferredService, count: 1 });
      }

      if (/^dns/.test(type) && dst) markInfra("dns", dst, "Observed as the responder in dns.log.");
      if (/^ntp/.test(type) && dst) markInfra("ntp", dst, "Observed as the responder in ntp.log.");
      if (/^(dhcp|dhcpv4)/.test(type)) {
        const server = text(first(row, "server_addr", "server_ip", "id.resp_h", "destination_ip"));
        if (server) markInfra("dhcp", server, "Observed as a DHCP server/responder in dhcp.log.");
        const clientIp = text(first(row, "client_addr", "assigned_addr", "requested_addr", "yiaddr", "ip", "source_ip", "id.orig_h", "src"));
        const clientSubnet = slash24(clientIp);
        if (clientSubnet) { dhcpSubnets.add(clientSubnet); dhcpAssignmentsObserved += 1; }
      }

      if (/^(dhcp|dhcpv4|arp)/.test(type)) {
        const mac = normalizeMac(first(row, "client_mac", "mac", "mac_address", "client_hardware_addr", "chaddr", "src_mac", "source_mac"));
        const ip = text(first(row, "client_addr", "assigned_addr", "requested_addr", "ip", "source_ip", "id.orig_h", "src"));
        if (ip && mac) upsertHost(hosts, ip, "", undefined, 0, mac);
      }
    });
  });

  const assetRows: AssetRecord[] = [...hosts.values()].map((host) => ({
    id: crypto.randomUUID(),
    ip: host.ip,
    hostname: "",
    assetType: host.otScore >= 3 ? "OT/ICS candidate" : "Observed host",
    role: host.otScore >= 3 ? "OT" : "Unknown",
    macAddresses: [...host.macs].sort(),
    services: [...host.services].sort(),
    ports: [...host.ports].sort((a, b) => a - b),
    source: "zeek",
    confidence: host.otScore >= 6 ? "high" : host.otScore >= 3 ? "medium" : "low",
    reason: host.otScore >= 3 ? "Observed using an OT/ICS protocol or well-known OT service port." : "Observed in Zeek network telemetry; role cannot be established from traffic alone.",
    observedCount: host.count,
  }));

  const subnetHosts = new Map<string, { count: number; ot: number }>();
  assetRows.forEach((asset) => {
    const subnet = slash24(asset.ip);
    if (!subnet) return;
    const current = subnetHosts.get(subnet) || { count: 0, ot: 0 };
    current.count += 1;
    if (asset.role === "OT") current.ot += 1;
    subnetHosts.set(subnet, current);
  });
  const segmentRows: NetworkSegment[] = [...subnetHosts.entries()].map(([cidr, evidence]) => {
    const vlan = [...(vlans.get(cidr) || new Set<number>())].sort((a, b) => a - b);
    const relatedAssets = assetRows.filter((asset) => slash24(asset.ip) === cidr);
    const otProtocols = [...new Set(relatedAssets.flatMap((asset) => asset.services).filter((value) => OT_TOKENS.test(value)))].sort();
    const likelyOt = evidence.ot > 0 || otProtocols.length > 0;
    const observedDhcp = dhcpSubnets.has(cidr);
    return {
      id: crypto.randomUUID(), name: likelyOt ? `OT candidate ${cidr}` : `Observed ${cidr}`, cidr,
      role: likelyOt ? "ot" : "unknown", purdueLevel: "", vlanId: vlan.length === 1 ? vlan[0] : undefined,
      addressing: observedDhcp ? "dhcp" : "unknown", dhcpAllowed: undefined, ipv6Allowed: undefined,
      observedDhcp, observedOtProtocols: otProtocols, observedVlanIds: vlan,
      suggestedRole: likelyOt ? "ot" : "unknown",
      suggestedPurdueLevel: likelyOt ? "2" : "",
      suggestedAddressing: observedDhcp ? "dhcp" : "unknown",
      source: "zeek", confidence: likelyOt ? "medium" : observedDhcp || vlan.length ? "medium" : "low",
      reason: likelyOt
        ? `${evidence.ot} observed host(s) in this subnet used OT/ICS protocol evidence${otProtocols.length ? ` (${otProtocols.join(", ")})` : ""}.`
        : observedDhcp
          ? "Derived from observed private IPv4 addresses; DHCP activity was observed in this subnet."
          : "Derived from observed private IPv4 addresses; network role may need adjustment.",
      observedCount: evidence.count,
    };
  });

  const infraRows: InfrastructureEntry[] = [...infra.values()].map((item) => ({
    id: crypto.randomUUID(), kind: item.kind, value: item.value, label: "", source: "zeek",
    confidence: item.count >= 5 ? "high" : item.count >= 2 ? "medium" : "low", reason: item.reason,
    observedCount: item.count,
  }));

  const pairRows: CommunicationPair[] = [...pairs.values()].sort((a, b) => b.count - a.count).slice(0, 500).map((pair) => ({
    id: crypto.randomUUID(), sourceIp: pair.src, destinationIp: pair.dst, protocol: pair.proto,
    destinationPort: pair.port, service: pair.service, description: "",
    source: "zeek", confidence: pair.count >= 20 ? "high" : pair.count >= 5 ? "medium" : "low",
    reason: `Observed ${pair.count} time(s). Observation is evidence of use, not authorization.`, observedCount: pair.count,
  }));

  return { segments: segmentRows, assets: assetRows, infrastructure: infraRows, pairs: pairRows, filesScanned: candidates.length, selectedFileCount: selected.length, sourceLabel, fileNames, recordsParsed, logTypes, warnings, dhcpAssignmentsObserved, ipv6AddressesObserved: ipv6Addresses.size, logs: analysisLogs };
}

export function mergeScanIntoProfile(profile: DetectionConfigurationProfile, scan: ZeekScanResult): DetectionConfigurationProfile {
  const mergeSegments = [...profile.segments];
  scan.segments.forEach((incoming) => {
    const index = mergeSegments.findIndex((item) => item.cidr.trim().toLowerCase() === incoming.cidr.trim().toLowerCase());
    if (index < 0) mergeSegments.push(incoming);
    else {
      const current = mergeSegments[index];
      const observedOtProtocols = [...new Set([...(current.observedOtProtocols || []), ...(incoming.observedOtProtocols || [])])].sort();
      const observedVlanIds = [...new Set([...(current.observedVlanIds || []), ...(incoming.observedVlanIds || [])])].sort((a, b) => a - b);
      const observed = {
        observedCount: Math.max(current.observedCount || 0, incoming.observedCount || 0),
        observedDhcp: Boolean(current.observedDhcp || incoming.observedDhcp),
        observedOtProtocols,
        observedVlanIds,
        suggestedRole: incoming.suggestedRole || current.suggestedRole,
        suggestedPurdueLevel: incoming.suggestedPurdueLevel || current.suggestedPurdueLevel,
        suggestedAddressing: incoming.suggestedAddressing || current.suggestedAddressing,
      };
      // Scanner-owned rows are refreshed with better scan-derived facts on every rescan.
      // User/imported policy choices are preserved, while their observed evidence still refreshes.
      mergeSegments[index] = current.source === "zeek"
        ? { ...current, ...incoming, ...observed, id: current.id, purdueLevel: current.purdueLevel || incoming.purdueLevel }
        : { ...current, ...observed };
    }
  });
  const mergeAssets = [...profile.assets];
  scan.assets.forEach((incoming) => {
    const index = mergeAssets.findIndex((item) => item.ip.trim().toLowerCase() === incoming.ip.trim().toLowerCase());
    if (index < 0) mergeAssets.push(incoming);
    else {
      const current = mergeAssets[index];
      mergeAssets[index] = { ...current, macAddresses: [...new Set([...(current.macAddresses || []), ...(incoming.macAddresses || [])])].sort(), services: [...new Set([...current.services, ...incoming.services])].sort(), ports: [...new Set([...current.ports, ...incoming.ports])].sort((a,b)=>a-b), observedCount: Math.max(current.observedCount || 0, incoming.observedCount || 0), reason: current.source === "zeek" ? incoming.reason : current.reason };
    }
  });
  const mergeInfrastructure = [...profile.infrastructure];
  scan.infrastructure.forEach((incoming) => {
    const index = mergeInfrastructure.findIndex((item) => `${item.kind}|${item.value}`.toLowerCase() === `${incoming.kind}|${incoming.value}`.toLowerCase());
    if (index < 0) mergeInfrastructure.push(incoming);
    else {
      const current = mergeInfrastructure[index];
      mergeInfrastructure[index] = { ...current, observedCount: Math.max(current.observedCount || 0, incoming.observedCount || 0), reason: current.source === "zeek" ? incoming.reason : current.reason };
    }
  });
  const normalized = (value?: string) => (value || "").trim().toLowerCase();
  const pairProtocol = (pair: CommunicationPair) => normalized(pair.protocol) || normalized(pair.service);
  const isPortlessProtocol = (pair: CommunicationPair) => {
    const protocol = pairProtocol(pair);
    return protocol === "icmp" || protocol === "icmpv6" || protocol === "icmp6" || protocol === "ipv6-icmp";
  };
  const comparableDestinationPort = (pair: CommunicationPair, portlessPath = isPortlessProtocol(pair)) => {
    // Zeek represents ICMP's synthetic responder port as 0 while imported/user context
    // normally leaves the destination port unset. ICMP has no transport-layer port, so
    // those representations describe the same observed path. If one side has explicit
    // ICMP identity, also normalize an otherwise blank scanner row on the other side.
    if (portlessPath && (pair.destinationPort == null || pair.destinationPort === 0)) return null;
    return pair.destinationPort ?? null;
  };
  const sameObservedPath = (left: CommunicationPair, right: CommunicationPair) => {
    if (normalized(left.sourceIp) !== normalized(right.sourceIp)) return false;
    if (normalized(left.destinationIp) !== normalized(right.destinationIp)) return false;
    // Protocol-specific Zeek logs frequently omit transport. Treat a blank protocol as
    // compatible with a known one, but never collapse explicit TCP and UDP rows.
    const leftProtocol = normalized(left.protocol);
    const rightProtocol = normalized(right.protocol);
    if (leftProtocol && rightProtocol && leftProtocol !== rightProtocol) return false;
    const portlessPath = isPortlessProtocol(left) || isPortlessProtocol(right);
    if (comparableDestinationPort(left, portlessPath) !== comparableDestinationPort(right, portlessPath)) return false;
    return true;
  };
  const sourcePriority = (source?: string) => source === "user" ? 3 : source === "imported" ? 2 : source === "zeek" ? 1 : 0;
  const mergePairEvidence = (left: CommunicationPair, right: CommunicationPair): CommunicationPair => {
    // Preserve the policy/user-owned row when one exists. The other row contributes only
    // observed evidence, so discovery can never turn an observation into authorization.
    const primary = sourcePriority(right.source) > sourcePriority(left.source) ? right : left;
    const secondary = primary === left ? right : left;
    return {
      ...primary,
      protocol: primary.protocol || secondary.protocol,
      service: primary.service || secondary.service,
      destinationPort: primary.destinationPort ?? secondary.destinationPort,
      description: primary.description || secondary.description,
      observedCount: Math.max(primary.observedCount || 0, secondary.observedCount || 0),
      reason: primary.source === "zeek" ? (secondary.reason || primary.reason) : primary.reason,
    };
  };

  // First repair profiles saved by older builds that appended scanner-owned copies of
  // communication rows. Without this pass, later scans could enrich the first matching
  // row but the stale duplicate would remain in the saved profile indefinitely.
  const mergePairs: CommunicationPair[] = [];
  profile.communicationPairs.forEach((existing) => {
    const index = mergePairs.findIndex((candidate) => sameObservedPath(candidate, existing));
    if (index < 0) mergePairs.push(existing);
    else mergePairs[index] = mergePairEvidence(mergePairs[index], existing);
  });

  scan.pairs.forEach((incoming) => {
    const index = mergePairs.findIndex((item) => sameObservedPath(item, incoming));
    if (index < 0) mergePairs.push(incoming);
    else mergePairs[index] = mergePairEvidence(mergePairs[index], incoming);
  });
  return {
    ...profile,
    updatedAt: new Date().toISOString(),
    scan: { scannedAt: new Date().toISOString(), sourceLabel: scan.sourceLabel, selectedFileCount: scan.selectedFileCount, fileNames: scan.fileNames, filesScanned: scan.filesScanned, recordsParsed: scan.recordsParsed, logTypes: scan.logTypes, warnings: scan.warnings, dhcpAssignmentsObserved: scan.dhcpAssignmentsObserved, ipv6AddressesObserved: scan.ipv6AddressesObserved },
    segments: mergeSegments,
    assets: mergeAssets,
    infrastructure: mergeInfrastructure,
    communicationPairs: mergePairs,
  };
}
