import { DetectionModuleFinding } from "./analysisClient";

export const ANALYSIS_SEVERITIES = ["critical", "high", "medium", "low", "informational"] as const;
export type AnalysisSeverity = (typeof ANALYSIS_SEVERITIES)[number];

const WORD_LABELS: Record<string, string> = {
  asrep: "AS-REP",
  bacnet: "BACnet",
  c2: "C2",
  cip: "CIP",
  codesys: "CODESYS",
  dhcp: "DHCP",
  dnp3: "DNP3",
  dns: "DNS",
  enip: "EtherNet/IP",
  fox: "FOX",
  ftp: "FTP",
  http: "HTTP",
  iccp: "ICCP",
  icmp: "ICMP",
  ics: "ICS",
  igd: "IGD",
  ip: "IP",
  ipv6: "IPv6",
  irc: "IRC",
  ja3: "JA3",
  kerberos: "Kerberos",
  ldap: "LDAP",
  llmnr: "LLMNR",
  mdns: "mDNS",
  nbtns: "NBT-NS",
  netbios: "NetBIOS",
  nla: "NLA",
  ntlmv1: "NTLMv1",
  ntp: "NTP",
  ot: "OT",
  plc: "PLC",
  quic: "QUIC",
  rdp: "RDP",
  s7comm: "S7comm",
  smb: "SMB",
  smb1: "SMBv1",
  snmp: "SNMP",
  socks: "SOCKS",
  ssl: "SSL",
  ssdp: "SSDP",
  tase2: "TASE.2",
  tls: "TLS",
  upnp: "UPnP",
  vlan: "VLAN",
  vnc: "VNC",
  vpn: "VPN",
};

const SPECIAL_MODULE_LABELS: Record<string, string> = {
  deprecated_insecure_services_protocols: "Deprecated / Insecure Services & Protocols",
  netbios_smbv1_exposure: "NetBIOS / SMBv1 Exposure",
  protocol_unexpected_high_risk_port: "Unexpected High-Risk Port",
  weird_protocol_violations: "Zeek Weird / Protocol Violations",
  control_system_enterprise_non_dmz: "Control-System / Enterprise Traffic Outside DMZ",
  llmnr_nbtns_mdns_poisoning_signals: "LLMNR / NBT-NS / mDNS Poisoning Signals",
  enip_cip_write_session_abuses: "EtherNet/IP CIP Write & Session Abuses",
  plc_program_logic_firmware_update: "PLC Program / Logic / Firmware Update",
  s7comm_unauthorized_write_stop: "Unauthorized S7comm Write / STOP",
  snmp_write_ot_devices: "SNMP Write to OT Devices",
  ipv6_traffic_ot: "IPv6 Traffic in OT",
  ot_external_dns_resolver: "External DNS Resolver Used by OT",
  ot_outbound_internet_any_protocol: "OT Outbound Internet Traffic",
  ntp_internet_multi_dest_ot: "OT NTP to Internet / Multiple Destinations",
};

export function formatModuleTitle(moduleId: string): string {
  const special = SPECIAL_MODULE_LABELS[moduleId];
  if (special) return special;
  return moduleId
    .split("_")
    .filter(Boolean)
    .map((word) => WORD_LABELS[word.toLowerCase()] ?? `${word.charAt(0).toUpperCase()}${word.slice(1)}`)
    .join(" ");
}

export function severityRank(severity: string | undefined): number {
  const index = ANALYSIS_SEVERITIES.indexOf(String(severity || "").toLowerCase() as AnalysisSeverity);
  return index === -1 ? ANALYSIS_SEVERITIES.length : index;
}

export function highestSeverity(findings: DetectionModuleFinding[]): string {
  if (!findings.length) return "none";
  return [...findings].sort((a, b) => severityRank(a.severity) - severityRank(b.severity))[0]?.severity || "unknown";
}

const addHostValue = (set: Set<string>, value: unknown) => {
  if (typeof value === "string" && value.trim()) set.add(value.trim());
};

const collectObjectHosts = (set: Set<string>, value: unknown) => {
  if (!value || typeof value !== "object" || Array.isArray(value)) return;
  const row = value as Record<string, unknown>;
  ["source", "destination", "src", "dst", "source_ip", "destination_ip", "orig_h", "resp_h", "id.orig_h", "id.resp_h", "host", "ip"].forEach((key) => addHostValue(set, row[key]));
  const id = row.id;
  if (id && typeof id === "object" && !Array.isArray(id)) {
    const idRow = id as Record<string, unknown>;
    addHostValue(set, idRow.orig_h);
    addHostValue(set, idRow.resp_h);
  }
};

export function findingHosts(finding: DetectionModuleFinding): string[] {
  const hosts = new Set<string>();
  (finding.devices || []).forEach((value) => addHostValue(hosts, value));
  (finding.connection_pairs || []).forEach((value) => collectObjectHosts(hosts, value));
  (finding.flows || []).forEach((value) => collectObjectHosts(hosts, value));
  return [...hosts].sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
}

export function findingEvidenceSummary(finding: DetectionModuleFinding): string[] {
  const parts: string[] = [];
  const hosts = findingHosts(finding);
  if (hosts.length) parts.push(hosts.slice(0, 3).join(" → "));
  if (finding.services?.length) parts.push(finding.services.slice(0, 3).join(", "));
  if (finding.ports?.length) parts.push(`port${finding.ports.length === 1 ? "" : "s"} ${finding.ports.slice(0, 4).join(", ")}`);
  if (finding.timestamps?.length) parts.push(String(finding.timestamps[0]));
  return parts.slice(0, 4);
}

export function contextTabForModule(moduleId: string): string | null {
  if (/unknown_rogue_devices/.test(moduleId)) return "assets";
  if (/public_to_public|ipv6_traffic_ot/.test(moduleId)) return "captureScope";
  if (/write|firmware|program_logic|s7comm|enip_cip/.test(moduleId)) return "controlActions";
  if (/dns_resolver|ntp_|rogue_dhcp/.test(moduleId)) return "infrastructure";
  if (/cross_purdue|enterprise_non_dmz|database_service_exposed|netbios_smbv1/.test(moduleId)) return "segmentPairs";
  if (/outbound|external|internet_exposed|large_outbound/.test(moduleId)) return "externalDestinations";
  if (/purdue|vlan|ot_protocol|quic_ot|broadcast_multicast_ot/.test(moduleId)) return "segments";
  return null;
}
