import { ALL_DETECTION_MODULES } from "./moduleCatalog";
import { DetectionConfigurationProfile, ModuleReadinessItem, ReadinessItem, ValidationIssue } from "./types";
import { validateProfile } from "./validation";

const STORAGE_KEY = "elevadr:detection-configuration:profiles:v3";
const ACTIVE_KEY = "elevadr:detection-configuration:active:v3";
const LEGACY_STORAGE_KEYS = ["elevadr:detection-configuration:profiles:v2", "elevadr:detection-configuration:profiles:v1"];
const LEGACY_ACTIVE_KEYS = ["elevadr:detection-configuration:active:v2", "elevadr:detection-configuration:active:v1"];

function stripLegacyFlags<T>(item: T): T {
  const copy = { ...(item as object) } as Record<string, unknown>;
  delete copy.confirmed;
  delete copy.allowed;
  return copy as T;
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((x): x is string => typeof x === "string") : [];
}
function objectArray(value: unknown): Record<string, unknown>[] {
  return Array.isArray(value)
    ? value.filter((x): x is Record<string, unknown> => Boolean(x) && typeof x === "object")
    : [];
}

export function createEmptyProfile(): DetectionConfigurationProfile {
  const now = new Date().toISOString();
  return {
    schemaVersion: 3,
    id: crypto.randomUUID(),
    name: "Default Detection Profile",
    description: "",
    updatedAt: now,
    selectedModules: [...ALL_DETECTION_MODULES],
    scan: { filesScanned: 0, recordsParsed: 0, logTypes: {}, warnings: [] },
    captureScope: { internalIcsOnlyExpected: false, dedicatedOtSensor: false, ipv4OnlyExpected: false },
    segments: [],
    assets: [],
    infrastructure: [],
    communicationPairs: [],
    allowedHosts: [],
    allowedSegmentPairs: [],
    approvedExternalDestinations: [],
    authorizedControlActions: [],
    modulePolicies: {},
  };
}

export function migrateProfile(value: unknown): { profile?: DetectionConfigurationProfile; issues: ValidationIssue[]; migrated: boolean } {
  const issues: ValidationIssue[] = [];
  if (!value || typeof value !== "object") {
    return { issues: [{ path: "profile", message: "The file does not contain a profile object.", severity: "error" }], migrated: false };
  }
  const raw = value as Record<string, unknown>;
  const version = Number(raw.schemaVersion ?? 1);
  if (![1, 2, 3].includes(version)) {
    return { issues: [{ path: "schemaVersion", message: `Unsupported profile schema version ${String(raw.schemaVersion)}. Supported versions are 1, 2, and 3.`, severity: "error" }], migrated: false };
  }
  const empty = createEmptyProfile();
  const profile: DetectionConfigurationProfile = {
    ...empty,
    ...raw,
    schemaVersion: 3,
    id: typeof raw.id === "string" && raw.id ? raw.id : crypto.randomUUID(),
    name: typeof raw.name === "string" ? raw.name : empty.name,
    description: typeof raw.description === "string" ? raw.description : "",
    updatedAt: typeof raw.updatedAt === "string" ? raw.updatedAt : new Date().toISOString(),
    selectedModules: stringArray(raw.selectedModules).length ? stringArray(raw.selectedModules) : [...ALL_DETECTION_MODULES],
    scan: raw.scan && typeof raw.scan === "object"
      ? {
          ...empty.scan,
          ...(raw.scan as object),
          warnings: stringArray((raw.scan as Record<string, unknown>).warnings),
          logTypes: (raw.scan as Record<string, unknown>).logTypes && typeof (raw.scan as Record<string, unknown>).logTypes === "object"
            ? (raw.scan as DetectionConfigurationProfile["scan"]).logTypes
            : {},
        }
      : empty.scan,
    captureScope: raw.captureScope && typeof raw.captureScope === "object"
      ? { ...empty.captureScope, ...(raw.captureScope as object) }
      : empty.captureScope,
    segments: objectArray(raw.segments).map((x) => stripLegacyFlags(x)) as unknown as DetectionConfigurationProfile["segments"],
    assets: objectArray(raw.assets).map((x) => ({
      ...stripLegacyFlags(x),
      macAddresses: stringArray(x.macAddresses ?? x.macs ?? x.mac_addresses ?? (x.mac ? [x.mac] : [])),
      services: stringArray(x.services),
      ports: Array.isArray(x.ports) ? x.ports.map(Number).filter(Number.isFinite) : [],
    })) as unknown as DetectionConfigurationProfile["assets"],
    infrastructure: objectArray(raw.infrastructure).map((x) => stripLegacyFlags(x)) as unknown as DetectionConfigurationProfile["infrastructure"],
    communicationPairs: objectArray(raw.communicationPairs).map((x) => stripLegacyFlags(x)) as unknown as DetectionConfigurationProfile["communicationPairs"],
    allowedHosts: stringArray(raw.allowedHosts),
    allowedSegmentPairs: objectArray(raw.allowedSegmentPairs).map((x) => ({
      id: typeof x.id === "string" && x.id ? x.id : crypto.randomUUID(),
      sourceSegment: String(x.sourceSegment ?? x.source ?? ""),
      destinationSegment: String(x.destinationSegment ?? x.destination ?? ""),
      description: typeof x.description === "string" ? x.description : "",
    })) as DetectionConfigurationProfile["allowedSegmentPairs"],
    approvedExternalDestinations: stringArray(raw.approvedExternalDestinations),
    authorizedControlActions: objectArray(raw.authorizedControlActions).map((x) => ({
      id: typeof x.id === "string" && x.id ? x.id : crypto.randomUUID(),
      protocol: (["modbus", "dnp3", "s7comm", "enip"].includes(String(x.protocol).toLowerCase()) ? String(x.protocol).toLowerCase() : "modbus") as DetectionConfigurationProfile["authorizedControlActions"][number]["protocol"],
      source: String(x.source ?? ""),
      destination: String(x.destination ?? ""),
      allowedOperations: stringArray(x.allowedOperations ?? x.allowed_operations ?? x.operations),
      allowedFunctionCodes: Array.isArray(x.allowedFunctionCodes ?? x.allowed_function_codes)
        ? ((x.allowedFunctionCodes ?? x.allowed_function_codes) as unknown[]).map((v) => typeof v === "number" ? v : String(v)).filter((v) => String(v).trim() !== "")
        : [],
      description: typeof x.description === "string" ? x.description : "",
    })) as DetectionConfigurationProfile["authorizedControlActions"],
    modulePolicies: raw.modulePolicies && typeof raw.modulePolicies === "object" && !Array.isArray(raw.modulePolicies)
      ? raw.modulePolicies as DetectionConfigurationProfile["modulePolicies"]
      : {},
  };
  if (version < 3) {
    issues.push({ path: "schemaVersion", message: `Profile schema v${version} was migrated to v3.`, severity: "warning" });
  }
  return { profile, issues: [...issues, ...validateProfile(profile)], migrated: version !== 3 };
}

export function normalizeProfile(profile: DetectionConfigurationProfile): DetectionConfigurationProfile {
  return migrateProfile(profile).profile || createEmptyProfile();
}

function readStored(key: string): DetectionConfigurationProfile[] {
  try {
    const parsed = JSON.parse(localStorage.getItem(key) || "[]");
    if (!Array.isArray(parsed)) return [];
    return parsed.map((x) => migrateProfile(x).profile).filter((x): x is DetectionConfigurationProfile => Boolean(x));
  } catch {
    return [];
  }
}
function writeStored(profiles: DetectionConfigurationProfile[]): void {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(profiles));
}

function dedupeStoredProfiles(profiles: DetectionConfigurationProfile[]): DetectionConfigurationProfile[] {
  const activeId = localStorage.getItem(ACTIVE_KEY);
  const byId = new Map<string, DetectionConfigurationProfile>();
  for (const profile of profiles) {
    const prior = byId.get(profile.id);
    if (!prior || profile.updatedAt > prior.updatedAt) byId.set(profile.id, profile);
  }
  const unique = [...byId.values()];
  const defaults = unique.filter((profile) => profile.name.trim().toLowerCase() === "default detection profile");
  if (defaults.length <= 1) return unique;
  const keep = defaults.find((profile) => profile.id === activeId)
    || [...defaults].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt))[0];
  return unique.filter((profile) => profile.name.trim().toLowerCase() !== "default detection profile" || profile.id === keep.id);
}

function hasMeaningfulSegmentContext(segment: DetectionConfigurationProfile["segments"][number]): boolean {
  return segment.role !== "unknown" || Boolean(segment.purdueLevel) || segment.vlanId !== undefined || segment.addressing !== "unknown" || segment.dhcpAllowed !== undefined || segment.ipv6Allowed !== undefined;
}

function recoverSegmentContext(
  current: DetectionConfigurationProfile,
  legacy: DetectionConfigurationProfile,
): DetectionConfigurationProfile {
  let changed = false;
  const segments = current.segments.map((segment) => {
    const prior = legacy.segments.find((candidate) => candidate.cidr.trim().toLowerCase() === segment.cidr.trim().toLowerCase());
    if (!prior || !hasMeaningfulSegmentContext(prior)) return segment;

    const recovered = {
      ...segment,
      name: /^Observed\s/i.test(segment.name) && prior.name && !/^Observed\s/i.test(prior.name) ? prior.name : segment.name,
      role: segment.role === "unknown" && prior.role !== "unknown" ? prior.role : segment.role,
      purdueLevel: !segment.purdueLevel && prior.purdueLevel ? prior.purdueLevel : segment.purdueLevel,
      vlanId: segment.vlanId === undefined && prior.vlanId !== undefined ? prior.vlanId : segment.vlanId,
      addressing: segment.addressing === "unknown" && prior.addressing !== "unknown" ? prior.addressing : segment.addressing,
      dhcpAllowed: segment.dhcpAllowed === undefined && prior.dhcpAllowed !== undefined ? prior.dhcpAllowed : segment.dhcpAllowed,
      ipv6Allowed: segment.ipv6Allowed === undefined && prior.ipv6Allowed !== undefined ? prior.ipv6Allowed : segment.ipv6Allowed,
    };

    if (JSON.stringify(recovered) !== JSON.stringify(segment)) {
      changed = true;
      return {
        ...recovered,
        source: prior.source === "zeek" ? segment.source : prior.source,
        confidence: prior.source === "zeek" ? segment.confidence : prior.confidence,
        reason: prior.source === "zeek" ? segment.reason : prior.reason,
      };
    }
    return segment;
  });

  return changed ? { ...current, segments } : current;
}

function migrateLegacyStorage(): DetectionConfigurationProfile[] {
  let current = readStored(STORAGE_KEY);
  const legacyProfiles = LEGACY_STORAGE_KEYS.flatMap((key) => readStored(key));

  if (!current.length) {
    if (!legacyProfiles.length) return [];
    current = legacyProfiles;
    writeStored(current);
    for (const activeKey of LEGACY_ACTIVE_KEYS) {
      const legacyActive = localStorage.getItem(activeKey);
      if (legacyActive) { localStorage.setItem(ACTIVE_KEY, legacyActive); break; }
    }
    return current;
  }

  if (!legacyProfiles.length) return current;

  let recoveredAny = false;
  const recovered = current.map((profile) => {
    const byId = legacyProfiles.find((legacy) => legacy.id === profile.id);
    const sameName = legacyProfiles.filter((legacy) => legacy.name.trim().toLowerCase() === profile.name.trim().toLowerCase());
    const legacy = byId || (sameName.length === 1 ? sameName[0] : undefined);
    if (!legacy) return profile;
    const next = recoverSegmentContext(profile, legacy);
    if (next !== profile) recoveredAny = true;
    return next;
  });

  if (recoveredAny) writeStored(recovered);
  return recovered;
}

export function saveProfile(profile: DetectionConfigurationProfile): DetectionConfigurationProfile {
  const next = normalizeProfile({ ...profile, updatedAt: new Date().toISOString() });
  const profiles = migrateLegacyStorage();
  const index = profiles.findIndex((x) => x.id === next.id);
  if (index >= 0) profiles[index] = next; else profiles.push(next);
  writeStored(profiles);
  localStorage.setItem(ACTIVE_KEY, next.id);
  return next;
}
export function listProfiles(): DetectionConfigurationProfile[] {
  const profiles = migrateLegacyStorage();
  const deduped = dedupeStoredProfiles(profiles);
  if (deduped.length !== profiles.length) writeStored(deduped);
  return deduped;
}
export function removeProfile(profileId: string): DetectionConfigurationProfile[] {
  const profiles = listProfiles().filter((x) => x.id !== profileId);
  writeStored(profiles);
  if (localStorage.getItem(ACTIVE_KEY) === profileId) {
    if (profiles.length) localStorage.setItem(ACTIVE_KEY, profiles[0].id); else localStorage.removeItem(ACTIVE_KEY);
  }
  return profiles;
}
export function loadActiveProfile(): DetectionConfigurationProfile {
  const profiles = listProfiles();
  const activeId = localStorage.getItem(ACTIVE_KEY) || LEGACY_ACTIVE_KEYS.map((k) => localStorage.getItem(k)).find(Boolean);
  return profiles.find((x) => x.id === activeId) || profiles[0] || createEmptyProfile();
}
export function activateProfile(profileId: string): void { localStorage.setItem(ACTIVE_KEY, profileId); }
export function exportProfile(profile: DetectionConfigurationProfile): void {
  const blob = new Blob([JSON.stringify(normalizeProfile(profile), null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${profile.name.trim().replace(/[^a-z0-9]+/gi, "-").replace(/^-|-$/g, "").toLowerCase() || "elevadr-detection-profile"}.json`;
  a.click();
  URL.revokeObjectURL(url);
}
export function isDetectionProfile(value: unknown): boolean { return Boolean(migrateProfile(value).profile); }

function isOt(p: DetectionConfigurationProfile): boolean {
  return p.segments.some((x) => x.role === "ot") || p.assets.some((x) => /ot|plc|controller/i.test(`${x.role} ${x.assetType}`));
}
function hasControlActions(p: DetectionConfigurationProfile, protocol?: string): boolean {
  return p.authorizedControlActions.some((x) => !protocol || x.protocol === protocol);
}

export function readiness(profile: DetectionConfigurationProfile): ReadinessItem[] {
  const segments = profile.segments;
  const assets = profile.assets;
  const infrastructure = profile.infrastructure;
  const trusted = (kind: string) => infrastructure.filter((x) => x.kind === kind).length;
  const otAssets = assets.filter((x) => x.assetType.toLowerCase().includes("plc") || x.role.toLowerCase().includes("ot") || x.services.some((s) => /modbus|s7|dnp3|bacnet|enip|cip|fox|codesys/i.test(s)));
  const macAssets = assets.filter((x) => x.macAddresses.length).length;
  const purdue = segments.filter((x) => x.purdueLevel).length;
  const ipv4Only = segments.filter((x) => x.ipv6Allowed === false).length;
  const staticSegments = segments.filter((x) => x.addressing === "static" || x.dhcpAllowed === false).length;
  const pairs = profile.communicationPairs.length;
  return [
    { id: "capture", label: "Capture scope", level: profile.captureScope.internalIcsOnlyExpected || profile.captureScope.dedicatedOtSensor || profile.captureScope.ipv4OnlyExpected ? "ready" : "info", detail: profile.captureScope.internalIcsOnlyExpected || profile.captureScope.dedicatedOtSensor || profile.captureScope.ipv4OnlyExpected ? "Capture-scope expectations are configured." : "Set capture-scope expectations when the sensor is dedicated to OT/ICS or the monitored scope is IPv4-only." },
    { id: "segments", label: "Network segments", level: segments.length ? "ready" : "warning", detail: segments.length ? `${segments.length} active segment(s).` : "Define OT/IT/DMZ network segments for policy-aware detectors." },
    { id: "assets", label: "Asset inventory", level: assets.length ? "ready" : "warning", detail: assets.length ? `${assets.length} active asset(s), including ${otAssets.length} OT/ICS candidate(s); ${macAssets} asset(s) include MAC addresses.` : "Add assets and identify OT devices where applicable." },
    { id: "purdue", label: "Purdue levels", level: purdue ? "ready" : "warning", detail: purdue ? `${purdue} segment(s) have Purdue levels.` : "Cross-Purdue detection needs Purdue levels assigned to relevant segments." },
    { id: "dns", label: "Trusted DNS", level: trusted("dns") ? "ready" : "warning", detail: trusted("dns") ? `${trusted("dns")} trusted resolver(s).` : "Add the DNS resolvers OT hosts are expected to use." },
    { id: "ntp", label: "Trusted NTP", level: trusted("ntp") ? "ready" : "warning", detail: trusted("ntp") ? `${trusted("ntp")} trusted server(s).` : "Add expected NTP servers for OT hosts." },
    { id: "dhcp", label: "DHCP policy", level: trusted("dhcp") || staticSegments ? "ready" : "warning", detail: trusted("dhcp") || staticSegments ? `${trusted("dhcp")} expected DHCP server(s); ${staticSegments} static/DHCP-prohibited segment(s).` : "Add DHCP servers and/or mark static OT segments." },
    { id: "ipv6", label: "IPv4-only policy", level: profile.captureScope.ipv4OnlyExpected || ipv4Only ? "ready" : "info", detail: profile.captureScope.ipv4OnlyExpected || ipv4Only ? `${ipv4Only} segment(s) explicitly disallow IPv6; global IPv4-only expectation is ${profile.captureScope.ipv4OnlyExpected ? "enabled" : "not enabled"}.` : "IPv6-in-OT findings require an explicit IPv4-only expectation." },
    { id: "pairs", label: "Communications", level: pairs || profile.allowedHosts.length || profile.allowedSegmentPairs.length ? "ready" : "warning", detail: `${pairs} host communication pair(s); ${profile.allowedSegmentPairs.length} segment-pair exception(s).` },
    { id: "control", label: "Authorized control actions", level: profile.authorizedControlActions.length ? "ready" : "warning", detail: profile.authorizedControlActions.length ? `${profile.authorizedControlActions.length} authorized control-action rule(s).` : "Add explicit Modbus/DNP3/S7/CIP control-action rules when write/program operations are expected." },
    { id: "defaults", label: "Module thresholds", level: "info", detail: "All 75 modules are selected. Module thresholds use detector defaults unless an Advanced override is supplied." },
  ];
}

const CONTEXT_REQUIREMENTS: Record<string, (p: DetectionConfigurationProfile) => string | undefined> = {
  cross_purdue_level_traffic: (p) => p.segments.some((x) => x.purdueLevel) ? undefined : "Assign Purdue levels to relevant network segments.",
  control_system_enterprise_non_dmz: (p) => p.segments.some((x) => x.role === "ot") && p.segments.some((x) => x.role === "it") ? undefined : "Identify both OT and IT network segments.",
  internet_exposed_ics: (p) => isOt(p) ? undefined : "Identify OT segments or OT/controller assets.",
  ipv6_traffic_ot: (p) => (p.captureScope.ipv4OnlyExpected || p.segments.some((x) => x.role === "ot" && x.ipv6Allowed === false)) ? undefined : "Explicitly mark the monitored OT scope or at least one OT segment as IPv4 only.",
  new_ot_conversation_pair: (p) => isOt(p) ? undefined : "Identify OT assets/segments; the module learns its baseline from the capture.",
  new_service_emergence_ot: (p) => isOt(p) ? undefined : "Identify OT assets/segments; the module learns its baseline from the capture.",
  ot_asset_gone_silent: (p) => isOt(p) ? undefined : "Identify OT assets/segments; sufficient baseline history is also required in the logs.",
  ot_external_dns_resolver: (p) => p.infrastructure.some((x) => x.kind === "dns") ? undefined : "Add expected/trusted DNS resolvers.",
  ntp_internet_multi_dest_ot: (p) => p.infrastructure.some((x) => x.kind === "ntp") ? undefined : "Add expected/trusted NTP servers.",
  rogue_dhcp_static_ot: (p) => p.infrastructure.some((x) => x.kind === "dhcp") || p.segments.some((x) => x.addressing === "static" || x.dhcpAllowed === false) ? undefined : "Add expected DHCP servers and/or mark static/DHCP-prohibited segments.",
  unexpected_dhcp_server: (p) => p.infrastructure.some((x) => x.kind === "dhcp") ? undefined : "Add trusted DHCP infrastructure before labeling a server unexpected.",
  dns_source_drift: (p) => p.infrastructure.some((x) => x.kind === "dns") ? undefined : "Add trusted DNS infrastructure for authoritative resolver-drift detection.",
  ntp_source_drift: (p) => p.infrastructure.some((x) => x.kind === "ntp") ? undefined : "Add trusted NTP infrastructure for authoritative time-source drift detection.",
  arp_ip_mac_identity_change: (p) => p.assets.some((x) => x.source !== "zeek" && x.ip && x.macAddresses.length) ? undefined : "Add authoritative asset IP/MAC mappings for strongest identity-change detection.",
  ot_protocol_role_reversal: (p) => isOt(p) ? undefined : "Identify OT assets/segments; the detector learns directionality from the capture baseline.",
  plc_rtu_peer_change: (p) => p.assets.some((x) => /plc|rtu|controller|ied/i.test(`${x.role} ${x.assetType}`)) ? undefined : "Identify authoritative PLC/RTU/controller/IED assets.",
  engineering_workstation_control_burst: (p) => p.assets.some((x) => /engineering|engineer|ews|programming workstation/i.test(`${x.hostname || ""} ${x.role} ${x.assetType}`)) ? undefined : "Identify authoritative engineering workstation assets.",
  encrypted_session_fingerprint_change: (p) => isOt(p) ? undefined : "Identify OT assets/segments so encrypted-session fingerprint drift can be interpreted in site context.",
  remote_access_session_anomaly: (p) => p.infrastructure.some((x) => x.kind === "management") ? undefined : "Add trusted management infrastructure or use a narrow Advanced authorized-source policy for strongest remote-access drift detection.",
  service_disappearance_replacement: (p) => isOt(p) ? undefined : "Identify OT assets/segments; the detector compares baseline and post-baseline service identity.",
  polling_cadence_disruption: (p) => isOt(p) ? undefined : "Identify OT assets/segments and provide enough capture duration to establish polling cadence.",
  controller_communication_jitter: (p) => p.assets.some((x) => /plc|rtu|controller/i.test(`${x.role} ${x.assetType}`)) ? undefined : "Identify authoritative PLC/RTU/controller assets for strongest jitter analysis.",
  vlan_tag_mismatch_double_tag: (p) => p.segments.some((x) => x.vlanId !== undefined) ? undefined : "Assign expected VLAN IDs to relevant segments.",
  public_to_public_traffic: (p) => p.captureScope.internalIcsOnlyExpected ? undefined : "Enable 'Internal ICS/OT traffic only expected' in Capture Scope before treating public-to-public traffic as anomalous.",
  unknown_rogue_devices: (p) => p.assets.length && p.assets.some((x) => x.ip || x.macAddresses.length) ? undefined : "Populate Asset Inventory with known IP and/or MAC addresses.",
  snmp_write_ot_devices: (p) => p.assets.some((x) => /ot|plc|controller|network/i.test(`${x.role} ${x.assetType}`)) ? undefined : "Identify OT/controller/network-device targets; optionally add approved managers/pairs.",
  ics_write_operations: (p) => hasControlActions(p, "modbus") || hasControlActions(p, "dnp3") ? undefined : "Add explicit authorized Modbus/DNP3 control actions if expected write/control paths should be treated as authorized.",
  s7comm_unauthorized_write_stop: (p) => hasControlActions(p, "s7comm") ? undefined : "Add explicit authorized S7 control actions for expected engineering-station to PLC write/STOP paths.",
  plc_program_logic_firmware_update: (p) => p.authorizedControlActions.length ? undefined : "Add authorized programming/firmware actions for expected Modbus, DNP3, S7, or CIP maintenance paths.",
  ot_outbound_internet_any_protocol: (p) => isOt(p) ? undefined : "Identify OT assets/segments and review approved external destinations.",
  file_extraction_sensitive_types: (p) => p.approvedExternalDestinations.length ? undefined : "Optional: add approved external destinations to reduce expected-transfer findings.",
  database_service_exposed: (p) => p.segments.length ? undefined : "Define network segments so exposure can be interpreted in context.",
  netbios_smbv1_exposure: (p) => p.segments.length ? undefined : "Define network segments so boundary exposure can be interpreted in context.",
  ot_protocol_exposure: (p) => p.segments.length ? undefined : "Define control and non-control network segments so OT protocol exposure can be classified.",
};

function humanize(id: string): string {
  const acronyms = new Set(["OT", "ICS", "DNS", "NTP", "DHCP", "TLS", "SMB", "SNMP", "HTTP", "LDAP", "ICMP", "IRC", "QUIC", "RDP", "VLAN"]);
  return id.split("_").map((x) => acronyms.has(x.toUpperCase()) ? x.toUpperCase() : x.charAt(0).toUpperCase() + x.slice(1)).join(" ");
}
export function moduleReadiness(profile: DetectionConfigurationProfile): ModuleReadinessItem[] {
  return profile.selectedModules.map((id) => {
    const missing = CONTEXT_REQUIREMENTS[id]?.(profile);
    const contextComplete = !missing;
    return missing
      ? { id, label: humanize(id), canRun: true, contextComplete, level: "warning" as const, detail: `Can run with detector defaults/log evidence. Context incomplete: ${missing}` }
      : { id, label: humanize(id), canRun: true, contextComplete, level: "ready" as const, detail: CONTEXT_REQUIREMENTS[id] ? "Can run. Site-specific context is complete." : "Can run. No additional site-specific frontend context is required; detector defaults/log evidence apply." };
  });
}
