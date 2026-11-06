export type Confidence = "high" | "medium" | "low";
export type ValueSource = "user" | "zeek" | "imported" | "default";

export interface Provenance {
  source: ValueSource;
  confidence: Confidence;
  reason?: string;
  observedCount?: number;
}

export interface NetworkSegment extends Provenance {
  id: string;
  name: string;
  cidr: string;
  role: "ot" | "it" | "dmz" | "unknown";
  purdueLevel?: string;
  vlanId?: number;
  addressing: "static" | "dhcp" | "mixed" | "unknown";
  dhcpAllowed?: boolean;
  ipv6Allowed?: boolean;
  /** Facts observed directly in the most recent Zeek scan. These are not site-policy declarations. */
  observedDhcp?: boolean;
  observedOtProtocols?: string[];
  observedVlanIds?: number[];
  suggestedRole?: "ot" | "it" | "dmz" | "unknown";
  suggestedPurdueLevel?: string;
  suggestedAddressing?: "static" | "dhcp" | "mixed" | "unknown";
}

export interface AssetRecord extends Provenance {
  id: string;
  ip: string;
  hostname?: string;
  macAddresses: string[];
  assetType: string;
  role: string;
  segment?: string;
  purdueLevel?: string;
  services: string[];
  ports: number[];
}

export interface InfrastructureEntry extends Provenance {
  id: string;
  kind: "dns" | "ntp" | "dhcp" | "management";
  value: string;
  label?: string;
}

export interface CommunicationPair extends Provenance {
  id: string;
  sourceIp: string;
  destinationIp: string;
  protocol?: string;
  destinationPort?: number;
  service?: string;
  description?: string;
}

export interface SegmentPairRule {
  id: string;
  sourceSegment: string;
  destinationSegment: string;
  description?: string;
}

export interface AuthorizedControlAction {
  id: string;
  protocol: "modbus" | "dnp3" | "s7comm" | "enip";
  source: string;
  destination: string;
  allowedOperations: string[];
  allowedFunctionCodes: Array<number | string>;
  description?: string;
}

export interface CaptureScope {
  internalIcsOnlyExpected: boolean;
  dedicatedOtSensor: boolean;
  ipv4OnlyExpected: boolean;
}

export interface ScanSummary {
  scannedAt?: string;
  sourceLabel?: string;
  selectedFileCount?: number;
  fileNames?: string[];
  filesScanned: number;
  recordsParsed: number;
  logTypes: Record<string, number>;
  warnings: string[];
  dhcpAssignmentsObserved?: number;
  ipv6AddressesObserved?: number;
}

export interface DetectionConfigurationProfile {
  schemaVersion: 3;
  id: string;
  name: string;
  description: string;
  updatedAt: string;
  selectedModules: string[];
  scan: ScanSummary;
  captureScope: CaptureScope;
  segments: NetworkSegment[];
  assets: AssetRecord[];
  infrastructure: InfrastructureEntry[];
  communicationPairs: CommunicationPair[];
  allowedHosts: string[];
  allowedSegmentPairs: SegmentPairRule[];
  approvedExternalDestinations: string[];
  authorizedControlActions: AuthorizedControlAction[];
  modulePolicies: Record<string, Record<string, unknown>>;
}

export interface ReadinessItem {
  id: string;
  label: string;
  level: "ready" | "warning" | "info";
  detail: string;
}

export interface ModuleReadinessItem {
  id: string;
  label: string;
  /** Whether the detector can execute with its available logs/defaults. */
  canRun: boolean;
  /** Whether the frontend has the site-specific context used to improve precision/interpretation. */
  contextComplete: boolean;
  level: "ready" | "warning" | "info";
  detail: string;
}

export interface ValidationIssue {
  path: string;
  message: string;
  severity: "error" | "warning";
}
