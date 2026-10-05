import type { ElevadrReport, Modules } from "../types/Report";

export const CURRENT_REPORT_VERSION = "2.0.0";
export const SUPPORTED_REPORT_MAJOR_VERSION = "2";

export interface ReportCompatibilityResult {
  report: ElevadrReport;
  warnings: string[];
  migrated: boolean;
  sourceVersion: string;
}

type JsonRecord = Record<string, unknown>;

const record = (value: unknown): JsonRecord =>
  value && typeof value === "object" && !Array.isArray(value) ? value as JsonRecord : {};
const array = <T = unknown>(value: unknown): T[] => Array.isArray(value) ? value as T[] : [];
const stringValue = (value: unknown, fallback = ""): string =>
  typeof value === "string" && value.trim() ? value : fallback;
const numberValue = (value: unknown, fallback = 0): number => {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
};

const first = (source: JsonRecord, ...keys: string[]): unknown => {
  for (const key of keys) {
    if (source[key] !== undefined && source[key] !== null) return source[key];
  }
  return undefined;
};

function defaultModules(): Modules {
  return {
    service_panel: { num_known_services: 0, num_ot_services: 0, num_risky_services: 0, num_unknown_services: 0 },
    device_panel: { hosts: 0, ot_hosts: 0, it_hosts: 0, edge_hosts: 0, ot_cross_segment: 0 },
    service_risk_breakdown_panel: { risk_category_counts: {}, risk_category_services: {} },
    service_count_panel: { service_count: 0, service_connections_count: { known_services: [], unknown_services: {} } },
    connection_success_panel: {
      summary: { successful_count: 0, unsuccessful_count: 0, by_state: {} },
      connections: [],
    },
    suspicious_outbound_connections_panel: [],
    ot_cross_segment_lines_panel: { lines: [], subnet_pair_counts: [], dst_subnet_counts: [], ot_device_counts: [] },
    ot_devices: [],
    it_devices: [],
    edge_devices: [],
    ot_services: [],
  };
}

function normalizeModules(value: unknown, warnings: string[]): Modules {
  const source = record(value);
  const defaults = defaultModules();

  const servicePanel = record(first(source, "service_panel", "servicePanel"));
  const devicePanel = record(first(source, "device_panel", "devicePanel"));
  const riskPanel = record(first(source, "service_risk_breakdown_panel", "serviceRiskBreakdownPanel"));
  const countPanel = record(first(source, "service_count_panel", "serviceCountPanel"));
  const connectionPanel = record(first(source, "connection_success_panel", "connectionSuccessPanel"));
  const connectionSummary = record(connectionPanel.summary);
  const crossPanel = record(first(source, "ot_cross_segment_lines_panel", "otCrossSegmentLinesPanel"));

  const normalized: Modules = {
    service_panel: {
      num_known_services: numberValue(first(servicePanel, "num_known_services", "numKnownServices")),
      num_ot_services: numberValue(first(servicePanel, "num_ot_services", "numOtServices")),
      num_risky_services: numberValue(first(servicePanel, "num_risky_services", "numRiskyServices")),
      num_unknown_services: numberValue(first(servicePanel, "num_unknown_services", "numUnknownServices")),
    },
    device_panel: {
      hosts: numberValue(devicePanel.hosts),
      ot_hosts: numberValue(first(devicePanel, "ot_hosts", "otHosts")),
      it_hosts: numberValue(first(devicePanel, "it_hosts", "itHosts")),
      edge_hosts: numberValue(first(devicePanel, "edge_hosts", "edgeHosts")),
      ot_cross_segment: numberValue(first(devicePanel, "ot_cross_segment", "otCrossSegment")),
    },
    service_risk_breakdown_panel: {
      risk_category_counts: record(first(riskPanel, "risk_category_counts", "riskCategoryCounts")) as Record<string, number>,
      risk_category_services: record(first(riskPanel, "risk_category_services", "riskCategoryServices")) as Record<string, string[]>,
    },
    service_count_panel: {
      service_count: numberValue(first(countPanel, "service_count", "serviceCount")),
      service_connections_count: (() => {
        const raw = record(first(countPanel, "service_connections_count", "serviceConnectionsCount"));
        return {
          known_services: array(first(raw, "known_services", "knownServices")) as Modules["service_count_panel"]["service_connections_count"]["known_services"],
          unknown_services: record(first(raw, "unknown_services", "unknownServices")) as Record<string, number>,
        };
      })(),
    },
    connection_success_panel: {
      summary: {
        successful_count: numberValue(first(connectionSummary, "successful_count", "successfulCount")),
        unsuccessful_count: numberValue(first(connectionSummary, "unsuccessful_count", "unsuccessfulCount")),
        by_state: record(first(connectionSummary, "by_state", "byState")) as Record<string, number>,
      },
      connections: array(connectionPanel.connections) as Modules["connection_success_panel"]["connections"],
    },
    suspicious_outbound_connections_panel: array(first(source, "suspicious_outbound_connections_panel", "suspiciousOutboundConnectionsPanel")) as Modules["suspicious_outbound_connections_panel"],
    ot_cross_segment_lines_panel: {
      lines: array(crossPanel.lines) as Modules["ot_cross_segment_lines_panel"]["lines"],
      subnet_pair_counts: array(first(crossPanel, "subnet_pair_counts", "subnetPairCounts")) as Modules["ot_cross_segment_lines_panel"]["subnet_pair_counts"],
      dst_subnet_counts: array(first(crossPanel, "dst_subnet_counts", "dstSubnetCounts")) as Modules["ot_cross_segment_lines_panel"]["dst_subnet_counts"],
      ot_device_counts: array(first(crossPanel, "ot_device_counts", "otDeviceCounts")) as Modules["ot_cross_segment_lines_panel"]["ot_device_counts"],
    },
    ot_devices: array(first(source, "ot_devices", "otDevices")) as Modules["ot_devices"],
    it_devices: array(first(source, "it_devices", "itDevices")) as Modules["it_devices"],
    edge_devices: array(first(source, "edge_devices", "edgeDevices")) as Modules["edge_devices"],
    ot_services: array(first(source, "ot_services", "otServices")) as Modules["ot_services"],
  };

  const requiredKeys = Object.keys(defaults) as (keyof Modules)[];
  for (const key of requiredKeys) {
    if (source[key] === undefined && source[toCamelCase(key)] === undefined) {
      warnings.push(`Missing modules.${key}; using an empty compatibility default.`);
    }
  }
  return normalized;
}

function toCamelCase(value: string): string {
  return value.replace(/_([a-z])/g, (_match, letter: string) => letter.toUpperCase());
}

export function normalizeElevadrReport(value: unknown): ReportCompatibilityResult {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Invalid eleVADR JSON report: expected a JSON object.");
  }
  const source = value as JsonRecord;
  const sourceVersion = stringValue(first(source, "report_version", "reportVersion"), "legacy-unversioned");
  const major = sourceVersion === "legacy-unversioned" ? "1" : sourceVersion.split(".")[0];
  if (!new Set(["1", "2"]).has(major)) {
    throw new Error(`Unsupported eleVADR report version '${sourceVersion}'. Supported report families are v1 and v2.`);
  }

  const executiveSummary = record(first(source, "executive_summary", "executiveSummary"));
  const modulesValue = source.modules;
  if (!modulesValue || typeof modulesValue !== "object" || Array.isArray(modulesValue)) {
    throw new Error("Invalid eleVADR JSON report: the report is missing a modules object.");
  }

  const warnings: string[] = [];
  const reportId = stringValue(first(source, "report_id", "reportId"), `legacy-${Date.now()}`);
  if (!first(source, "report_id", "reportId")) warnings.push("Report ID was missing; a temporary compatibility ID was assigned.");
  if (Object.keys(executiveSummary).length === 0) warnings.push("Executive summary was missing or empty.");

  const archInsights = record(first(source, "arch_insights", "archInsights"));
  const compatibility = {
    source_report_version: sourceVersion,
    normalized_report_version: CURRENT_REPORT_VERSION,
    migrated: major !== SUPPORTED_REPORT_MAJOR_VERSION || source.report_version === undefined,
    warnings,
  };

  const report = {
    ...source,
    report_version: CURRENT_REPORT_VERSION,
    report_id: reportId,
    executive_summary: executiveSummary as Record<string, string>,
    modules: normalizeModules(modulesValue, warnings),
    arch_insights: { ...archInsights, report_compatibility: compatibility },
  } as unknown as ElevadrReport;

  return {
    report,
    warnings,
    migrated: compatibility.migrated,
    sourceVersion,
  };
}

export function isCurrentReportVersion(version?: string): boolean {
  return typeof version === "string" && version.split(".")[0] === SUPPORTED_REPORT_MAJOR_VERSION;
}
