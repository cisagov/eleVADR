import {
  AssetRecord,
  AuthorizedControlAction,
  CaptureScope,
  CommunicationPair,
  InfrastructureEntry,
  NetworkSegment,
  SegmentPairRule,
} from "./types";

function quote(value: unknown): string {
  const text = value == null ? "" : String(value);
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

export function toCsv(headers: string[], rows: unknown[][]): string {
  return [headers, ...rows].map((row) => row.map(quote).join(",")).join("\r\n");
}

export function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [],
    field = "",
    quoted = false;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (quoted) {
      if (ch === '"' && text[i + 1] === '"') {
        field += '"';
        i += 1;
      } else if (ch === '"') quoted = false;
      else field += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === ",") {
      row.push(field);
      field = "";
    } else if (ch === "\n") {
      row.push(field.replace(/\r$/, ""));
      rows.push(row);
      row = [];
      field = "";
    } else field += ch;
  }
  row.push(field.replace(/\r$/, ""));
  if (row.some((value) => value.length) || rows.length === 0) rows.push(row);
  return rows;
}

export function captureScopeToCsv(scope: CaptureScope): string {
  return toCsv(
    ["internal_ics_only_expected", "dedicated_ot_sensor", "ipv4_only_expected"],
    [
      [
        scope.internalIcsOnlyExpected,
        scope.dedicatedOtSensor,
        scope.ipv4OnlyExpected,
      ],
    ],
  );
}
export function assetsToCsv(items: AssetRecord[]): string {
  return toCsv(
    [
      "ip",
      "hostname",
      "mac_addresses",
      "asset_type",
      "role",
      "segment",
      "purdue_level",
      "services",
      "ports",
    ],
    items.map((x) => [
      x.ip,
      x.hostname || "",
      x.macAddresses.join(";"),
      x.assetType,
      x.role,
      x.segment || "",
      x.purdueLevel || "",
      x.services.join(";"),
      x.ports.join(";"),
    ]),
  );
}
export function segmentsToCsv(items: NetworkSegment[]): string {
  return toCsv(
    [
      "name",
      "cidr",
      "role",
      "purdue_level",
      "vlan_id",
      "addressing",
      "dhcp_allowed",
      "ipv6_allowed",
    ],
    items.map((x) => [
      x.name,
      x.cidr,
      x.role,
      x.purdueLevel || "",
      x.vlanId ?? "",
      x.addressing,
      x.dhcpAllowed ?? "",
      x.ipv6Allowed ?? "",
    ]),
  );
}
export function infrastructureToCsv(items: InfrastructureEntry[]): string {
  return toCsv(
    ["type", "host_or_ip", "label"],
    items.map((x) => [x.kind, x.value, x.label || ""]),
  );
}
export function communicationsToCsv(items: CommunicationPair[]): string {
  return toCsv(
    [
      "source_ip",
      "destination_ip",
      "protocol",
      "destination_port",
      "service",
      "description",
    ],
    items.map((x) => [
      x.sourceIp,
      x.destinationIp,
      x.protocol || "",
      x.destinationPort ?? "",
      x.service || "",
      x.description || "",
    ]),
  );
}
export function segmentPairsToCsv(items: SegmentPairRule[]): string {
  return toCsv(
    ["source_segment", "destination_segment", "description"],
    items.map((x) => [
      x.sourceSegment,
      x.destinationSegment,
      x.description || "",
    ]),
  );
}
export function controlActionsToCsv(items: AuthorizedControlAction[]): string {
  return toCsv(
    [
      "protocol",
      "source",
      "destination",
      "allowed_operations",
      "allowed_function_codes",
      "description",
    ],
    items.map((x) => [
      x.protocol,
      x.source,
      x.destination,
      x.allowedOperations.join(";"),
      x.allowedFunctionCodes.join(";"),
      x.description || "",
    ]),
  );
}
export function ignoredHostsToCsv(items: string[]): string {
  return toCsv(
    ["host_or_ip"],
    items.map((x) => [x]),
  );
}
export function externalDestinationsToCsv(items: string[]): string {
  return toCsv(
    ["destination"],
    items.map((x) => [x]),
  );
}
export function modulePoliciesToCsv(
  items: Record<string, Record<string, unknown>>,
): string {
  return toCsv(
    ["module_id", "policy_json"],
    Object.entries(items)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([id, policy]) => [id, JSON.stringify(policy)]),
  );
}

function rowsByHeader(text: string): Record<string, string>[] {
  const rows = parseCsv(text);
  if (rows.length < 2) return [];
  const headers = rows[0].map((h) => h.trim().toLowerCase());
  return rows
    .slice(1)
    .filter((r) => r.some((v) => v.trim()))
    .map((r) => Object.fromEntries(headers.map((h, i) => [h, r[i] ?? ""])));
}
function boolValue(value: string): boolean | undefined {
  const v = value.trim().toLowerCase();
  return v === "true" || v === "yes" || v === "1"
    ? true
    : v === "false" || v === "no" || v === "0"
      ? false
      : undefined;
}
function numValue(value: string): number | undefined {
  const n = Number(value);
  return value.trim() !== "" && Number.isFinite(n) ? n : undefined;
}
function listValue(value: string): string[] {
  return (value || "")
    .split(";")
    .map((x) => x.trim())
    .filter(Boolean);
}
function codeValue(value: string): Array<number | string> {
  return listValue(value).map((x) =>
    /^0x[0-9a-f]+$/i.test(x)
      ? Number.parseInt(x, 16)
      : /^-?\d+$/.test(x)
        ? Number(x)
        : x,
  );
}

export function captureScopeFromCsv(text: string): CaptureScope {
  const row = rowsByHeader(text)[0] || {};
  return {
    internalIcsOnlyExpected:
      boolValue(row.internal_ics_only_expected || "") ?? false,
    dedicatedOtSensor: boolValue(row.dedicated_ot_sensor || "") ?? false,
    ipv4OnlyExpected: boolValue(row.ipv4_only_expected || "") ?? false,
  };
}
export function assetsFromCsv(text: string): AssetRecord[] {
  return rowsByHeader(text).map((r) => ({
    id: crypto.randomUUID(),
    ip: r.ip || "",
    hostname: r.hostname || "",
    macAddresses: listValue(r.mac_addresses || r.macs || r.mac || ""),
    assetType: r.asset_type || "Observed host",
    role: r.role || "Unknown",
    segment: r.segment || "",
    purdueLevel: r.purdue_level || "",
    services: listValue(r.services || ""),
    ports: listValue(r.ports || "")
      .map(Number)
      .filter(Number.isFinite),
    source: "imported",
    confidence: "high",
  }));
}
export function segmentsFromCsv(text: string): NetworkSegment[] {
  return rowsByHeader(text).map((r) => ({
    id: crypto.randomUUID(),
    name: r.name || "Imported segment",
    cidr: r.cidr || "",
    role: (["ot", "it", "dmz"].includes((r.role || "").toLowerCase())
      ? r.role.toLowerCase()
      : "unknown") as NetworkSegment["role"],
    purdueLevel: r.purdue_level || "",
    vlanId: numValue(r.vlan_id || ""),
    addressing: (["static", "dhcp", "mixed"].includes(
      (r.addressing || "").toLowerCase(),
    )
      ? r.addressing.toLowerCase()
      : "unknown") as NetworkSegment["addressing"],
    dhcpAllowed: boolValue(r.dhcp_allowed || ""),
    ipv6Allowed: boolValue(r.ipv6_allowed || ""),
    source: "imported",
    confidence: "high",
  }));
}
export function infrastructureFromCsv(text: string): InfrastructureEntry[] {
  return rowsByHeader(text).map((r) => {
    const raw = (r.type || r.kind || "dns").trim().toLowerCase();
    const kind = (
      ["dns", "ntp", "dhcp", "management"].includes(raw) ? raw : "management"
    ) as InfrastructureEntry["kind"];
    return {
      id: crypto.randomUUID(),
      kind,
      value: r.host_or_ip || r.value || r.host || r.ip || "",
      label: r.label || "",
      source: "imported",
      confidence: "high",
    };
  });
}
export function communicationsFromCsv(text: string): CommunicationPair[] {
  return rowsByHeader(text).map((r) => ({
    id: crypto.randomUUID(),
    sourceIp: r.source_ip || "",
    destinationIp: r.destination_ip || "",
    protocol: r.protocol || "",
    destinationPort: numValue(r.destination_port || ""),
    service: r.service || "",
    description: r.description || "",
    source: "imported",
    confidence: "high",
  }));
}
export function segmentPairsFromCsv(text: string): SegmentPairRule[] {
  return rowsByHeader(text).map((r) => ({
    id: crypto.randomUUID(),
    sourceSegment: r.source_segment || r.source || "",
    destinationSegment: r.destination_segment || r.destination || "",
    description: r.description || "",
  }));
}
export function controlActionsFromCsv(text: string): AuthorizedControlAction[] {
  return rowsByHeader(text).map((r) => ({
    id: crypto.randomUUID(),
    protocol: (["modbus", "dnp3", "s7comm", "enip"].includes(
      (r.protocol || "").toLowerCase(),
    )
      ? r.protocol.toLowerCase()
      : "modbus") as AuthorizedControlAction["protocol"],
    source: r.source || r.source_ip || "",
    destination: r.destination || r.destination_ip || "",
    allowedOperations: listValue(r.allowed_operations || r.operations || ""),
    allowedFunctionCodes: codeValue(
      r.allowed_function_codes || r.function_codes || "",
    ),
    description: r.description || "",
  }));
}
export function ignoredHostsFromCsv(text: string): string[] {
  return rowsByHeader(text)
    .map((r) => (r.host_or_ip || r.host || r.ip || "").trim())
    .filter(Boolean);
}
export function externalDestinationsFromCsv(text: string): string[] {
  return rowsByHeader(text)
    .map((r) =>
      (r.destination || r.host_or_ip || r.host || r.ip || r.cidr || "").trim(),
    )
    .filter(Boolean);
}
export function modulePoliciesFromCsv(
  text: string,
): Record<string, Record<string, unknown>> {
  const result: Record<string, Record<string, unknown>> = {};
  for (const r of rowsByHeader(text)) {
    const id = (r.module_id || r.module || "").trim();
    if (!id) continue;
    const policy: unknown = (() => {
      try {
        return JSON.parse(r.policy_json || r.policy || "{}");
      } catch {
        throw new Error(`Module policy for ${id} contains invalid JSON.`);
      }
    })();
    if (!policy || typeof policy !== "object" || Array.isArray(policy))
      throw new Error(`Module policy for ${id} must be a JSON object.`);
    result[id] = policy as Record<string, unknown>;
  }
  return result;
}

export function downloadText(
  filename: string,
  text: string,
  type = "text/csv",
): void {
  const blob = new Blob([text], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
