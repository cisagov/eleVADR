import React, { useMemo, useState } from "react";
import { ElevadrReport } from "../../types/Report";
import { InvestigationFilter, SelectedEntity } from "../../types/Investigation";
import "./FindingsPanel.css";
import Panel from "../Panel/Panel";
import ReportGuidance from "../ReportGuidance/ReportGuidance";
import PivotValue from "../PivotValue/PivotValue";

export interface DerivedFinding {
  id: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  summary: string;
  evidence: string;
  remediation: string;
  service?: string;
  ip?: string;
  destination?: string;
  count?: number;
  moduleId?: string;
  confidence?: string;
  detectionBasis?: string;
  inference?: string;
  observedEvidence?: string[];
  provenanceEvidence?: string[];
  contextEvidence?: string[];
  suppressionGuidance?: string[];
  tags?: string[];
}

type UnknownRecord = Record<string, unknown>;

function record(value: unknown): UnknownRecord | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as UnknownRecord)
    : undefined;
}

function textList(value: unknown): string[] {
  return Array.isArray(value) ? value.map(String).filter(Boolean) : [];
}

function sourceLabel(value: unknown): string {
  const source = String(value || "").toLowerCase();
  if (source === "zeek") return "observed-only";
  if (source === "imported" || source === "user") return "authoritative";
  return source || "unspecified";
}

function policyGuidance(moduleId: string): string[] {
  const prefix =
    "Do not suppress from observed traffic alone. Change Detection Context policy only after the behavior is verified as expected and approved.";
  const byModule: Record<string, string> = {
    cross_purdue_level_traffic:
      "If this direct path is intentionally permitted, add the exact approved source/destination segment pair under Communications & Exceptions, or correct an inaccurate Purdue assignment.",
    ipv6_traffic_ot:
      "If IPv6 is intentionally supported in this OT scope, clear the IPv4-only capture expectation and/or mark the applicable segment as IPv6-allowed.",
    ot_outbound_internet_any_protocol:
      "If the external peer is operationally required, add the exact destination to Approved External Destinations for this Detection Context.",
    large_outbound_http_uploads:
      "If this upload target and transfer pattern are approved, add the exact external destination to Approved External Destinations or use an approved module-specific exception in Advanced settings.",
    unusual_outbound_data_volume:
      "If the destination and transfer volume are expected, approve the exact external destination and, when justified, tune the module threshold in Advanced settings for this profile.",
    ot_external_dns_resolver:
      "If the resolver is sanctioned, define it as trusted DNS infrastructure rather than relying on observed DNS traffic.",
    ntp_internet_multi_dest_ot:
      "If the NTP peer is sanctioned, define it as trusted NTP infrastructure or an approved external destination.",
    ics_write_operations:
      "If the control operation is authorized, add the exact protocol/source/destination control path under Control Authorization.",
    modbus_dnp3_write_operations_outside_allowed_paths:
      "If the control operation is authorized, add the exact protocol/source/destination control path under Control Authorization.",
    enip_cip_write_session_abuses:
      "If the CIP write path is authorized, add the exact EtherNet/IP/CIP source/destination path under Control Authorization.",
    s7comm_unauthorized_write_stop:
      "If the S7 write/STOP path is authorized, add the exact S7comm source/destination path under Control Authorization.",
    unknown_rogue_devices:
      "If the device is known and managed, add it to the authoritative asset inventory. A Zeek-discovered asset alone must remain observed-only and must not suppress this detector.",
    rogue_dhcp_static_ot:
      "If DHCP is approved, update the applicable segment DHCP policy and identify the sanctioned DHCP infrastructure; observed DHCP alone is not policy.",
    quic_ot_segments:
      "If QUIC is explicitly approved in this OT segment, document the exception in the applicable Advanced module policy rather than treating observed QUIC as authorization.",
    public_to_public_traffic:
      "If public-to-public traffic is legitimately in sensor scope, correct the capture-scope expectation or define the intended scope exception.",
    new_ot_conversation_pair:
      "If the communication is part of the approved baseline, record the intended pair as authoritative context. Do not convert a Zeek-observed pair into authorization automatically.",
    arp_ip_mac_identity_change:
      "If the IP-to-MAC change is legitimate, update the authoritative Asset Inventory only after verifying the device identity. Do not trust the newly observed MAC merely because ARP reported it.",
    unexpected_dhcp_server:
      "If the DHCP server is sanctioned, add it explicitly as trusted DHCP infrastructure. Observed Offer/ACK traffic alone must not make it trusted.",
    ot_protocol_role_reversal:
      "If the role change is expected, document the narrowest module-specific policy or correct authoritative asset/segment context; do not treat observed originator behavior as authorization.",
    plc_rtu_peer_change:
      "If the new controller peer is legitimate, document the intended peer narrowly in the module policy after verification. A Zeek-observed pair alone remains evidence, not approval.",
    engineering_workstation_control_burst:
      "If the maintenance burst is expected, verify the engineering workstation and control paths, then tune the burst threshold/window only for this Detection Context. Existing Control Authorization does not automatically suppress burst behavior.",
    encrypted_session_fingerprint_change:
      "If the TLS fingerprint change is expected, verify the endpoint software/certificate/configuration change before tuning the baseline policy; observed fingerprints never become trusted configuration automatically.",
    remote_access_session_anomaly:
      "If the remote-access expansion is approved, verify the management source and intended OT targets, then scope the module policy narrowly rather than treating newly observed targets as authorized.",
    service_disappearance_replacement:
      "If the service replacement is planned, verify the asset change and update authoritative asset/service expectations; observed replacement traffic remains evidence, not policy.",
    polling_cadence_disruption:
      "If the cadence change is expected, confirm the control-system operating mode and tune the baseline/interval threshold only for the applicable Detection Context.",
    controller_communication_jitter:
      "If increased controller timing variance is operationally acceptable, validate the process/network condition before tuning the jitter threshold; observed jitter must not redefine the expected baseline automatically.",
  };
  return [
    prefix,
    byModule[moduleId] ||
      "If this behavior is an accepted exception, document the narrowest authoritative exception in Detection Context or the module's Advanced policy; avoid broad detector disablement when a specific exception is available.",
  ];
}

function contextEvidenceForFinding(
  report: ElevadrReport,
  item: UnknownRecord,
  devices: string[],
): string[] {
  const snapshot = record(report.arch_insights?.detection_context_snapshot);
  if (!snapshot)
    return ["No Detection Context snapshot is embedded in this report."];
  const details: string[] = [];
  const profileName = String(snapshot.name || "Unnamed Detection Context");
  details.push(`Profile: ${profileName}`);

  const scope = record(snapshot.captureScope);
  if (scope) {
    const scopeBits: string[] = [];
    if (scope.internalIcsOnlyExpected === true)
      scopeBits.push("internal ICS/OT-only expected");
    if (scope.dedicatedOtSensor === true) scopeBits.push("dedicated OT sensor");
    if (scope.ipv4OnlyExpected === true) scopeBits.push("IPv4-only expected");
    if (scopeBits.length)
      details.push(`Capture scope: ${scopeBits.join("; ")}`);
  }

  const assets = Array.isArray(snapshot.assets)
    ? snapshot.assets.map(record).filter((x): x is UnknownRecord => Boolean(x))
    : [];
  devices.slice(0, 4).forEach((ip) => {
    const asset = assets.find(
      (candidate) =>
        String(candidate.ip || "") === ip ||
        textList(candidate.ips).includes(ip),
    );
    if (!asset) return;
    const bits = [sourceLabel(asset.source)];
    if (asset.role) bits.push(`role ${String(asset.role)}`);
    if (asset.segment) bits.push(`segment ${String(asset.segment)}`);
    if (asset.purdueLevel) bits.push(String(asset.purdueLevel));
    details.push(`${ip}: ${bits.join(", ")}`);
  });

  const pairs = Array.isArray(snapshot.communicationPairs)
    ? snapshot.communicationPairs
        .map(record)
        .filter((x): x is UnknownRecord => Boolean(x))
    : [];
  const rawPairs = Array.isArray(item.connection_pairs)
    ? item.connection_pairs
        .map(record)
        .filter((x): x is UnknownRecord => Boolean(x))
    : [];
  const matchedPair = rawPairs.find((pair) =>
    pairs.some(
      (candidate) =>
        String(candidate.sourceIp || "") ===
          String(pair.source || pair.src || "") &&
        String(candidate.destinationIp || "") ===
          String(pair.destination || pair.dst || ""),
    ),
  );
  if (matchedPair) {
    const existing = pairs.find(
      (candidate) =>
        String(candidate.sourceIp || "") ===
          String(matchedPair.source || matchedPair.src || "") &&
        String(candidate.destinationIp || "") ===
          String(matchedPair.destination || matchedPair.dst || ""),
    );
    if (existing)
      details.push(
        `Communication pair is present as ${sourceLabel(existing.source)} context; this is evidence/baseline context, not control authorization.`,
      );
  }

  const moduleId = String(item.module_id || "");
  const approved = textList(snapshot.approvedExternalDestinations);
  if (
    [
      "ot_outbound_internet_any_protocol",
      "large_outbound_http_uploads",
      "unusual_outbound_data_volume",
      "ot_external_dns_resolver",
      "ntp_internet_multi_dest_ot",
    ].includes(moduleId)
  ) {
    const destinations = rawPairs
      .map((pair) => String(pair.destination || pair.dst || ""))
      .filter(Boolean);
    const match = destinations.find((ip) => approved.includes(ip));
    details.push(
      match
        ? `Approved external destination matched: ${match}`
        : "No matching Approved External Destination is configured for the displayed peer(s).",
    );
  }

  const authorized = Array.isArray(snapshot.authorizedControlActions)
    ? snapshot.authorizedControlActions
    : [];
  if (
    [
      "ics_write_operations",
      "modbus_dnp3_write_operations_outside_allowed_paths",
      "enip_cip_write_session_abuses",
      "s7comm_unauthorized_write_stop",
      "engineering_workstation_control_burst",
    ].includes(moduleId)
  ) {
    details.push(
      authorized.length
        ? `${authorized.length} explicit Control Authorization entr${authorized.length === 1 ? "y is" : "ies are"} configured; review whether one exactly matches this path.`
        : "No explicit Control Authorization entries are configured.",
    );
  }
  return details;
}

function observedEvidenceForFinding(
  item: UnknownRecord,
  devices: string[],
  services: string[],
): string[] {
  const evidence: string[] = [];
  const pairs = Array.isArray(item.connection_pairs)
    ? item.connection_pairs
        .map(record)
        .filter((x): x is UnknownRecord => Boolean(x))
    : [];
  pairs.slice(0, 4).forEach((pair) => {
    const src = String(pair.source || pair.src || "?");
    const dst = String(pair.destination || pair.dst || "?");
    const port = pair.port == null ? "" : `:${String(pair.port)}`;
    const proto = String(pair.protocol || pair.service || "").trim();
    evidence.push(`${src} → ${dst}${port}${proto ? ` (${proto})` : ""}`);
  });
  const flows = Array.isArray(item.flows) ? item.flows : [];
  if (flows.length)
    evidence.push(
      `${flows.length} retained flow/event record${flows.length === 1 ? "" : "s"} support this finding.`,
    );
  if (!pairs.length && devices.length)
    evidence.push(
      `Observed device${devices.length === 1 ? "" : "s"}: ${devices.slice(0, 5).join(", ")}`,
    );
  if (services.length)
    evidence.push(
      `Observed service${services.length === 1 ? "" : "s"}: ${services.slice(0, 5).join(", ")}`,
    );
  if (!evidence.length)
    evidence.push(
      "The detector reported a finding but did not retain flow-level evidence in this report.",
    );
  return evidence;
}

function provenanceEvidenceForFinding(item: UnknownRecord): string[] {
  const provenance =
    record(item.provenance) || record(record(item.metadata)?.zeek_provenance);
  const sources = Array.isArray(provenance?.sources) ? provenance.sources : [];
  return sources
    .map((rawSource) => {
      const source = record(rawSource);
      if (!source) return "";
      const logType = String(source.log_type || "Zeek log");
      const recordIndex =
        source.record_index == null
          ? ""
          : ` record ${String(source.record_index)}`;
      const fields = record(source.fields);
      const entries = fields ? Object.entries(fields) : [];
      const renderedFields = entries.length
        ? `: ${entries
            .slice(0, 8)
            .map(([key, value]) => `${key}=${String(value)}`)
            .join(
              ", ",
            )}${entries.length > 8 ? `, +${entries.length - 8} more` : ""}`
        : "";
      return `${logType}${recordIndex}${renderedFields}`;
    })
    .filter(Boolean);
}

function remediationFor(
  kind: "service" | "outbound" | "segment",
  service?: string,
): string {
  if (kind === "outbound")
    return "Validate the destination and business need, then restrict egress to approved destinations and investigate the source asset if the communication is unexpected.";
  if (kind === "segment")
    return "Confirm the flow is required by the control-system architecture and enforce the narrowest allowed source, destination, service, and direction at the segmentation boundary.";
  return `Validate whether ${service || "the service"} is operationally required. Disable unused exposure, restrict access to authorized peers, and prefer authenticated/encrypted alternatives where supported.`;
}

export function deriveFindings(report: ElevadrReport): DerivedFinding[] {
  const findings: DerivedFinding[] = [];
  const detectorFindings = report.arch_insights?.detector_findings;
  if (Array.isArray(detectorFindings)) {
    detectorFindings.forEach((raw, index) => {
      if (!raw || typeof raw !== "object") return;
      const item = raw as Record<string, unknown>;
      const rawSeverity = String(
        item.severity || "informational",
      ).toLowerCase();
      const severity: DerivedFinding["severity"] =
        rawSeverity === "informational"
          ? "info"
          : ["critical", "high", "medium", "low"].includes(rawSeverity)
            ? (rawSeverity as DerivedFinding["severity"])
            : "info";
      const devices = Array.isArray(item.devices)
        ? item.devices.map(String)
        : [];
      const services = Array.isArray(item.services)
        ? item.services.map(String)
        : [];
      const pairs = Array.isArray(item.connection_pairs)
        ? item.connection_pairs
        : [];
      const firstPair = pairs.find(
        (pair) => pair && typeof pair === "object",
      ) as Record<string, unknown> | undefined;
      const moduleId = String(item.module_id || "detector");
      const detectionBasis = String(
        item.detection_basis ||
          record(item.metadata)?.detection_basis ||
          "derived",
      );
      const confidence = String(
        item.confidence || record(item.metadata)?.confidence || "unspecified",
      );
      const observedEvidence = observedEvidenceForFinding(
        item,
        devices,
        services,
      );
      findings.push({
        id: `detector:${String(item.module_id || "module")}:${index}`,
        severity,
        title: String(item.title || item.module_id || "Detector finding"),
        summary: String(item.summary || "Detector module produced a finding."),
        evidence: `${moduleId} · ${detectionBasis} · ${confidence} confidence`,
        remediation:
          "Validate the retained evidence and the authoritative Detection Context before changing policy. If the behavior is not expected, investigate the source asset and enforce the narrowest appropriate network or control restriction.",
        service: services[0],
        ip:
          devices[0] ||
          (firstPair
            ? String(firstPair.source || firstPair.src || "")
            : undefined),
        destination: firstPair
          ? String(firstPair.destination || firstPair.dst || "")
          : undefined,
        count:
          Array.isArray(item.flows) && item.flows.length
            ? item.flows.length
            : 1,
        moduleId,
        confidence,
        detectionBasis,
        inference: String(
          item.summary || "Detector module produced a finding.",
        ),
        observedEvidence,
        provenanceEvidence: provenanceEvidenceForFinding(item),
        contextEvidence: contextEvidenceForFinding(report, item, devices),
        suppressionGuidance: policyGuidance(moduleId),
        tags: textList(item.tags),
      });
    });
  }
  Object.entries(
    report.modules.service_risk_breakdown_panel.risk_category_services,
  ).forEach(([risk, services]) => {
    const normalized = risk.toLowerCase();
    const severity: DerivedFinding["severity"] = /critical|severe/.test(
      normalized,
    )
      ? "critical"
      : /high|danger|remote/.test(normalized)
        ? "high"
        : /medium|moderate|cleartext|legacy/.test(normalized)
          ? "medium"
          : /low/.test(normalized)
            ? "low"
            : "info";
    services.forEach((service) =>
      findings.push({
        id: `risk:${risk}:${service}`,
        severity,
        title: `${risk} service exposure`,
        summary: `${service} is associated with the ${risk} risk category.`,
        evidence: "Service risk classification",
        remediation: remediationFor("service", service),
        service,
        confidence: "contextual",
        detectionBasis: "report classification",
        inference: `${service} is categorized by the report as ${risk}.`,
        observedEvidence: [`Service observed in report inventory: ${service}`],
        contextEvidence: [
          "This finding is derived from report service-risk classification rather than a detector-specific Detection Context assertion.",
        ],
        suppressionGuidance: [
          "Confirm the service classification and operational requirement before accepting the exposure. Prefer a narrow documented exception over removing evidence.",
        ],
      }),
    );
  });
  report.modules.suspicious_outbound_connections_panel.forEach((item, index) =>
    findings.push({
      id: `outbound:${index}`,
      severity: item.count >= 20 ? "high" : "medium",
      title: "Suspicious outbound communication",
      summary: `${item["src_endpoint.ip"]} communicated with ${item["dst_endpoint.ip"]}:${item["dst_endpoint.port"]} using ${item["service.name"]}.`,
      evidence: "Suspicious outbound connections · report-derived",
      remediation: remediationFor("outbound"),
      service: item["service.name"],
      ip: item["src_endpoint.ip"],
      destination: item["dst_endpoint.ip"],
      count: item.count,
      confidence: "contextual",
      detectionBasis: "report aggregation",
      inference:
        "The report aggregation classified this communication as suspicious outbound activity.",
      observedEvidence: [
        `${item["src_endpoint.ip"]} → ${item["dst_endpoint.ip"]}:${item["dst_endpoint.port"]} (${item["service.name"]})`,
        `${item.count} observed connection(s)`,
      ],
      contextEvidence: [
        "Review Approved External Destinations and authoritative asset roles in Detection Context.",
      ],
      suppressionGuidance: [
        "If the peer is verified and approved, add the exact destination to Approved External Destinations. Do not treat observation alone as approval.",
      ],
    }),
  );
  report.modules.ot_cross_segment_lines_panel.lines
    .slice(0, 80)
    .forEach((item, index) =>
      findings.push({
        id: `cross:${index}`,
        severity: item.count >= 50 ? "medium" : "low",
        title: "OT cross-segment communication",
        summary: `${item["src_endpoint.ip"]} → ${item["dst_endpoint.ip"]}:${item["dst_endpoint.port"]} (${item["service.name"]}) crosses observed network segments.`,
        evidence: "OT segmentation analysis · report-derived",
        remediation: remediationFor("segment"),
        service: item["service.name"],
        ip: item["src_endpoint.ip"],
        destination: item["dst_endpoint.ip"],
        count: item.count,
        confidence: "contextual",
        detectionBasis: "report aggregation",
        inference:
          "The report identified an observed communication crossing OT network segments.",
        observedEvidence: [
          `${item["src_endpoint.ip"]} → ${item["dst_endpoint.ip"]}:${item["dst_endpoint.port"]} (${item["service.name"]})`,
          `${item.count} observed connection(s)`,
        ],
        contextEvidence: [
          "Review the source/destination segment definitions and Allowed Segment Pairs in Detection Context.",
        ],
        suppressionGuidance: [
          "If the path is intentionally permitted, add the exact approved segment pair. Do not infer permission from observed traffic.",
        ],
      }),
    );
  const rank = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
  return findings.sort(
    (a, b) =>
      rank[b.severity] - rank[a.severity] || (b.count || 0) - (a.count || 0),
  );
}

function downloadCsv(findings: DerivedFinding[], reportId: string) {
  const headers = [
    "severity",
    "title",
    "source_ip",
    "destination_ip",
    "service",
    "observations",
    "confidence",
    "detection_basis",
    "evidence",
    "remediation",
  ];
  const escape = (value: unknown) =>
    `"${String(value ?? "").replace(/"/g, '""')}"`;
  const rows = findings.map((finding) =>
    [
      finding.severity,
      finding.title,
      finding.ip,
      finding.destination,
      finding.service,
      finding.count,
      finding.confidence,
      finding.detectionBasis,
      finding.evidence,
      finding.remediation,
    ]
      .map(escape)
      .join(","),
  );
  const blob = new Blob([[headers.join(","), ...rows].join("\n")], {
    type: "text/csv;charset=utf-8",
  });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `elevadr-findings-${reportId}.csv`;
  link.click();
  URL.revokeObjectURL(url);
}

interface Props {
  report: ElevadrReport;
  filters: InvestigationFilter[];
  onFilter: (filter: InvestigationFilter) => void;
  onSelect: (entity: SelectedEntity) => void;
  onClearFilters?: () => void;
}
const FindingsPanel: React.FC<Props> = ({
  report,
  filters,
  onFilter,
  onSelect,
  onClearFilters,
}) => {
  const [limit, setLimit] = useState(12);
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("all");
  const [sort, setSort] = useState<"priority" | "count" | "title">("priority");
  const findings = useMemo(() => deriveFindings(report), [report]);
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    const result = findings.filter((finding) => {
      if (severity !== "all" && finding.severity !== severity) return false;
      if (
        q &&
        ![
          finding.title,
          finding.summary,
          finding.service,
          finding.ip,
          finding.destination,
          finding.evidence,
        ].some((value) =>
          String(value || "")
            .toLowerCase()
            .includes(q),
        )
      )
        return false;
      return filters.every((filter) => {
        if (filter.key === "service") return finding.service === filter.value;
        if (filter.key === "risk")
          return (
            finding.severity === filter.value.toLowerCase() ||
            finding.title.toLowerCase().includes(filter.value.toLowerCase())
          );
        if (filter.key === "ip")
          return (
            finding.ip === filter.value ||
            finding.destination === filter.value ||
            finding.summary.includes(filter.value)
          );
        if (filter.key === "subnet") {
          const ips = [finding.ip, finding.destination].filter(
            Boolean,
          ) as string[];
          const devices = [
            ...report.modules.ot_devices,
            ...report.modules.it_devices,
            ...report.modules.edge_devices,
          ];
          return devices.some((device) => {
            const deviceIps = [
              ...(device.ip_addresses || []),
              ...(device.ipv4_ips || []),
              ...(device.ipv6_ips || []),
            ];
            const subnets = [
              ...(device.subnets || []),
              ...(device.ipv4_subnets || []),
              ...(device.ipv6_subnets || []),
            ];
            return (
              ips.some((ip) => deviceIps.includes(ip)) &&
              subnets.includes(filter.value)
            );
          });
        }
        return true;
      });
    });
    if (sort === "count")
      result.sort((a, b) => (b.count || 0) - (a.count || 0));
    if (sort === "title") result.sort((a, b) => a.title.localeCompare(b.title));
    return result;
  }, [findings, filters, query, severity, sort, report]);
  const severityCounts = useMemo(
    () =>
      findings.reduce<Record<string, number>>((acc, finding) => {
        acc[finding.severity] = (acc[finding.severity] || 0) + 1;
        return acc;
      }, {}),
    [findings],
  );

  return (
    <Panel id="prioritized-evidence" title="Prioritized Evidence">
      <section
        className="findings-console findings-console-inner"
        aria-label="Findings table and filters"
      >
        <div className="findings-head">
          <div className="findings-context">Severity Summary</div>
          <div className="severity-summary">
            {(["critical", "high", "medium", "low"] as const).map((item) => (
              <button
                key={item}
                type="button"
                className={`severity-pill severity-${item}`}
                onClick={() => {
                  setSeverity(item);
                  onFilter({ key: "risk", value: item, label: "Risk" });
                }}
                aria-pressed={filters.some(
                  (filter) => filter.key === "risk" && filter.value === item,
                )}
                title={`Filter report by ${item} severity`}
              >
                <strong>{severityCounts[item] || 0}</strong>
                {item}
              </button>
            ))}
          </div>
        </div>
        <div className="findings-controls">
          <label className="findings-search">
            <span>Search findings</span>
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="IP, service, evidence, finding…"
            />
          </label>
          <label>
            <span>Severity</span>
            <select
              value={severity}
              onChange={(event) => setSeverity(event.target.value)}
            >
              <option value="all">All severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
          </label>
          <label>
            <span>Sort</span>
            <select
              value={sort}
              onChange={(event) => setSort(event.target.value as typeof sort)}
            >
              <option value="priority">Priority</option>
              <option value="count">Observation count</option>
              <option value="title">Finding name</option>
            </select>
          </label>
          <button
            type="button"
            className="findings-export"
            onClick={() => downloadCsv(filtered, report.report_id)}
          >
            Export CSV
          </button>
        </div>
        {filtered.length > 0 ? (
          <>
            <div className="findings-table-wrap">
              <table className="findings-table">
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Finding</th>
                    <th>Asset / service</th>
                    <th>Evidence</th>
                    <th>Count</th>
                    <th>
                      <span className="sr-only">Action</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.slice(0, limit).map((finding) => (
                    <tr
                      key={finding.id}
                      className="clickable-row"
                      onClick={() =>
                        onSelect({ type: "finding", id: finding.id })
                      }
                      tabIndex={0}
                      role="button"
                      onKeyDown={(event) => {
                        if (event.key === "Enter" || event.key === " ") {
                          event.preventDefault();
                          onSelect({ type: "finding", id: finding.id });
                        }
                      }}
                    >
                      <td>
                        <span
                          className={`severity-badge severity-${finding.severity}`}
                        >
                          {finding.severity}
                        </span>
                      </td>
                      <td>
                        <div className="finding-title">
                          {finding.title}
                          <small>{finding.summary}</small>
                        </div>
                      </td>
                      <td>
                        <div className="finding-entities">
                          {finding.ip && (
                            <PivotValue
                              filter={{
                                key: "ip",
                                value: finding.ip!,
                                label: "Device",
                              }}
                              filters={filters}
                              onFilter={onFilter}
                            >
                              {finding.ip}
                            </PivotValue>
                          )}
                          {finding.service && (
                            <PivotValue
                              filter={{
                                key: "service",
                                value: finding.service!,
                                label: "Service",
                              }}
                              filters={filters}
                              onFilter={onFilter}
                            >
                              {finding.service}
                            </PivotValue>
                          )}
                        </div>
                      </td>
                      <td>
                        <div className="finding-evidence-cell">
                          <span>
                            {finding.detectionBasis || finding.evidence}
                          </span>
                          {finding.confidence && (
                            <small
                              className={`confidence-badge confidence-${finding.confidence.toLowerCase()}`}
                            >
                              {finding.confidence} confidence
                            </small>
                          )}
                        </div>
                      </td>
                      <td>{finding.count?.toLocaleString() ?? "—"}</td>
                      <td>
                        <button
                          type="button"
                          className="inspect-button"
                          onClick={(event) => {
                            event.stopPropagation();
                            onSelect({ type: "finding", id: finding.id });
                          }}
                        >
                          Why flagged?
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="findings-footer">
              <span>
                Showing {Math.min(limit, filtered.length)} of {filtered.length}{" "}
                matching findings
              </span>
              {filtered.length > limit && (
                <button
                  type="button"
                  className="show-more-findings"
                  onClick={() => setLimit((value) => value + 20)}
                >
                  Show more findings
                </button>
              )}
            </div>
          </>
        ) : (
          <ReportGuidance
            title="No findings match the current view"
            note={`${findings.length.toLocaleString()} finding${findings.length === 1 ? " exists" : "s exist"} in the report before the current search, severity, and investigation filters are applied.`}
            actions={[
              {
                label: "Clear finding filters",
                primary: true,
                onClick: () => {
                  setQuery("");
                  setSeverity("all");
                  onClearFilters?.();
                },
              },
            ]}
          >
            <p>
              This is a filtered empty state, not a zero-finding analysis
              result. Clear the filters to return to the complete finding set.
            </p>
          </ReportGuidance>
        )}
      </section>
    </Panel>
  );
};
export default FindingsPanel;
