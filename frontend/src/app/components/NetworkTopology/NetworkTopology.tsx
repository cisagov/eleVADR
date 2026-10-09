import React, { useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { ElevadrReport, Device } from "../../types/Report";
import { InvestigationFilter, SelectedEntity } from "../../types/Investigation";
import "./NetworkTopology.css";
import { authApiUrl, getAccessToken } from "../../services/authService";

type DeviceType = "OT" | "IT" | "Edge" | "Unknown";
type Node = {
  id: string;
  type: DeviceType;
  x: number;
  y: number;
  degree: number;
  manufacturer?: string | null;
  services: string[];
  subnet: string;
  findingCount: number;
  roleGroup: string;
  purdueLevel: string;
};
type Edge = {
  id: string;
  source: string;
  target: string;
  service: string;
  count: number;
  suspicious: boolean;
  findingRelated: boolean;
};
type GraphQuery = {
  type?: string;
  subnet?: string;
  purdueLevel?: string;
  roleGroup?: string;
  service?: string;
  suspicious?: boolean;
  findingRelated?: boolean;
  minCount?: number;
  startAsset?: string;
  maxHops?: number;
  direction?: "both" | "outbound" | "inbound";
};
type SavedGraphQuery = { id: string; name: string; query: GraphQuery; updatedAt: string };
const GRAPH_QUERY_TEMPLATES: { name: string; query: GraphQuery }[] = [
  { name: "Suspicious communications", query: { suspicious: true } },
  { name: "Finding-related communications", query: { findingRelated: true } },
  { name: "PLC / OT assets", query: { type: "OT" } },
  { name: "High-volume links", query: { minCount: 10 } },
  { name: "Observed two-hop neighborhood", query: { maxHops: 2 } },
  { name: "PLC / OT two-hop relationships", query: { type: "OT", maxHops: 2 } },
  { name: "Suspicious two-hop relationships", query: { suspicious: true, maxHops: 2 } },
];
type Point = { x: number; y: number };
type Viewport = { x: number; y: number; scale: number };
type LabelMode = "minimal" | "full" | "off";
type LayoutMode = "class" | "subnet" | "role" | "purdue";
export type NetworkTopologyState = {
  preset: "simple" | "risk" | "full";
  layoutMode: LayoutMode;
  labelMode: LabelMode;
  suspiciousOnly: boolean;
  findingOnly: boolean;
  hideIsolated: boolean;
  neighborsOnly: boolean;
  focusedNodeId: string | null;
  viewport: Viewport;
  positions: Record<string, Point>;
};
type GroupRegion = {
  key: string;
  label: string;
  x: number;
  y: number;
  width: number;
  height: number;
  count: number;
};

const WIDTH = 1040;
const HEIGHT = 610;
const MIN_ZOOM = 0.45;
const MAX_ZOOM = 2.8;
const STATE_PERSIST_DELAY_MS = 180;
const EDGE_LIMITS = { simple: 45, risk: 100, full: 140 } as const;
const NODE_LIMITS = { simple: 55, risk: 90, full: 150 } as const;

function deviceIps(device: Device): string[] {
  return device.ip_addresses || device.ipv4_ips || [];
}

function classify(
  ip: string,
  report: ElevadrReport,
): { type: DeviceType; device?: Device } {
  const groups: [DeviceType, Device[]][] = [
    ["OT", report.modules.ot_devices],
    ["IT", report.modules.it_devices],
    ["Edge", report.modules.edge_devices],
  ];
  for (const [type, devices] of groups) {
    const device = devices.find((item) => deviceIps(item).includes(ip));
    if (device) return { type, device };
  }
  return { type: "Unknown" };
}

function serviceList(device?: Device): string[] {
  if (!device) return [];
  return [
    ...new Set([
      ...(device.incoming_services || []),
      ...(device.sent_services || []),
    ]),
  ].filter(Boolean);
}

function defaultPosition(
  type: DeviceType,
  index: number,
  total: number,
): Point {
  const columns: Record<DeviceType, { x: number; y: number; spread: number }> =
    {
      IT: { x: 185, y: 285, spread: 215 },
      Edge: { x: 520, y: 285, spread: 190 },
      OT: { x: 855, y: 285, spread: 215 },
      Unknown: { x: 520, y: 505, spread: 120 },
    };
  const base = columns[type];
  const safeTotal = Math.max(total, 1);
  const angle = (Math.PI * 2 * index) / safeTotal - Math.PI / 2;
  const radius = Math.min(base.spread, 42 + safeTotal * 8);
  return {
    x: base.x + Math.cos(angle) * radius,
    y: base.y + Math.sin(angle) * radius * 0.72,
  };
}


// Compare report-derived observations, never inferred physical links.
type ComparisonEdge = { source: string; target: string; service: string; count: number };
type ComparisonSnapshot = { assets: Set<string>; edges: Map<string, ComparisonEdge> };
function comparisonSnapshot(report: ElevadrReport): ComparisonSnapshot {
  const assets = new Set<string>();
  const edges = new Map<string, ComparisonEdge>();
  const modules = report.modules;
  for (const device of [...(modules.ot_devices || []), ...(modules.it_devices || []), ...(modules.edge_devices || [])]) {
    for (const ip of deviceIps(device)) if (ip) assets.add(ip);
  }
  const add = (source: string, target: string, service: string, count: number) => {
    if (!source || !target || source === target) return;
    assets.add(source); assets.add(target);
    const name = service || "Unknown service";
    const key = JSON.stringify([source, target, name]);
    const previous = edges.get(key);
    edges.set(key, { source, target, service: name, count: (previous?.count || 0) + count });
  };
  for (const line of modules.ot_cross_segment_lines_panel?.lines || []) {
    add(line["src_endpoint.ip"], line["dst_endpoint.ip"], line["service.name"], Number(line.count) || 1);
  }
  for (const line of modules.suspicious_outbound_connections_panel || []) {
    add(line["src_endpoint.ip"], line["dst_endpoint.ip"], line["service.name"], Number(line.count) || 1);
  }
  for (const line of modules.connection_success_panel?.connections || []) {
    add(line["src_endpoint.ip"] || "", line["dst_endpoint.ip"] || "", line["service.name"] || line["connection_info.protocol_name"] || (line["dst_endpoint.port"] ? `Port ${line["dst_endpoint.port"]}` : "Connection"), 1);
  }
  return { assets, edges };
}

type ComparisonChange = { key: string; status: "New" | "Not observed" | "Count changed"; edge: ComparisonEdge; baselineCount: number; currentCount: number };
type ComparisonFinding = { title: string; severity: string };
function comparisonFindings(report: ElevadrReport, source: string, target: string): ComparisonFinding[] {
  const findings = report.arch_insights?.detector_findings;
  if (!Array.isArray(findings)) return [];
  return findings.flatMap((raw): ComparisonFinding[] => {
    if (!raw || typeof raw !== "object") return [];
    const item = raw as Record<string, unknown>;
    const addresses = new Set<string>();
    if (Array.isArray(item.devices)) for (const ip of item.devices) if (typeof ip === "string") addresses.add(ip);
    for (const field of ["connection_pairs", "flows"]) {
      const records = item[field];
      if (!Array.isArray(records)) continue;
      for (const record of records) {
        if (!record || typeof record !== "object") continue;
        const pair = record as Record<string, unknown>;
        for (const value of [pair.source, pair.src, pair.destination, pair.dst, pair["src_endpoint.ip"], pair["dst_endpoint.ip"]]) {
          if (typeof value === "string") addresses.add(value);
        }
      }
    }
    if (!addresses.has(source) && !addresses.has(target)) return [];
    return [{ title: String(item.title || item.name || item.module || "Detection finding"), severity: String(item.severity || "Unspecified") }];
  });
}
function comparisonCsvCell(value: string | number): string {
  return `"${String(value).replace(/"/g, '""')}"`;
}
function downloadComparison(name: string, contents: string, mime: string): void {
  const url = URL.createObjectURL(new Blob([contents], { type: mime }));
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function compareTopology(baseline: ElevadrReport, current: ElevadrReport) {
  const before = comparisonSnapshot(baseline);
  const after = comparisonSnapshot(current);
  const newAssets = [...after.assets].filter((ip) => !before.assets.has(ip)).sort();
  const missingAssets = [...before.assets].filter((ip) => !after.assets.has(ip)).sort();
  const changes: ComparisonChange[] = [];
  for (const [key, edge] of after.edges) {
    const prior = before.edges.get(key);
    if (!prior) changes.push({ key, status: "New", edge, baselineCount: 0, currentCount: edge.count });
    else if (prior.count !== edge.count) changes.push({ key, status: "Count changed", edge, baselineCount: prior.count, currentCount: edge.count });
  }
  for (const [key, edge] of before.edges) if (!after.edges.has(key)) {
    changes.push({ key, status: "Not observed", edge, baselineCount: edge.count, currentCount: 0 });
  }
  return { newAssets, missingAssets, changes };
}

interface Props {
  report: ElevadrReport;
  filters: InvestigationFilter[];
  onFilter: (filter: InvestigationFilter) => void;
  onSelect: (entity: SelectedEntity) => void;
  onStateChange?: (state: NetworkTopologyState) => void;
}

const DEFAULT_VIEWPORT: Viewport = { x: 0, y: 0, scale: 1 };

const NetworkTopology: React.FC<Props> = ({
  report,
  filters,
  onFilter,
  onSelect,
  onStateChange,
}) => {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const cardRef = useRef<HTMLElement | null>(null);
  const dragRef = useRef<{
    id: string;
    moved: boolean;
    startClientX: number;
    startClientY: number;
  } | null>(null);
  const panRef = useRef<{
    startX: number;
    startY: number;
    viewport: Viewport;
    moved: boolean;
  } | null>(null);

  const [comparisonOpen, setComparisonOpen] = useState(false);
  const [baselineReport, setBaselineReport] = useState<ElevadrReport | null>(null);
  const [baselineName, setBaselineName] = useState("");
  const [comparisonError, setComparisonError] = useState("");
  const [comparisonPage, setComparisonPage] = useState(0);
  const [comparisonOverlay, setComparisonOverlay] = useState(true);
  const [selectedComparisonKey, setSelectedComparisonKey] = useState<string | null>(null);
  const [comparisonFilter, setComparisonFilter] = useState<"All" | ComparisonChange["status"]>("All");
  const comparison = useMemo(() => baselineReport ? compareTopology(baselineReport, report) : null, [baselineReport, report]);
  const [comparisonFindingsOnly, setComparisonFindingsOnly] = useState(false);
  const [comparisonQueryOnly, setComparisonQueryOnly] = useState(false);
  const [comparisonSavedName, setComparisonSavedName] = useState("");
  type SavedComparison = { id: string; name: string; currentReportId: string; baselineId: string; filter: "All" | ComparisonChange["status"]; findingsOnly: boolean; queryOnly: boolean; updatedAt: string };
  const [savedComparisons, setSavedComparisons] = useState<SavedComparison[]>([]);
  const [comparisonBusy, setComparisonBusy] = useState(false);
  const [comparisonSavedId, setComparisonSavedId] = useState<string | null>(null);
  const comparisonRequest = async (method: string, path: string, body?: unknown) => {
    const token = getAccessToken();
    if (!token) throw new Error("Sign in to manage saved comparisons.");
    const response = await fetch(authApiUrl(path), {
      method, headers: { Authorization: `Bearer ${token}`, ...(body ? { "Content-Type": "application/json" } : {}) },
      body: body ? JSON.stringify(body) : undefined, cache: "no-store",
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.message || `Comparison service returned HTTP ${response.status}`);
    return data;
  };
  const refreshComparisons = async () => {
    try {
      const data = await comparisonRequest("GET", "/api/v1/topology-comparisons");
      setSavedComparisons(Array.isArray(data.comparisons) ? data.comparisons : []);
    } catch (error) { setComparisonError(error instanceof Error ? error.message : "Cannot load saved comparisons"); }
  };
  useEffect(() => { if (comparisonOpen) void refreshComparisons(); }, [comparisonOpen]);
  const saveComparisonSettings = async () => {
    if (!comparisonSavedName.trim() || !baselineReport) return;
    setComparisonBusy(true);
    try {
      const payload = {
        id: comparisonSavedId || undefined, name: comparisonSavedName.trim(),
        currentReportId: String(report.report_id || ""),
        baselineId: String(baselineReport.report_id || baselineName),
        filter: comparisonFilter, findingsOnly: comparisonFindingsOnly, queryOnly: comparisonQueryOnly,
      };
      const data = await comparisonRequest("POST", "/api/v1/topology-comparisons", payload);
      setComparisonSavedId(data.comparison.id);
      await refreshComparisons(); setComparisonError("");
    } catch (error) { setComparisonError(error instanceof Error ? error.message : "Cannot save comparison"); }
    finally { setComparisonBusy(false); }
  };
  // Restore the baseline from the owner-scoped report store when possible.
  // Never silently compare a saved configuration against a different report.
  const recallComparisonSettings = async (item: SavedComparison) => {
    setComparisonSavedId(item.id);
    setComparisonSavedName(item.name);
    setComparisonFilter(item.filter);
    setComparisonFindingsOnly(item.findingsOnly);
    setComparisonQueryOnly(item.queryOnly);
    setComparisonPage(0);
    setSelectedComparisonKey(null);
    if (item.currentReportId !== String(report.report_id || "")) {
      setComparisonError("Load the saved comparison's current report before recalling its baseline.");
      return;
    }
    if (baselineReport && String(baselineReport.report_id || "") === item.baselineId) {
      setComparisonError("");
      return;
    }
    setComparisonBusy(true);
    try {
      const data = await comparisonRequest("GET", `/api/v1/reports/${encodeURIComponent(item.baselineId)}`);
      const candidate = data.report as ElevadrReport | undefined;
      if (!candidate?.modules?.connection_success_panel || !candidate.modules?.ot_cross_segment_lines_panel ||
          !Array.isArray(candidate.modules?.ot_devices) || String(candidate.report_id || "") !== item.baselineId) {
        throw new Error("The saved baseline report is unavailable or has incompatible topology data.");
      }
      setBaselineReport(candidate);
      setBaselineName(`Saved report ${item.baselineId}`);
      setComparisonError("");
    } catch (error) {
      setBaselineReport(null);
      setComparisonError(`${error instanceof Error ? error.message : "Cannot restore baseline"} Open the baseline JSON manually if it was not retained.`);
    } finally {
      setComparisonBusy(false);
    }
  };
  const deleteComparisonSettings = async () => {
    if (!comparisonSavedId) return;
    setComparisonBusy(true);
    try {
      await comparisonRequest("DELETE", `/api/v1/topology-comparisons/${encodeURIComponent(comparisonSavedId)}`);
      setComparisonSavedId(null); setComparisonSavedName(""); await refreshComparisons(); setComparisonError("");
    } catch (error) { setComparisonError(error instanceof Error ? error.message : "Cannot delete comparison"); }
    finally { setComparisonBusy(false); }
  };
  const exportComparison = (format: "json" | "csv") => {
    if (!comparison || !baselineReport) return;
    const rows = comparison.changes.map((change) => ({
      status: change.status, source: change.edge.source, destination: change.edge.target,
      service: change.edge.service, baselineCount: change.baselineCount, currentCount: change.currentCount,
      baselineFindings: comparisonFindings(baselineReport, change.edge.source, change.edge.target).length,
      currentFindings: comparisonFindings(report, change.edge.source, change.edge.target).length,
    }));
    if (format === "json") {
      downloadComparison("topology-comparison.json", JSON.stringify({ baselineReportId: baselineReport.report_id, currentReportId: report.report_id, newAssets: comparison.newAssets, notObservedAssets: comparison.missingAssets, changes: rows, caution: "Differences in observed traffic are not proof of physical network changes." }, null, 2), "application/json");
    } else {
      const fields = ["status", "source", "destination", "service", "baselineCount", "currentCount", "baselineFindings", "currentFindings"] as const;
      downloadComparison("topology-comparison.csv", [fields.join(","), ...rows.map((row) => fields.map((field) => comparisonCsvCell(row[field])).join(","))].join("\r\n"), "text/csv;charset=utf-8");
    }
  };

  const loadBaseline = async (file: File | undefined) => {
    if (!file) return;
    setComparisonError("");
    try {
      if (file.size > 50 * 1024 * 1024) throw new Error("JSON report exceeds the 50 MiB comparison limit.");
      const value: unknown = JSON.parse(await file.text());
      if (!value || typeof value !== "object" || !("modules" in value)) throw new Error("File is not an eleVADR report.");
      const candidate = value as ElevadrReport;
      if (!candidate.modules?.connection_success_panel || !candidate.modules?.ot_cross_segment_lines_panel || !Array.isArray(candidate.modules?.ot_devices)) throw new Error("Report is missing required topology data.");
      setBaselineReport(candidate);
      setBaselineName(file.name);
      setComparisonPage(0);
      setSelectedComparisonKey(null);
      setComparisonOverlay(true);
      setComparisonFilter("All");
    } catch (error) {
      setComparisonError(error instanceof Error ? error.message : "Unable to load comparison report.");
    }
  };
  const [labelMode, setLabelMode] = useState<LabelMode>("minimal");
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);
  const [hoveredEdgeId, setHoveredEdgeId] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [suspiciousOnly, setSuspiciousOnly] = useState(false);
  const [findingOnly, setFindingOnly] = useState(false);
  const [hideIsolated, setHideIsolated] = useState(true);
  const [neighborsOnly, setNeighborsOnly] = useState(false);
  const [focusedNodeId, setFocusedNodeId] = useState<string | null>(null);
  const [focusedEdgeId, setFocusedEdgeId] = useState<string | null>(null);
  const [layoutMode, setLayoutMode] = useState<LayoutMode>("class");
  const [clusterFocus, setClusterFocus] = useState("");
  const [clusterListOpen, setClusterListOpen] = useState(false);
  const [clusterRenderLimit, setClusterRenderLimit] = useState(24);
  const [autoRevealClusters, setAutoRevealClusters] = useState(false);
  const [showPerformanceDetails, setShowPerformanceDetails] = useState(false);
  const [lastFrameDelay, setLastFrameDelay] = useState<number | null>(null);
  // Opt-in measurements of the real browser main thread, not synthetic SVG timings.
  const [browserMetrics, setBrowserMetrics] = useState<{ samples: number; averageFrameMs: number; p95FrameMs: number; slowFrames: number; longTasks: number; longestTaskMs: number } | null>(null);
  useEffect(() => {
    if (!showPerformanceDetails) return;
    let active = true;
    let frameId = 0;
    let previous = 0;
    const frames: number[] = [];
    let longTasks = 0;
    let longestTaskMs = 0;
    let observer: PerformanceObserver | undefined;
    try {
      if (PerformanceObserver.supportedEntryTypes?.includes("longtask")) {
        observer = new PerformanceObserver((list) => {
          for (const entry of list.getEntries()) {
            longTasks += 1;
            longestTaskMs = Math.max(longestTaskMs, entry.duration);
          }
        });
        observer.observe({ entryTypes: ["longtask"] });
      }
    } catch { /* Long Task API is not available in all browsers. */ }
    const sample = (now: number) => {
      if (!active) return;
      if (previous) frames.push(now - previous);
      previous = now;
      if (frames.length >= 120) {
        const sorted = [...frames].sort((a, b) => a - b);
        const total = frames.reduce((a, b) => a + b, 0);
        setBrowserMetrics({
          samples: frames.length,
          averageFrameMs: Math.round(total / frames.length * 10) / 10,
          p95FrameMs: Math.round(sorted[Math.min(sorted.length - 1, Math.ceil(sorted.length * .95) - 1)] * 10) / 10,
          slowFrames: frames.filter((ms) => ms > 50).length,
          longTasks,
          longestTaskMs: Math.round(longestTaskMs * 10) / 10,
        });
        frames.length = 0;
      }
      frameId = window.requestAnimationFrame(sample);
    };
    frameId = window.requestAnimationFrame(sample);
    return () => { active = false; window.cancelAnimationFrame(frameId); observer?.disconnect(); };
  }, [showPerformanceDetails]);

  const revealFrameRef = useRef<number | null>(null);
  const clusterLayoutCacheRef = useRef<{ signature: string; coordinates: Map<string, Point> } | null>(null);
  const [inspectedClusterEdge, setInspectedClusterEdge] = useState<string | null>(null);
  const [clusterEdgePage, setClusterEdgePage] = useState(0);
  const [preset, setPreset] = useState<"simple" | "risk" | "full">("simple");
  const [positions, setPositions] = useState<Record<string, Point>>({});
  const [viewport, setViewport] = useState<Viewport>(DEFAULT_VIEWPORT);
  const hydratedStateKeyRef = useRef<string>("");
  const skipNextPersistenceRef = useRef(false);
  const printViewportRef = useRef<Viewport | null>(null);
  const persistenceTimerRef = useRef<number | null>(null);
  const latestStateRef = useRef<NetworkTopologyState | null>(null);
  const latestStorageKeyRef = useRef("");
  const pointerFrameRef = useRef<number | null>(null);
  const pendingPointerRef = useRef<{
    clientX: number;
    clientY: number;
    rectWidth: number;
    rectHeight: number;
  } | null>(null);
  const [isInteracting, setIsInteracting] = useState(false);
  const [isFullScreen, setIsFullScreen] = useState(false);
  const [legendOpen, setLegendOpen] = useState(true);

  const [queryOpen, setQueryOpen] = useState(false);
  const [query, setQuery] = useState<GraphQuery>({});
  const [queryName, setQueryName] = useState("");
  const [savedQueryId, setSavedQueryId] = useState<string | null>(null);
  const [savedQueries, setSavedQueries] = useState<SavedGraphQuery[]>([]);
  const [queryActive, setQueryActive] = useState(false);
  const [queryError, setQueryError] = useState("");
  const [queryBusy, setQueryBusy] = useState(false);
  const [queryAdvanced, setQueryAdvanced] = useState(false);
  const [queryResultsOpen, setQueryResultsOpen] = useState(true);
  const [queryResultPage, setQueryResultPage] = useState(0);
  const [showOnlyQueryMatches, setShowOnlyQueryMatches] = useState(false);
  const QUERY_PAGE_SIZE = 50;
  const queryRequest = async (method: string, path: string, body?: unknown) => {
    const token = getAccessToken();
    if (!token) throw new Error("Sign in to manage saved queries.");
    const response = await fetch(authApiUrl(path), {
      method,
      headers: { Authorization: `Bearer ${token}`, ...(body ? { "Content-Type": "application/json" } : {}) },
      body: body ? JSON.stringify(body) : undefined,
      cache: "no-store",
    });
    if (!response.ok) throw new Error(`Saved-query service returned HTTP ${response.status}`);
    return response.json();
  };
  const refreshSavedQueries = async () => {
    try {
      const result = await queryRequest("GET", "/api/v1/topology-queries");
      setSavedQueries(result.queries || []);
      setQueryError("");
    } catch (error) { setQueryError(error instanceof Error ? error.message : "Cannot load saved queries"); }
  };
  useEffect(() => { if (queryOpen) void refreshSavedQueries(); }, [queryOpen]);
  const saveGraphQuery = async () => {
    setQueryBusy(true);
    try {
      const result = await queryRequest("POST", "/api/v1/topology-queries", { id: savedQueryId || undefined, name: queryName, query });
      setSavedQueryId(result.query.id);
      await refreshSavedQueries();
    } catch (error) { setQueryError(error instanceof Error ? error.message : "Cannot save query"); }
    finally { setQueryBusy(false); }
  };
  const deleteGraphQuery = async () => {
    if (!savedQueryId) return;
    setQueryBusy(true);
    try {
      await queryRequest("DELETE", `/api/v1/topology-queries/${encodeURIComponent(savedQueryId)}`);
      setSavedQueryId(null);
      await refreshSavedQueries();
    } catch (error) { setQueryError(error instanceof Error ? error.message : "Cannot delete query"); }
    finally { setQueryBusy(false); }
  };
  const graphStateStorageKey = `elevadr-topology-state:${report.report_id || "report"}`;

  useEffect(() => {
    if (hydratedStateKeyRef.current === graphStateStorageKey) return;
    hydratedStateKeyRef.current = graphStateStorageKey;
    skipNextPersistenceRef.current = true;
    try {
      const raw = localStorage.getItem(graphStateStorageKey);
      if (!raw) {
        setPreset("simple");
        setLayoutMode("class");
        setLabelMode("minimal");
        setSuspiciousOnly(false);
        setFindingOnly(false);
        setHideIsolated(true);
        setNeighborsOnly(false);
        setFocusedNodeId(null);
        setFocusedEdgeId(null);
        setPositions({});
        setViewport(DEFAULT_VIEWPORT);
        return;
      }
      const saved = JSON.parse(raw) as Partial<NetworkTopologyState>;
      if (
        saved.preset === "simple" ||
        saved.preset === "risk" ||
        saved.preset === "full"
      )
        setPreset(saved.preset);
      if (
        saved.layoutMode === "class" ||
        saved.layoutMode === "subnet" ||
        saved.layoutMode === "role" ||
        saved.layoutMode === "purdue"
      )
        setLayoutMode(saved.layoutMode);
      if (
        saved.labelMode === "minimal" ||
        saved.labelMode === "full" ||
        saved.labelMode === "off"
      )
        setLabelMode(saved.labelMode);
      if (typeof saved.suspiciousOnly === "boolean")
        setSuspiciousOnly(saved.suspiciousOnly);
      if (typeof saved.findingOnly === "boolean")
        setFindingOnly(saved.findingOnly);
      if (typeof saved.hideIsolated === "boolean")
        setHideIsolated(saved.hideIsolated);
      if (typeof saved.neighborsOnly === "boolean")
        setNeighborsOnly(saved.neighborsOnly);
      if (
        typeof saved.focusedNodeId === "string" ||
        saved.focusedNodeId === null
      )
        setFocusedNodeId(saved.focusedNodeId ?? null);
      if (
        saved.viewport &&
        Number.isFinite(saved.viewport.x) &&
        Number.isFinite(saved.viewport.y) &&
        Number.isFinite(saved.viewport.scale)
      ) {
        setViewport({
          x: saved.viewport.x!,
          y: saved.viewport.y!,
          scale: Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, saved.viewport.scale!)),
        });
      }
      if (saved.positions && typeof saved.positions === "object")
        setPositions(saved.positions);
    } catch {
      /* Ignore malformed or unavailable local persistence. */
    }
  }, [graphStateStorageKey]);

  useEffect(() => {
    const state: NetworkTopologyState = {
      preset,
      layoutMode,
      labelMode,
      suspiciousOnly,
      findingOnly,
      hideIsolated,
      neighborsOnly,
      focusedNodeId,
      viewport,
      positions,
    };
    latestStateRef.current = state;
    latestStorageKeyRef.current = graphStateStorageKey;
    if (skipNextPersistenceRef.current) {
      skipNextPersistenceRef.current = false;
      onStateChange?.(state);
      return;
    }
    if (persistenceTimerRef.current !== null)
      window.clearTimeout(persistenceTimerRef.current);
    persistenceTimerRef.current = window.setTimeout(() => {
      try {
        localStorage.setItem(graphStateStorageKey, JSON.stringify(state));
      } catch {
        /* Local persistence unavailable. */
      }
      onStateChange?.(state);
      persistenceTimerRef.current = null;
    }, STATE_PERSIST_DELAY_MS);
    return () => {
      if (persistenceTimerRef.current !== null) {
        window.clearTimeout(persistenceTimerRef.current);
        persistenceTimerRef.current = null;
      }
    };
  }, [
    graphStateStorageKey,
    preset,
    layoutMode,
    labelMode,
    suspiciousOnly,
    findingOnly,
    hideIsolated,
    neighborsOnly,
    focusedNodeId,
    viewport,
    positions,
    onStateChange,
  ]);

  const findingIndex = useMemo(() => {
    const deviceCounts = new Map<string, number>();
    const pairs = new Set<string>();
    const raw = report.arch_insights?.detector_findings;
    if (!Array.isArray(raw)) return { deviceCounts, pairs };
    const addDevice = (value: unknown) => {
      const ip = typeof value === "string" ? value.trim() : "";
      if (ip) deviceCounts.set(ip, (deviceCounts.get(ip) || 0) + 1);
    };
    raw.forEach((entry) => {
      if (!entry || typeof entry !== "object") return;
      const item = entry as Record<string, unknown>;
      if (Array.isArray(item.devices)) item.devices.forEach(addDevice);
      if (Array.isArray(item.connection_pairs)) {
        item.connection_pairs.forEach((rawPair) => {
          if (!rawPair || typeof rawPair !== "object") return;
          const pair = rawPair as Record<string, unknown>;
          const source = String(
            pair.source || pair.src || pair["src_endpoint.ip"] || "",
          );
          const target = String(
            pair.destination || pair.dst || pair["dst_endpoint.ip"] || "",
          );
          if (source && target) {
            pairs.add(`${source}|${target}`);
            addDevice(source);
            addDevice(target);
          }
        });
      }
      if (Array.isArray(item.flows)) {
        item.flows.forEach((rawFlow) => {
          if (!rawFlow || typeof rawFlow !== "object") return;
          const flow = rawFlow as Record<string, unknown>;
          const source = String(
            flow.source || flow.src || flow["src_endpoint.ip"] || "",
          );
          const target = String(
            flow.destination || flow.dst || flow["dst_endpoint.ip"] || "",
          );
          if (source && target) {
            pairs.add(`${source}|${target}`);
            addDevice(source);
            addDevice(target);
          }
        });
      }
    });
    return { deviceCounts, pairs };
  }, [report]);

  const allQueryEdges = useMemo<Edge[]>(() => {
    const suspicious = new Set(
      report.modules.suspicious_outbound_connections_panel.map(
        (item) =>
          `${item["src_endpoint.ip"]}|${item["dst_endpoint.ip"]}|${item["service.name"]}`,
      ),
    );
    const edgeMap = new Map<string, Edge>();
    const add = (
      source: string,
      target: string,
      service: string,
      count: number,
    ) => {
      if (!source || !target || source === target) return;
      const normalizedService = service || "Unknown service";
      const id = `${source}|${target}|${normalizedService}`;
      const prior = edgeMap.get(id);
      edgeMap.set(id, {
        id,
        source,
        target,
        service: normalizedService,
        count: (prior?.count || 0) + Math.max(1, count || 1),
        suspicious: Boolean(prior?.suspicious) || suspicious.has(id),
        findingRelated:
          Boolean(prior?.findingRelated) ||
          findingIndex.pairs.has(`${source}|${target}`),
      });
    };

    report.modules.ot_cross_segment_lines_panel.lines.forEach((item) =>
      add(
        item["src_endpoint.ip"],
        item["dst_endpoint.ip"],
        item["service.name"],
        item.count,
      ),
    );
    report.modules.suspicious_outbound_connections_panel.forEach((item) =>
      add(
        item["src_endpoint.ip"],
        item["dst_endpoint.ip"],
        item["service.name"],
        item.count,
      ),
    );
    report.modules.connection_success_panel.connections
      .forEach((item) => {
        if (item["src_endpoint.ip"] && item["dst_endpoint.ip"]) {
          const service =
            item["service.name"] ||
            item["connection_info.protocol_name"] ||
            (item["dst_endpoint.port"]
              ? `Port ${item["dst_endpoint.port"]}`
              : "Connection");
          add(item["src_endpoint.ip"]!, item["dst_endpoint.ip"]!, service, 1);
        }
      });

    return [...edgeMap.values()]
      .sort((a, b) => b.count - a.count);
  }, [report, findingIndex]);

  // Keep the rendered graph bounded, but never truncate the query dataset.
  const rawEdges = useMemo(() => allQueryEdges.slice(0, 180), [allQueryEdges]);

  const services = useMemo(
    () =>
      [...new Set<string>(rawEdges.map((edge) => edge.service))]
        .sort((a, b) => a.localeCompare(b))
        .slice(0, 60),
    [rawEdges],
  );

  const deviceIndex = useMemo(() => {
    const index = new Map<string, { type: DeviceType; device: Device }>();
    const groups: [DeviceType, Device[]][] = [
      ["OT", report.modules.ot_devices],
      ["IT", report.modules.it_devices],
      ["Edge", report.modules.edge_devices],
    ];
    groups.forEach(([type, devices]) =>
      devices.forEach((device) =>
        deviceIps(device).forEach((ip) => index.set(ip, { type, device })),
      ),
    );
    return index;
  }, [report]);

  const activeService =
    filters.find((filter) => filter.key === "service")?.value || "all";
  const selectedClass =
    filters.find((filter) => filter.key === "deviceClass")?.value || "all";
  const selectedIp = filters.find((filter) => filter.key === "ip")?.value;
  const selectedSubnet = filters.find(
    (filter) => filter.key === "subnet",
  )?.value;

  const edges = useMemo(() => {
    return rawEdges
      .filter((edge) => {
        if (activeService !== "all" && edge.service !== activeService)
          return false;
        if (
          selectedIp &&
          edge.source !== selectedIp &&
          edge.target !== selectedIp
        )
          return false;
        if (selectedSubnet) {
          const sourceDevice = deviceIndex.get(edge.source)?.device;
          const targetDevice = deviceIndex.get(edge.target)?.device;
          const sourceSubnet = (sourceDevice?.subnets ||
            sourceDevice?.ipv4_subnets ||
            [])[0];
          const targetSubnet = (targetDevice?.subnets ||
            targetDevice?.ipv4_subnets ||
            [])[0];
          if (
            sourceSubnet !== selectedSubnet &&
            targetSubnet !== selectedSubnet
          )
            return false;
        }
        if (selectedClass !== "all") {
          const sourceType = deviceIndex.get(edge.source)?.type || "Unknown";
          const targetType = deviceIndex.get(edge.target)?.type || "Unknown";
          if (sourceType !== selectedClass && targetType !== selectedClass)
            return false;
        }
        if (suspiciousOnly && !edge.suspicious) return false;
        if (findingOnly && !edge.findingRelated && !edge.suspicious)
          return false;
        return true;
      })
      .slice(0, EDGE_LIMITS[preset]);
  }, [
    rawEdges,
    activeService,
    selectedIp,
    selectedSubnet,
    selectedClass,
    suspiciousOnly,
    findingOnly,
    deviceIndex,
    preset,
  ]);

  const contextArchitecture = useMemo(() => {
    const snapshot = report.arch_insights?.detection_context_snapshot;
    if (!snapshot || typeof snapshot !== "object")
      return {
        assets: [] as Record<string, unknown>[],
        segments: [] as Record<string, unknown>[],
      };
    const record = snapshot as Record<string, unknown>;
    const assets = Array.isArray(record.assets)
      ? record.assets.filter(
          (item): item is Record<string, unknown> =>
            Boolean(item) && typeof item === "object",
        )
      : [];
    const segments = Array.isArray(record.segments)
      ? record.segments.filter(
          (item): item is Record<string, unknown> =>
            Boolean(item) && typeof item === "object",
        )
      : [];
    return { assets, segments };
  }, [report]);

  const contextLookup = useMemo(() => {
    const assetsByIp = new Map<string, Record<string, unknown>>();
    contextArchitecture.assets.forEach((asset) => {
      const values = [asset.ip, ...(Array.isArray(asset.ips) ? asset.ips : [])]
        .map(String)
        .filter(Boolean);
      values.forEach((ip) => assetsByIp.set(ip, asset));
    });
    const segmentsByKey = new Map<string, Record<string, unknown>>();
    contextArchitecture.segments.forEach((segment) => {
      [segment.cidr, segment.id, segment.name]
        .map(String)
        .filter(Boolean)
        .forEach((key) => segmentsByKey.set(key, segment));
    });
    return { assetsByIp, segmentsByKey };
  }, [contextArchitecture]);

  const architectureFor = (ip: string, type: DeviceType, subnet: string) => {
    const asset = contextLookup.assetsByIp.get(ip);
    const segmentName = asset
      ? String(asset.segment || asset.segmentId || "")
      : "";
    const segment =
      contextLookup.segmentsByKey.get(subnet) ||
      (segmentName ? contextLookup.segmentsByKey.get(segmentName) : undefined);
    const rawRole = String(asset?.role || segment?.role || "")
      .trim()
      .toLowerCase();
    const roleGroup =
      rawRole === "ot"
        ? "OT"
        : rawRole === "it"
          ? "IT"
          : rawRole === "dmz"
            ? "DMZ"
            : rawRole === "infrastructure"
              ? "Network"
              : type === "Edge"
                ? "Network"
                : type;
    const rawPurdue = String(
      asset?.purdueLevel ||
        asset?.purdue_level ||
        segment?.purdueLevel ||
        segment?.purdue_level ||
        "",
    ).trim();
    const purdueLevel = rawPurdue
      ? rawPurdue.toLowerCase().startsWith("level")
        ? rawPurdue
        : `Level ${rawPurdue}`
      : "Unassigned";
    return { roleGroup: roleGroup || "Unknown", purdueLevel };
  };

  const baseNodes = useMemo<Omit<Node, "x" | "y">[]>(() => {
    const degree = new Map<string, number>();
    const knownIds = new Set<string>();
    edges.forEach((edge) => {
      degree.set(edge.source, (degree.get(edge.source) || 0) + edge.count);
      degree.set(edge.target, (degree.get(edge.target) || 0) + edge.count);
      knownIds.add(edge.source);
      knownIds.add(edge.target);
    });
    [
      report.modules.ot_devices,
      report.modules.it_devices,
      report.modules.edge_devices,
    ].forEach((devices) =>
      devices.forEach((device) =>
        deviceIps(device).forEach((ip) => knownIds.add(ip)),
      ),
    );

    const limit = NODE_LIMITS[preset];
    return [...knownIds]
      .filter((id) => {
        const observedDegree = degree.get(id) || 0;
        if (hideIsolated && observedDegree === 0) return false;
        if (selectedIp && id !== selectedIp && observedDegree === 0)
          return false;
        const info = deviceIndex.get(id) || {
          type: "Unknown" as DeviceType,
          device: undefined,
        };
        if (
          selectedClass !== "all" &&
          info.type !== selectedClass &&
          observedDegree === 0
        )
          return false;
        const subnet = (info.device?.subnets ||
          info.device?.ipv4_subnets ||
          [])[0];
        if (selectedSubnet && subnet !== selectedSubnet && observedDegree === 0)
          return false;
        if (
          activeService !== "all" &&
          !serviceList(info.device).includes(activeService) &&
          observedDegree === 0
        )
          return false;
        return true;
      })
      .sort(
        (a, b) =>
          (degree.get(b) || 0) - (degree.get(a) || 0) || a.localeCompare(b),
      )
      .slice(0, limit)
      .map((id) => {
        const info = deviceIndex.get(id) || {
          type: "Unknown" as DeviceType,
          device: undefined,
        };
        const subnet =
          (info.device?.subnets ||
            info.device?.ipv4_subnets || ["Unknown subnet"])[0] ||
          "Unknown subnet";
        const architecture = architectureFor(id, info.type, subnet);
        return {
          id,
          type: info.type,
          degree: degree.get(id) || 0,
          manufacturer: info.device?.manufacturer,
          services: serviceList(info.device),
          subnet,
          findingCount: findingIndex.deviceCounts.get(id) || 0,
          roleGroup: architecture.roleGroup,
          purdueLevel: architecture.purdueLevel,
        };
      });
  }, [
    edges,
    report,
    findingIndex,
    hideIsolated,
    preset,
    selectedIp,
    selectedClass,
    selectedSubnet,
    activeService,
    contextArchitecture,
    contextLookup,
    deviceIndex,
  ]);

  const focusedNeighborIds = useMemo(() => {
    if (!focusedNodeId) return null;
    const ids = new Set<string>([focusedNodeId]);
    edges.forEach((edge) => {
      if (edge.source === focusedNodeId) ids.add(edge.target);
      if (edge.target === focusedNodeId) ids.add(edge.source);
    });
    return ids;
  }, [edges, focusedNodeId]);

  const groupKeyFor = (node: Omit<Node, "x" | "y"> | Node): string => {
    if (layoutMode === "subnet") return node.subnet;
    if (layoutMode === "role") return node.roleGroup;
    if (layoutMode === "purdue") return node.purdueLevel;
    return node.type;
  };

  const groupedPosition = (
    index: number,
    total: number,
    groupIndex: number,
    groupTotal: number,
  ): Point => {
    const columns = Math.max(1, Math.ceil(Math.sqrt(groupTotal)));
    const rows = Math.max(1, Math.ceil(groupTotal / columns));
    const col = groupIndex % columns;
    const row = Math.floor(groupIndex / columns);
    const centerX =
      columns === 1 ? WIDTH / 2 : 120 + col * (800 / Math.max(1, columns - 1));
    const centerY =
      rows === 1 ? HEIGHT / 2 : 120 + row * (360 / Math.max(1, rows - 1));
    const angle = (Math.PI * 2 * index) / Math.max(1, total);
    const radius = Math.min(90, 26 + total * 5);
    return {
      x: centerX + Math.cos(angle) * radius,
      y: centerY + Math.sin(angle) * radius,
    };
  };

  const layoutPosition = (
    node: Omit<Node, "x" | "y">,
    index: number,
    total: number,
    groupIndex = 0,
    groupTotal = 1,
  ): Point => {
    if (layoutMode === "class") return defaultPosition(node.type, index, total);
    return groupedPosition(index, total, groupIndex, groupTotal);
  };

  useEffect(() => {
    setPositions((current) => {
      const next = { ...current };
      if (layoutMode === "class") {
        const grouped = new Map<DeviceType, Omit<Node, "x" | "y">[]>();
        baseNodes.forEach((node) => {
          const bucket = grouped.get(node.type);
          if (bucket) bucket.push(node);
          else grouped.set(node.type, [node]);
        });
        grouped.forEach((items) =>
          items.forEach((node, index) => {
            if (!next[node.id])
              next[node.id] = layoutPosition(node, index, items.length);
          }),
        );
      } else {
        const grouped = new Map<string, Omit<Node, "x" | "y">[]>();
        baseNodes.forEach((node) => {
          const key = groupKeyFor(node);
          const bucket = grouped.get(key);
          if (bucket) bucket.push(node);
          else grouped.set(key, [node]);
        });
        const groups = [...grouped.entries()].sort(([a], [b]) =>
          a.localeCompare(b, undefined, { numeric: true }),
        );
        groups.forEach(([, items], groupIndex) =>
          items.forEach((node, index) => {
            if (!next[node.id])
              next[node.id] = layoutPosition(
                node,
                index,
                items.length,
                groupIndex,
                groups.length,
              );
          }),
        );
      }
      return next;
    });
  }, [baseNodes, layoutMode]);

  // Cluster drill-down restricts rendering only; saved queries still inspect
  // all report-derived relationships independently of the display budget.
  const clusterSummaries = useMemo(() => {
    const groups = new Map<string, number>();
    for (const node of baseNodes) {
      const key = groupKeyFor(node) || "Unassigned";
      groups.set(key, (groups.get(key) || 0) + 1);
    }
    return [...groups.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  }, [baseNodes, layoutMode]);
  useEffect(() => { setClusterFocus(""); setClusterRenderLimit(24); setAutoRevealClusters(false); setInspectedClusterEdge(null); setClusterEdgePage(0); }, [layoutMode, report.report_id]);

  const nodes = useMemo<Node[]>(() => {
    const query = search.trim().toLowerCase();
    return baseNodes
      .map((node) => ({
        ...node,
        ...(positions[node.id] || { x: WIDTH / 2, y: HEIGHT / 2 }),
      }))
      .filter((node) => {
        if (clusterFocus && groupKeyFor(node) !== clusterFocus) return false;
        if (
          neighborsOnly &&
          focusedNeighborIds &&
          !focusedNeighborIds.has(node.id)
        )
          return false;
        if (!query) return true;
        return (
          node.id.toLowerCase().includes(query) ||
          (node.manufacturer || "").toLowerCase().includes(query) ||
          node.services.some((service) => service.toLowerCase().includes(query))
        );
      });
  }, [baseNodes, positions, search, neighborsOnly, focusedNeighborIds, clusterFocus, layoutMode]);

  useEffect(() => {
    if (focusedNodeId && !baseNodes.some((node) => node.id === focusedNodeId)) {
      setFocusedNodeId(null);
      setNeighborsOnly(false);
    }
    const validNodeIds = new Set(baseNodes.map((node) => node.id));
    setPositions((current) =>
      Object.fromEntries(
        Object.entries(current).filter(([id]) => validNodeIds.has(id)),
      ),
    );
  }, [baseNodes, focusedNodeId]);

  const nodeMap = useMemo(
    () => new Map(nodes.map((node) => [node.id, node])),
    [nodes],
  );
  const visibleEdges = useMemo(
    () =>
      edges.filter(
        (edge) => nodeMap.has(edge.source) && nodeMap.has(edge.target),
      ),
    [edges, nodeMap],
  );
  const groupRegions = useMemo<GroupRegion[]>(() => {
    if (layoutMode === "class") return [];
    const grouped = new Map<string, Node[]>();
    nodes.forEach((node) => {
      const key = groupKeyFor(node);
      const bucket = grouped.get(key);
      if (bucket) bucket.push(node);
      else grouped.set(key, [node]);
    });
    return [...grouped.entries()].map(([key, members]) => {
      const xs = members.map((node) => node.x);
      const ys = members.map((node) => node.y);
      const paddingX = 64,
        paddingTop = 48,
        paddingBottom = 52;
      const minX = Math.max(14, Math.min(...xs) - paddingX),
        maxX = Math.min(WIDTH - 14, Math.max(...xs) + paddingX);
      const minY = Math.max(14, Math.min(...ys) - paddingTop),
        maxY = Math.min(HEIGHT - 14, Math.max(...ys) + paddingBottom);
      const label =
        layoutMode === "subnet"
          ? key
          : layoutMode === "role"
            ? `${key} role`
            : key === "Unassigned"
              ? "Purdue unassigned"
              : `Purdue ${key}`;
      return {
        key,
        label,
        x: minX,
        y: minY,
        width: Math.max(118, maxX - minX),
        height: Math.max(92, maxY - minY),
        count: members.length,
      };
    });
  }, [layoutMode, nodes]);

  const maxDegree = Math.max(1, ...nodes.map((node) => node.degree));

  const graphPoint = (clientX: number, clientY: number): Point => {
    const svg = svgRef.current;
    if (!svg) return { x: 0, y: 0 };
    const rect = svg.getBoundingClientRect();
    const localX = ((clientX - rect.left) / rect.width) * WIDTH;
    const localY = ((clientY - rect.top) / rect.height) * HEIGHT;
    return {
      x: (localX - viewport.x) / viewport.scale,
      y: (localY - viewport.y) / viewport.scale,
    };
  };

  const inspectEdge = (edge: Edge) => {
    if (dragRef.current?.moved) return;
    setFocusedEdgeId(edge.id);
    setFocusedNodeId(null);
    onSelect({ type: "connection", id: edge.id });
  };

  const inspectNode = (node: Node) => {
    if (dragRef.current?.moved) return;
    setFocusedNodeId(node.id);
    setFocusedEdgeId(null);
    onSelect({ type: "device", id: node.id });
  };

  const focusedNode = focusedNodeId ? nodeMap.get(focusedNodeId) : undefined;
  const focusedEdge = focusedEdgeId
    ? visibleEdges.find((edge) => edge.id === focusedEdgeId)
    : undefined;
  const neighborIds = useMemo(() => {
    if (!focusedNodeId) return new Set<string>();
    const peers = new Set<string>([focusedNodeId]);
    visibleEdges.forEach((edge) => {
      if (edge.source === focusedNodeId) peers.add(edge.target);
      if (edge.target === focusedNodeId) peers.add(edge.source);
    });
    return peers;
  }, [focusedNodeId, visibleEdges]);
  const focusedPeerCount = Math.max(
    0,
    neighborIds.size - (focusedNodeId ? 1 : 0),
  );

  const clearGraphSelection = () => {
    setFocusedNodeId(null);
    setFocusedEdgeId(null);
    setNeighborsOnly(false);
  };
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      const active = document.activeElement as HTMLElement | null;
      if (
        active &&
        (active.tagName === "INPUT" ||
          active.tagName === "SELECT" ||
          active.tagName === "TEXTAREA")
      )
        return;
      clearGraphSelection();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);
  const filterFocusedDevice = () => {
    if (!focusedNode) return;
    onFilter({ key: "ip", value: focusedNode.id, label: "Device" });
  };
  const filterFocusedService = () => {
    if (!focusedEdge) return;
    onFilter({ key: "service", value: focusedEdge.service, label: "Service" });
  };
  const focusedDeviceFilterActive = Boolean(
    focusedNode &&
    filters.some(
      (filter) => filter.key === "ip" && filter.value === focusedNode.id,
    ),
  );
  const focusedServiceFilterActive = Boolean(
    focusedEdge &&
    filters.some(
      (filter) =>
        filter.key === "service" && filter.value === focusedEdge.service,
    ),
  );
  const toggleFullScreen = () => setIsFullScreen((current) => !current);

  const resetGraphView = () => {
    setPreset("simple");
    setLayoutMode("class");
    setLabelMode("minimal");
    setSuspiciousOnly(false);
    setFindingOnly(false);
    setHideIsolated(true);
    setNeighborsOnly(false);
    setFocusedNodeId(null);
    setFocusedEdgeId(null);
    setSearch("");
    setPositions({});
    setViewport(DEFAULT_VIEWPORT);
  };

  const clearGraphRefinements = () => {
    setSearch("");
    setSuspiciousOnly(false);
    setFindingOnly(false);
    setNeighborsOnly(false);
    setFocusedNodeId(null);
    setFocusedEdgeId(null);
  };

  const zoomBy = (factor: number) => {
    setViewport((current) => ({
      ...current,
      scale: Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, current.scale * factor)),
    }));
  };

  const handleWheel = (event: React.WheelEvent<SVGSVGElement>) => {
    // Let ordinary wheel/trackpad gestures scroll the report.
    // Graph zoom is deliberate: Ctrl/Command + wheel only.
    if (!event.ctrlKey && !event.metaKey) return;
    event.preventDefault();
    const factor = event.deltaY > 0 ? 0.9 : 1.1;
    const nextScale = Math.min(
      MAX_ZOOM,
      Math.max(MIN_ZOOM, viewport.scale * factor),
    );
    const rect = event.currentTarget.getBoundingClientRect();
    const px = ((event.clientX - rect.left) / rect.width) * WIDTH;
    const py = ((event.clientY - rect.top) / rect.height) * HEIGHT;
    const worldX = (px - viewport.x) / viewport.scale;
    const worldY = (py - viewport.y) / viewport.scale;
    setViewport({
      scale: nextScale,
      x: px - worldX * nextScale,
      y: py - worldY * nextScale,
    });
  };

  const handleCanvasPointerDown = (
    event: React.PointerEvent<SVGSVGElement>,
  ) => {
    if ((event.target as Element).closest(".topology-node, .topology-edge"))
      return;
    event.currentTarget.setPointerCapture(event.pointerId);
    panRef.current = {
      startX: event.clientX,
      startY: event.clientY,
      viewport,
      moved: false,
    };
    setIsInteracting(true);
  };

  const handleCanvasPointerMove = (
    event: React.PointerEvent<SVGSVGElement>,
  ) => {
    if (!dragRef.current && !panRef.current) return;
    const rect = event.currentTarget.getBoundingClientRect();
    pendingPointerRef.current = {
      clientX: event.clientX,
      clientY: event.clientY,
      rectWidth: rect.width,
      rectHeight: rect.height,
    };
    if (pointerFrameRef.current !== null) return;
    pointerFrameRef.current = window.requestAnimationFrame(() => {
      const pending = pendingPointerRef.current;
      pointerFrameRef.current = null;
      if (!pending) return;
      if (dragRef.current) {
        const dxClient = pending.clientX - dragRef.current.startClientX;
        const dyClient = pending.clientY - dragRef.current.startClientY;
        if (!dragRef.current.moved && Math.hypot(dxClient, dyClient) < 5)
          return;
        const svg = svgRef.current;
        if (!svg) return;
        const svgRect = svg.getBoundingClientRect();
        const localX =
          ((pending.clientX - svgRect.left) / svgRect.width) * WIDTH;
        const localY =
          ((pending.clientY - svgRect.top) / svgRect.height) * HEIGHT;
        const point = {
          x: (localX - viewport.x) / viewport.scale,
          y: (localY - viewport.y) / viewport.scale,
        };
        const id = dragRef.current.id;
        dragRef.current.moved = true;
        setIsInteracting(true);
        setPositions((current) => ({ ...current, [id]: point }));
        return;
      }
      if (panRef.current) {
        const dxClient = pending.clientX - panRef.current.startX;
        const dyClient = pending.clientY - panRef.current.startY;
        if (!panRef.current.moved && Math.hypot(dxClient, dyClient) < 5) return;
        panRef.current.moved = true;
        const dx = (dxClient / pending.rectWidth) * WIDTH;
        const dy = (dyClient / pending.rectHeight) * HEIGHT;
        setViewport({
          ...panRef.current.viewport,
          x: panRef.current.viewport.x + dx,
          y: panRef.current.viewport.y + dy,
        });
      }
    });
  };

  const handleCanvasPointerUp = (event: React.PointerEvent<SVGSVGElement>) => {
    if (event.currentTarget.hasPointerCapture(event.pointerId))
      event.currentTarget.releasePointerCapture(event.pointerId);
    const backgroundClick = Boolean(panRef.current && !panRef.current.moved);
    panRef.current = null;
    pendingPointerRef.current = null;
    if (pointerFrameRef.current !== null) {
      window.cancelAnimationFrame(pointerFrameRef.current);
      pointerFrameRef.current = null;
    }
    setIsInteracting(false);
    if (backgroundClick) clearGraphSelection();
    window.setTimeout(() => {
      dragRef.current = null;
    }, 0);
  };

  const beginNodeDrag = (
    event: React.PointerEvent<SVGCircleElement>,
    node: Node,
  ) => {
    event.preventDefault();
    event.stopPropagation();
    event.currentTarget.setPointerCapture(event.pointerId);
    dragRef.current = {
      id: node.id,
      moved: false,
      startClientX: event.clientX,
      startClientY: event.clientY,
    };
  };

  const finishNodeDrag = (event: React.PointerEvent<SVGCircleElement>) => {
    event.preventDefault();
    event.stopPropagation();
    if (event.currentTarget.hasPointerCapture(event.pointerId))
      event.currentTarget.releasePointerCapture(event.pointerId);
    dragRef.current = null;
    pendingPointerRef.current = null;
    if (pointerFrameRef.current !== null) {
      window.cancelAnimationFrame(pointerFrameRef.current);
      pointerFrameRef.current = null;
    }
    setIsInteracting(false);
  };

  const fittedViewport = (): Viewport | null => {
    if (!nodes.length) return null;
    const xs = nodes.map((node) => node.x),
      ys = nodes.map((node) => node.y);
    const minX = Math.min(...xs) - 70,
      maxX = Math.max(...xs) + 70,
      minY = Math.min(...ys) - 70,
      maxY = Math.max(...ys) + 70;
    const scale = Math.min(
      1.8,
      Math.max(
        MIN_ZOOM,
        Math.min(
          WIDTH / Math.max(1, maxX - minX),
          HEIGHT / Math.max(1, maxY - minY),
        ) * 0.92,
      ),
    );
    return {
      scale,
      x: WIDTH / 2 - ((minX + maxX) / 2) * scale,
      y: HEIGHT / 2 - ((minY + maxY) / 2) * scale,
    };
  };

  const fitToView = () => {
    const next = fittedViewport();
    if (next) setViewport(next);
  };

  const focusNodeNeighborhood = (node: Node) => {
    inspectNode(node);
    const ids = new Set<string>([node.id]);
    visibleEdges.forEach((edge) => {
      if (edge.source === node.id) ids.add(edge.target);
      if (edge.target === node.id) ids.add(edge.source);
    });
    const points = [...ids]
      .map((id) => nodeMap.get(id))
      .filter((item): item is Node => Boolean(item));
    if (!points.length) return;
    const xs = points.map((item) => item.x);
    const ys = points.map((item) => item.y);
    const minX = Math.min(...xs) - 90,
      maxX = Math.max(...xs) + 90;
    const minY = Math.min(...ys) - 90,
      maxY = Math.max(...ys) + 90;
    const scale = Math.min(
      2.2,
      Math.max(
        MIN_ZOOM,
        Math.min(
          WIDTH / Math.max(1, maxX - minX),
          HEIGHT / Math.max(1, maxY - minY),
        ) * 0.88,
      ),
    );
    setViewport({
      scale,
      x: WIDTH / 2 - ((minX + maxX) / 2) * scale,
      y: HEIGHT / 2 - ((minY + maxY) / 2) * scale,
    });
  };

  useEffect(() => {
    const beforePrint = () => {
      printViewportRef.current = viewport;
      const next = fittedViewport();
      if (next) setViewport(next);
    };
    const afterPrint = () => {
      if (printViewportRef.current) setViewport(printViewportRef.current);
      printViewportRef.current = null;
    };
    window.addEventListener("beforeprint", beforePrint);
    window.addEventListener("afterprint", afterPrint);
    return () => {
      window.removeEventListener("beforeprint", beforePrint);
      window.removeEventListener("afterprint", afterPrint);
    };
  }, [viewport, nodes]);

  useEffect(
    () => () => {
      if (pointerFrameRef.current !== null)
        window.cancelAnimationFrame(pointerFrameRef.current);
      if (persistenceTimerRef.current !== null)
        window.clearTimeout(persistenceTimerRef.current);
      if (latestStateRef.current && latestStorageKeyRef.current) {
        try {
          localStorage.setItem(
            latestStorageKeyRef.current,
            JSON.stringify(latestStateRef.current),
          );
        } catch {
          /* Local persistence unavailable. */
        }
      }
    },
    [],
  );

  const exportSvg = () => {
    if (!svgRef.current) return;
    const clone = svgRef.current.cloneNode(true) as SVGSVGElement;
    clone.setAttribute("xmlns", "http://www.w3.org/2000/svg");
    const metadata = document.createElementNS(
      "http://www.w3.org/2000/svg",
      "metadata",
    );
    metadata.textContent = JSON.stringify({
      report_id: report.report_id,
      graph_view: {
        preset,
        layoutMode,
        labelMode,
        suspiciousOnly,
        findingOnly,
        hideIsolated,
        neighborsOnly,
        focusedNodeId,
        viewport,
      },
      active_investigation_filters: filters,
    });
    clone.insertBefore(metadata, clone.firstChild);
    const blob = new Blob([new XMLSerializer().serializeToString(clone)], {
      type: "image/svg+xml;charset=utf-8",
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `elevadr-topology-${report.report_id}.svg`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const suspiciousCount = visibleEdges.filter((edge) => edge.suspicious).length;
  const findingRelatedCount = visibleEdges.filter(
    (edge) => edge.findingRelated || edge.suspicious,
  ).length;
  const nodeBudgetReached = baseNodes.length >= NODE_LIMITS[preset];
  const edgeBudgetReached =
    edges.length >= EDGE_LIMITS[preset] && rawEdges.length > edges.length;
  const displayLimited = nodeBudgetReached || edgeBudgetReached;
  const applyPreset = (next: "simple" | "risk" | "full") => {
    setPreset(next);
    setNeighborsOnly(false);
    if (next === "simple") {
      setSuspiciousOnly(false);
      setFindingOnly(false);
      setHideIsolated(true);
      setLabelMode("minimal");
      setLayoutMode("class");
    }
    if (next === "risk") {
      setSuspiciousOnly(false);
      setFindingOnly(true);
      setHideIsolated(true);
      setLabelMode("minimal");
      setLayoutMode("class");
    }
    if (next === "full") {
      setSuspiciousOnly(false);
      setFindingOnly(false);
      setHideIsolated(false);
      setLabelMode("full");
    }
    setPositions({});
    setViewport(DEFAULT_VIEWPORT);
    clearGraphSelection();
  };

  // Query against the full report-derived graph, not just the display-limited subset.
  const queryMatchingEdges = useMemo(() => {
    if (!queryActive) return [] as Edge[];
    const matchDevice = (id: string) => {
      const item = deviceIndex.get(id);
      const subnet = (item?.device?.subnets || item?.device?.ipv4_subnets || [])[0] || "Unknown subnet";
      const role = baseNodes.find((n) => n.id === id);
      return (!query.type || item?.type === query.type) &&
        (!query.subnet || subnet.toLowerCase().includes(query.subnet.toLowerCase())) &&
        (!query.purdueLevel || role?.purdueLevel.toLowerCase().includes(query.purdueLevel.toLowerCase())) &&
        (!query.roleGroup || role?.roleGroup.toLowerCase().includes(query.roleGroup.toLowerCase()));
    };
    const eligible = allQueryEdges.filter((edge) =>
      (!query.service || edge.service.toLowerCase().includes(query.service.toLowerCase())) &&
      (query.suspicious === undefined || edge.suspicious === query.suspicious) &&
      (query.findingRelated === undefined || edge.findingRelated === query.findingRelated) &&
      (!query.minCount || edge.count >= query.minCount)
    );
    // Bounded breadth-first traversal of *observed communications*. This does not
    // imply routing, physical connectivity, or that a packet could traverse the path.
    const seed = (query.startAsset || "").trim();
    const hops = query.maxHops || 1;
    const direction = query.direction || "both";
    const seeds = seed ? [seed] : [...new Set(eligible.flatMap((edge) => [edge.source, edge.target]))].filter(matchDevice);
    if (!seeds.length) return [] as Edge[];
    const reached = new Set(seeds);
    let frontier = new Set(seeds);
    const selected = new Map<string, Edge>();
    for (let depth = 0; depth < hops && frontier.size; depth++) {
      const next = new Set<string>();
      for (const edge of eligible) {
        const forward = direction !== "inbound" && frontier.has(edge.source);
        const reverse = direction !== "outbound" && frontier.has(edge.target);
        if (!forward && !reverse) continue;
        selected.set(edge.id, edge);
        for (const neighbor of [forward ? edge.target : null, reverse ? edge.source : null]) {
          if (neighbor && !reached.has(neighbor)) { reached.add(neighbor); next.add(neighbor); }
        }
      }
      frontier = next;
    }
    return [...selected.values()];
  }, [queryActive, query, allQueryEdges, deviceIndex, baseNodes]);
  // Label observed edges with their first discovery depth for readable path results.
  const queryHopDepths = useMemo(() => {
    const depths = new Map<string, number>();
    const seed = (query.startAsset || "").trim();
    if (!seed || !queryActive) return depths;
    const visited = new Set([seed]);
    let frontier = new Set([seed]);
    for (let hop = 1; hop <= (query.maxHops || 1) && frontier.size; hop++) {
      const next = new Set<string>();
      for (const edge of queryMatchingEdges) {
        const forward = query.direction !== "inbound" && frontier.has(edge.source);
        const reverse = query.direction !== "outbound" && frontier.has(edge.target);
        if (!forward && !reverse) continue;
        if (!depths.has(edge.id)) depths.set(edge.id, hop);
        for (const neighbor of [forward ? edge.target : null, reverse ? edge.source : null]) {
          if (neighbor && !visited.has(neighbor)) { visited.add(neighbor); next.add(neighbor); }
        }
      }
      frontier = next;
    }
    return depths;
  }, [queryActive, query, queryMatchingEdges]);
  const queryEdgeIds = useMemo(() => new Set(queryMatchingEdges.map((edge) => edge.id)), [queryMatchingEdges]);
  const queryNodeIds = useMemo(() => new Set(queryMatchingEdges.flatMap((edge) => [edge.source, edge.target])), [queryMatchingEdges]);
  const queryPageCount = Math.max(1, Math.ceil(queryMatchingEdges.length / QUERY_PAGE_SIZE));
  const effectiveQueryPage = Math.min(queryResultPage, queryPageCount - 1);
  const pagedQueryEdges = useMemo(
    () => queryMatchingEdges.slice(effectiveQueryPage * QUERY_PAGE_SIZE, (effectiveQueryPage + 1) * QUERY_PAGE_SIZE),
    [queryMatchingEdges, effectiveQueryPage],
  );
  // A query can search the full report; graph rendering is intentionally bounded.
  const renderedQueryEdges = useMemo(
    () => showOnlyQueryMatches && queryActive
      ? visibleEdges.filter((edge) => queryEdgeIds.has(edge.id))
      : visibleEdges,
    [showOnlyQueryMatches, queryActive, visibleEdges, queryEdgeIds],
  );

  // Aggregate only the bounded display graph. Queries retain the full report data.
  const aggregateView = !clusterFocus;
  const aggregateGraph = useMemo(() => {
    const grouped = new Map<string, { key: string; members: Node[]; x: number; y: number }>();
    for (const node of nodes) {
      const key = layoutMode === "subnet" ? node.subnet : layoutMode === "role" ? node.roleGroup : layoutMode === "purdue" ? node.purdueLevel : node.type;
      let group = grouped.get(key);
      if (!group) {
        group = { key, members: [], x: 0, y: 0 };
        grouped.set(key, group);
      }
      group.members.push(node);
      group.x += node.x;
      group.y += node.y;
    }
    const clusters = [...grouped.values()].sort((a, b) => a.key.localeCompare(b.key));
    // Cache deterministic cluster coordinates for unchanged group membership.
    // Filtering edges or opening the Query Explorer must not trigger a new layout.
    const signature = `${layoutMode}:${clusters.map((group) => group.key).join("\u001f")}`;
    let cached = clusterLayoutCacheRef.current;
    if (!cached || cached.signature !== signature) {
      const columns = Math.max(1, Math.ceil(Math.sqrt(clusters.length)));
      const rows = Math.ceil(clusters.length / columns);
      const coordinates = new Map<string, Point>();
      clusters.forEach((group, index) => {
        coordinates.set(group.key, {
          x: (index % columns + 1) * WIDTH / (columns + 1),
          y: (Math.floor(index / columns) + 1) * HEIGHT / (rows + 1),
        });
      });
      cached = { signature, coordinates };
      clusterLayoutCacheRef.current = cached;
    }
    for (const group of clusters) {
      const point = cached.coordinates.get(group.key);
      if (point) { group.x = point.x; group.y = point.y; }
    }
    const memberGroups = new Map<string, string>();
    for (const group of clusters) {
      for (const member of group.members) memberGroups.set(member.id, group.key);
    }
    const aggregated = new Map<string, { source: string; target: string; count: number; relationships: number; services: Set<string>; suspicious: boolean; findingRelated: boolean }>();
    for (const edge of renderedQueryEdges) {
      const source = memberGroups.get(edge.source);
      const target = memberGroups.get(edge.target);
      if (!source || !target || source === target) continue;
      const key = JSON.stringify([source, target]);
      let item = aggregated.get(key);
      if (!item) {
        item = { source, target, count: 0, relationships: 0, services: new Set(), suspicious: false, findingRelated: false };
        aggregated.set(key, item);
      }
      item.count += edge.count;
      item.relationships += 1;
      item.services.add(edge.service);
      item.suspicious ||= edge.suspicious;
      item.findingRelated ||= edge.findingRelated;
    }
    return { clusters, edges: [...aggregated.values()] };
  }, [nodes, renderedQueryEdges, layoutMode]);

  // Progressive aggregate display: bounded SVG complexity without truncating query data.
  // Reveal additional SVG groups in separate animation frames, keeping each
  // React update bounded. Cancel immediately when the view changes/unmounts.
  useEffect(() => {
    if (!autoRevealClusters || !aggregateView || clusterRenderLimit >= aggregateGraph.clusters.length) {
      if (autoRevealClusters && clusterRenderLimit >= aggregateGraph.clusters.length) setAutoRevealClusters(false);
      return;
    }
    const started = performance.now();
    revealFrameRef.current = window.requestAnimationFrame(() => {
      revealFrameRef.current = null;
      const frameDelay = performance.now() - started;
      setLastFrameDelay(Math.round(frameDelay * 10) / 10);
      // Slow frames reveal fewer clusters. This bounds incremental SVG work
      // without changing the underlying graph or saved-query results.
      const batch = frameDelay > 48 ? 6 : frameDelay > 24 ? 12 : 24;
      setClusterRenderLimit((limit) => Math.min(limit + batch, aggregateGraph.clusters.length));
    });
    return () => {
      if (revealFrameRef.current !== null) window.cancelAnimationFrame(revealFrameRef.current);
      revealFrameRef.current = null;
    };
  }, [autoRevealClusters, aggregateView, clusterRenderLimit, aggregateGraph.clusters.length]);
  const renderedClusters = useMemo(() => aggregateGraph.clusters.slice(0, clusterRenderLimit), [aggregateGraph.clusters, clusterRenderLimit]);
  // Index cluster positions once rather than searching the cluster array for each SVG edge.
  const clusterPositions = useMemo(() => new Map(aggregateGraph.clusters.map((cluster) => [cluster.key, cluster] as const)), [aggregateGraph.clusters]);
  // Pre-sort edges by the index of their later endpoint. As clusters are revealed,
  // a binary search selects a prefix instead of filtering every edge each frame.
  const revealOrderedEdges = useMemo(() => {
    const indices = new Map(aggregateGraph.clusters.map((cluster, index) => [cluster.key, index] as const));
    return aggregateGraph.edges.map((edge) => ({ edge, revealAt: Math.max(indices.get(edge.source) ?? Infinity, indices.get(edge.target) ?? Infinity) }))
      .sort((a, b) => a.revealAt - b.revealAt);
  }, [aggregateGraph.clusters, aggregateGraph.edges]);
  const renderedClusterEdges = useMemo(() => {
    let low = 0;
    let high = revealOrderedEdges.length;
    while (low < high) {
      const mid = (low + high) >>> 1;
      if (revealOrderedEdges[mid].revealAt < clusterRenderLimit) low = mid + 1;
      else high = mid;
    }
    return revealOrderedEdges.slice(0, low).map(({ edge }) => edge);
  }, [revealOrderedEdges, clusterRenderLimit]);
  const clusterMembership = useMemo(() => {
    const membership = new Map<string, string>();
    for (const cluster of aggregateGraph.clusters) {
      for (const member of cluster.members) membership.set(member.id, cluster.key);
    }
    return membership;
  }, [aggregateGraph.clusters]);
  const inspectedClusterRelationship = useMemo(() => {
    if (!inspectedClusterEdge) return [] as Edge[];
    const [source, target] = JSON.parse(inspectedClusterEdge) as [string, string];
    return renderedQueryEdges.filter((edge) => clusterMembership.get(edge.source) === source && clusterMembership.get(edge.target) === target);
  }, [inspectedClusterEdge, clusterMembership, renderedQueryEdges]);
  const inspectedClusterPageEdges = inspectedClusterRelationship.slice(clusterEdgePage * 25, (clusterEdgePage + 1) * 25);

  // The overlay is presentation-only: compare full report observations, then
  // draw only relationships whose endpoints are visible in the current graph.
  // Apply the same bounded observed-communication traversal independently to each capture.
  // Comparing edge sets never implies routing or physical reachability.
  const crossReportQuery = useMemo(() => {
    if (!baselineReport || !queryActive) return null;
    const execute = (capture: ElevadrReport) => {
      const snapshot = comparisonSnapshot(capture);
      const deviceMatches = (ip: string) => {
        const identified = classify(ip, capture);
        const device = identified.device;
        const subnet = (device?.subnets || device?.ipv4_subnets || [])[0] || "Unknown subnet";
        const attributes = device as (Device & { roleGroup?: string; role?: string; purdueLevel?: string; purdue_level?: string }) | undefined;
        const role = String(attributes?.roleGroup || attributes?.role || identified.type);
        const purdue = String(attributes?.purdueLevel || attributes?.purdue_level || "Unassigned");
        return (!query.type || identified.type === query.type) &&
          (!query.subnet || subnet.toLowerCase().includes(query.subnet.toLowerCase())) &&
          (!query.roleGroup || role.toLowerCase().includes(query.roleGroup.toLowerCase())) &&
          (!query.purdueLevel || purdue.toLowerCase().includes(query.purdueLevel.toLowerCase()));
      };
      const suspiciousPairs = new Set((capture.modules.suspicious_outbound_connections_panel || []).map((line) =>
        JSON.stringify([line["src_endpoint.ip"], line["dst_endpoint.ip"], line["service.name"] || "Unknown service"])));
      const eligible = [...snapshot.edges.entries()].filter(([key, edge]) =>
        (!query.service || edge.service.toLowerCase().includes(query.service.toLowerCase())) &&
        (!query.minCount || edge.count >= query.minCount) &&
        (query.suspicious === undefined || suspiciousPairs.has(key) === query.suspicious) &&
        (query.findingRelated === undefined || (comparisonFindings(capture, edge.source, edge.target).length > 0) === query.findingRelated));
      const seed = (query.startAsset || "").trim();
      if (!seed) return new Set(eligible.filter(([, edge]) => deviceMatches(edge.source) || deviceMatches(edge.target)).map(([key]) => key));
      const selected = new Set<string>();
      const visited = new Set([seed]);
      let frontier = new Set([seed]);
      for (let hop = 0; hop < Math.min(4, Math.max(1, query.maxHops || 1)) && frontier.size; hop++) {
        const next = new Set<string>();
        for (const [key, edge] of eligible) {
          const forward = query.direction !== "inbound" && frontier.has(edge.source);
          const reverse = query.direction !== "outbound" && frontier.has(edge.target);
          if (!forward && !reverse) continue;
          if (!deviceMatches(edge.source) && !deviceMatches(edge.target)) continue;
          selected.add(key);
          for (const neighbor of [forward ? edge.target : null, reverse ? edge.source : null]) {
            if (neighbor && !visited.has(neighbor)) { visited.add(neighbor); next.add(neighbor); }
          }
        }
        frontier = next;
      }
      return selected;
    };
    const baseline = execute(baselineReport);
    const current = execute(report);
    return { baseline, current,
      newlyMatched: [...current].filter((key) => !baseline.has(key)).length,
      noLongerMatched: [...baseline].filter((key) => !current.has(key)).length };
  }, [baselineReport, report, queryActive, query]);
  const comparisonChanges = useMemo(() => comparison?.changes.filter((change) => {
    if (comparisonFilter !== "All" && change.status !== comparisonFilter) return false;
    if (comparisonFindingsOnly && baselineReport && !comparisonFindings(baselineReport, change.edge.source, change.edge.target).length && !comparisonFindings(report, change.edge.source, change.edge.target).length) return false;
    if (comparisonQueryOnly && (!crossReportQuery || (!crossReportQuery.baseline.has(change.key) && !crossReportQuery.current.has(change.key)))) return false;
    return true;
  }) || [], [comparison, comparisonFilter, comparisonFindingsOnly, comparisonQueryOnly, baselineReport, report, crossReportQuery]);
  const selectedComparison = comparison?.changes.find((change) => change.key === selectedComparisonKey);
  const comparisonColors: Record<ComparisonChange["status"], string> = {
    New: "#16804a",
    "Count changed": "#ad7400",
    "Not observed": "#bd3945",
  };
  const topologyView = (
    <section
      className={`topology-card${isFullScreen ? " topology-card--expanded" : ""}`}
      ref={cardRef}
      aria-label="Network topology visualization"
    >
      <div className="topology-comparison-workspace" style={{ padding: "0.75rem", borderBottom: "1px solid #bbb" }}>
        <button type="button" aria-expanded={comparisonOpen} onClick={() => setComparisonOpen((open) => !open)}>
          {comparisonOpen ? "Hide report comparison" : "Compare with another report"}
        </button>
        {comparisonOpen && <div style={{ display: "grid", gap: "0.65rem", marginTop: "0.65rem" }}>
          <label>Baseline eleVADR JSON report <input type="file" accept=".json,application/json" onChange={(event) => void loadBaseline(event.target.files?.[0])} /></label>
          <small>Current report: {report.report_id || "Loaded report"}. Baseline: {baselineName || "None selected"}.</small>
          {comparisonError && <p role="alert">{comparisonError}</p>}
          {comparison && <>
            {crossReportQuery && <p role="status">Cross-report query traversal: {crossReportQuery.newlyMatched} newly matching relationships; {crossReportQuery.noLongerMatched} no longer matching relationships (observed communications only).</p>}
            <p role="status">{comparison.newAssets.length} newly observed assets; {comparison.missingAssets.length} assets not observed; {comparison.changes.length} changed communication relationships.</p>
            <small>Changes describe observations in the two reports, not confirmed physical network changes. Counts may reflect different capture durations or visibility.</small>
            <div className="topology-comparison-controls" style={{ display: "flex", alignItems: "center", gap: "0.75rem", flexWrap: "wrap" }}>
              <label><input type="checkbox" checked={comparisonOverlay} onChange={(event) => setComparisonOverlay(event.target.checked)} /> Show comparison on graph</label>
              <label><input type="checkbox" checked={comparisonFindingsOnly} onChange={(event) => { setComparisonFindingsOnly(event.target.checked); setComparisonPage(0); }} /> Finding-associated changes only</label>
              <label><input type="checkbox" checked={comparisonQueryOnly} onChange={(event) => { setComparisonQueryOnly(event.target.checked); setComparisonPage(0); }} disabled={!queryActive} /> Apply active query filters to differences</label>
              <label>Highlight <select value={comparisonFilter} onChange={(event) => { setComparisonFilter(event.target.value as typeof comparisonFilter); setComparisonPage(0); }}>
                <option value="All">All changes</option><option value="New">Newly observed</option><option value="Count changed">Count changed</option><option value="Not observed">Not observed</option>
              </select></label>
              <span aria-label="Comparison overlay legend" style={{ display: "inline-flex", gap: "0.7rem", flexWrap: "wrap" }}>
                <span style={{ color: "#16804a" }}>● New</span>
                <span style={{ color: "#ad7400" }}>● Count changed</span>
                <span style={{ color: "#bd3945" }}>┄ Not observed</span>
              </span>
            </div>
            <div className="topology-comparison-export" style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap", alignItems: "center" }}>
              <button type="button" onClick={() => exportComparison("csv")}>Export comparison CSV</button>
              <button type="button" onClick={() => exportComparison("json")}>Export comparison JSON</button>
              <label>Comparison name <input value={comparisonSavedName} maxLength={100} onChange={(event) => setComparisonSavedName(event.target.value)} /></label>
              <button type="button" disabled={comparisonBusy || !baselineReport || !comparisonSavedName.trim()} onClick={() => void saveComparisonSettings()}>Save comparison settings</button>
              <label>Recall settings <select value="" onChange={(event) => {
                const item = savedComparisons.find((entry) => entry.id === event.target.value);
                if (!item) return;
                void recallComparisonSettings(item);
              }}><option value="">Choose saved settings</option>{savedComparisons.map((entry) => <option key={entry.id} value={entry.id}>{entry.name}</option>)}</select></label>
              <button type="button" disabled={!comparisonSavedId || comparisonBusy} onClick={() => void deleteComparisonSettings()}>Delete saved comparison</button>
              <small>Saved comparison settings are stored in MongoDB. Retained baseline reports are restored automatically; otherwise choose a baseline JSON file.</small>
            </div>
            <details><summary>Newly observed assets ({comparison.newAssets.length})</summary><p>{comparison.newAssets.slice(0, 100).join(", ") || "None"}{comparison.newAssets.length > 100 ? " ..." : ""}</p></details>
            <details><summary>Assets not observed in current report ({comparison.missingAssets.length})</summary><p>{comparison.missingAssets.slice(0, 100).join(", ") || "None"}{comparison.missingAssets.length > 100 ? " ..." : ""}</p></details>
            <div><strong>Communication differences</strong>
              <div style={{ maxHeight: "220px", overflowY: "auto" }}>
                {comparisonChanges.slice(comparisonPage * 25, (comparisonPage + 1) * 25).map((change) => <button key={change.key} type="button"
                  aria-pressed={selectedComparisonKey === change.key}
                  onClick={() => setSelectedComparisonKey(change.key)}
                  style={{ display: "block", width: "100%", textAlign: "left", padding: "0.4rem", border: selectedComparisonKey === change.key ? "2px solid currentColor" : "1px solid transparent", background: "transparent", cursor: "pointer" }}>
                  {change.status}: {change.edge.source} to {change.edge.target} ({change.edge.service}) - baseline {change.baselineCount}, current {change.currentCount}
                </button>)}
                {!comparisonChanges.length && <p>No communication differences in the report-derived topology.</p>}
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                <button type="button" disabled={comparisonPage === 0} onClick={() => setComparisonPage((n) => Math.max(0, n - 1))}>Previous</button>
                <span>Page {comparisonPage + 1} of {Math.max(1, Math.ceil(comparisonChanges.length / 25))}</span>
                <button type="button" disabled={(comparisonPage + 1) * 25 >= comparisonChanges.length} onClick={() => setComparisonPage((n) => n + 1)}>Next</button>
              </div>
            </div>
            {selectedComparison && <aside role="region" aria-label="Selected communication comparison" style={{ border: "1px solid #aaa", borderRadius: "0.4rem", padding: "0.75rem", display: "grid", gap: "0.4rem" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <strong>Communication comparison details</strong>
                <button type="button" onClick={() => setSelectedComparisonKey(null)} aria-label="Close comparison details">Close</button>
              </div>
              <div><strong>Status:</strong> {selectedComparison.status}</div>
              <div><strong>Source:</strong> {selectedComparison.edge.source} <button type="button" onClick={() => onSelect({ type: "device", id: selectedComparison.edge.source })}>Inspect source asset</button></div>
              <div><strong>Destination:</strong> {selectedComparison.edge.target} <button type="button" onClick={() => onSelect({ type: "device", id: selectedComparison.edge.target })}>Inspect destination asset</button></div>
              <div><strong>Service:</strong> {selectedComparison.edge.service}</div>
              <div><strong>Baseline observations:</strong> {selectedComparison.baselineCount}</div>
              <div><strong>Current observations:</strong> {selectedComparison.currentCount}</div>
              <div><strong>Difference:</strong> {selectedComparison.currentCount - selectedComparison.baselineCount > 0 ? "+" : ""}{selectedComparison.currentCount - selectedComparison.baselineCount}</div>
              {baselineReport && <div>
                <strong>Associated findings (asset or flow evidence):</strong>
                <div>Baseline: {comparisonFindings(baselineReport, selectedComparison.edge.source, selectedComparison.edge.target).length}; Current: {comparisonFindings(report, selectedComparison.edge.source, selectedComparison.edge.target).length}</div>
                {comparisonFindings(report, selectedComparison.edge.source, selectedComparison.edge.target).slice(0, 15).map((finding, index) => <div key={index}>{finding.title} - {finding.severity}</div>)}
                <small>Finding association is based on referenced endpoints and may not identify the exact communication. Review the Findings section for evidence.</small>
              </div>}
              <small>These are report-derived observations, not proof of a physical link or actual reachability. Asset details refer to the current report; baseline-only assets may not be present.</small>
            </aside>}
            <button type="button" onClick={() => { setBaselineReport(null); setBaselineName(""); setComparisonPage(0); setSelectedComparisonKey(null); }}>Clear comparison</button>
          </>}
        </div>}
      </div>
      <div className="topology-query-workspace">
        <button type="button" aria-expanded={queryOpen} onClick={() => setQueryOpen((open) => !open)}>
          {queryOpen ? "Hide Query Explorer" : "Graph Query Explorer"}
        </button>
        {queryActive && <span role="status">{queryMatchingEdges.length} matching relationships · {queryNodeIds.size} assets</span>}
        {queryOpen && <div className="topology-query-panel">
          <div className="topology-query-primary">
            <label>Saved query
              <select value={savedQueryId || ""} onChange={(event) => {
                const saved = savedQueries.find((item) => item.id === event.target.value);
                setSavedQueryId(saved?.id || null);
                if (saved) { setQuery(saved.query); setQueryName(saved.name); setQueryActive(false); }
              }}>
                <option value="">New query</option>
                {savedQueries.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}
              </select>
            </label>
            <label>Investigation template
              <select value="" onChange={(event) => {
                const template = GRAPH_QUERY_TEMPLATES.find((item) => item.name === event.target.value);
                if (template) { setQuery(template.query); setQueryName(template.name); setSavedQueryId(null); setQueryActive(false); }
              }}>
                <option value="">Choose a template</option>
                {GRAPH_QUERY_TEMPLATES.map((item) => <option key={item.name} value={item.name}>{item.name}</option>)}
              </select>
            </label>
            <label>Query name<input maxLength={100} value={queryName} onChange={(event) => setQueryName(event.target.value)} placeholder="Name this investigation" /></label>
          </div>
          <div className="topology-query-builder" aria-label="Visual relationship builder">
            <strong>Relationship builder</strong>
            <div className="topology-query-path">
              <label>Starting asset IP<input placeholder="Any asset" value={query.startAsset || ""} onChange={(event) => setQuery((q) => ({ ...q, startAsset: event.target.value || undefined }))} /></label>
              <label>Direction<select value={query.direction || "both"} onChange={(event) => setQuery((q) => ({ ...q, direction: event.target.value as "both" | "outbound" | "inbound" }))}>
                <option value="both">Either direction ↔</option><option value="outbound">Source → destination</option><option value="inbound">Destination ← source</option>
              </select></label>
              <label>Depth<select value={query.maxHops || 1} onChange={(event) => setQuery((q) => ({ ...q, maxHops: Number(event.target.value) }))}>
                <option value={1}>1 hop</option><option value={2}>2 hops</option><option value={3}>3 hops</option><option value={4}>4 hops</option>
              </select></label>
              <label>Asset class<select value={query.type || ""} onChange={(event) => setQuery((q) => ({ ...q, type: event.target.value || undefined }))}>
                <option value="">Any class</option><option>OT</option><option>IT</option><option>Edge</option><option>Unknown</option>
              </select></label>
            </div>
            <p className="topology-query-hint">Find chains of observed communications. A multi-hop chain does not establish physical connectivity or network reachability.</p>
          </div>
          <button className="topology-query-advanced-toggle" type="button" aria-expanded={queryAdvanced} onClick={() => setQueryAdvanced((value) => !value)}>
            {queryAdvanced ? "Hide advanced filters −" : "Advanced filters +"}
          </button>
          {queryAdvanced && <div className="topology-query-fields">
            <label>Subnet contains<input value={query.subnet || ""} onChange={(event) => setQuery((q) => ({ ...q, subnet: event.target.value || undefined }))} /></label>
            <label>Purdue level contains<input value={query.purdueLevel || ""} onChange={(event) => setQuery((q) => ({ ...q, purdueLevel: event.target.value || undefined }))} /></label>
            <label>Role group contains<input value={query.roleGroup || ""} onChange={(event) => setQuery((q) => ({ ...q, roleGroup: event.target.value || undefined }))} /></label>
            <label>Service contains<input value={query.service || ""} onChange={(event) => setQuery((q) => ({ ...q, service: event.target.value || undefined }))} /></label>
            <label>Minimum observations<input type="number" min="1" value={query.minCount || ""} onChange={(event) => setQuery((q) => ({ ...q, minCount: event.target.value ? Number(event.target.value) : undefined }))} /></label>
            <label>Suspicious<select value={query.suspicious === undefined ? "any" : String(query.suspicious)} onChange={(event) => setQuery((q) => ({ ...q, suspicious: event.target.value === "any" ? undefined : event.target.value === "true" }))}>
              <option value="any">Any</option><option value="true">Yes</option><option value="false">No</option>
            </select></label>
            <label>Finding-related<select value={query.findingRelated === undefined ? "any" : String(query.findingRelated)} onChange={(event) => setQuery((q) => ({ ...q, findingRelated: event.target.value === "any" ? undefined : event.target.value === "true" }))}>
              <option value="any">Any</option><option value="true">Yes</option><option value="false">No</option>
            </select></label>
          </div>}
          <div className="topology-query-actions">
            <button type="button" onClick={() => { setQueryActive(true); setQueryResultsOpen(true); setQueryResultPage(0); }}>Run query</button>
            <button type="button" onClick={() => { setQueryActive(false); setShowOnlyQueryMatches(false); setQueryResultPage(0); }}>Clear results</button>
            <button type="button" disabled={queryBusy || !queryName.trim()} onClick={() => void saveGraphQuery()}>Save query</button>
            <button type="button" disabled={queryBusy || !savedQueryId} onClick={() => void deleteGraphQuery()}>Delete saved query</button>
          </div>
          {queryActive && <label className="topology-query-display-toggle">
            <input type="checkbox" checked={showOnlyQueryMatches} onChange={(event) => setShowOnlyQueryMatches(event.target.checked)} />
            Show only matching relationships in graph
          </label>}
          {queryError && <p role="alert">{queryError}</p>}
          {queryActive && <div className="topology-query-results">
            <button type="button" aria-expanded={queryResultsOpen} onClick={() => setQueryResultsOpen((value) => !value)}>
              {queryResultsOpen ? "Hide" : "Show"} results · {queryMatchingEdges.length} relationships · {queryNodeIds.size} assets
            </button>
            {queryResultsOpen && <div className="topology-query-result-list" role="region" aria-label="Matching observed communications">
              {pagedQueryEdges.map((edge) => <button type="button" key={edge.id} onClick={() => inspectEdge(edge)}>
                <span>{edge.source} → {edge.target}</span>
                <span>{edge.service} · {edge.count} observations{queryHopDepths.has(edge.id) ? ` · hop ${queryHopDepths.get(edge.id)}` : ""}</span>
              </button>)}
              {!queryMatchingEdges.length && <span>No matching communications in the report-derived graph.</span>}
              {queryMatchingEdges.length > QUERY_PAGE_SIZE && <div className="topology-query-pagination">
                <button type="button" disabled={effectiveQueryPage === 0} onClick={() => setQueryResultPage((page) => Math.max(0, page - 1))}>Previous</button>
                <span>Page {effectiveQueryPage + 1} of {queryPageCount} ({queryMatchingEdges.length} total)</span>
                <button type="button" disabled={effectiveQueryPage + 1 >= queryPageCount} onClick={() => setQueryResultPage((page) => Math.min(queryPageCount - 1, page + 1))}>Next</button>
              </div>}
            </div>}
          </div>}
          <small>Queries search all relationships available in this report; the visualization is limited for responsiveness. Maximum traversal depth: four hops.</small>
        </div>}
      </div>
      <div className="topology-cluster-controls" aria-label="Topology grouping and cluster drill-down">
        <strong className="topology-control-heading">Grouping and drill-down</strong>
        <label htmlFor="topology-cluster-mode">Group by</label>
        <select id="topology-cluster-mode" value={layoutMode} onChange={(event) => setLayoutMode(event.target.value as LayoutMode)}>
          <option value="class">Asset class</option>
          <option value="subnet">Subnet</option>
          <option value="purdue">Purdue level</option>
          <option value="role">Role group</option>
        </select>
        <label htmlFor="topology-cluster-focus">Cluster drill-down</label>
        <select id="topology-cluster-focus" value={clusterFocus} onChange={(event) => { setClusterFocus(event.target.value); setViewport(DEFAULT_VIEWPORT); }}>
          <option value="">All displayed clusters</option>
          {clusterSummaries.map(([name, count]) => <option key={name} value={name}>{name} ({count} assets)</option>)}
        </select>
        <button type="button" aria-expanded={clusterListOpen} onClick={() => setClusterListOpen((open) => !open)}>
          {clusterListOpen ? "Hide cluster summary" : "Cluster summary"}
        </button>
        <span role="status">{aggregateView ? `${aggregateGraph.clusters.length} aggregate nodes / ${nodes.length} display-candidate assets` : `${nodes.length} displayed assets / ${baseNodes.length} display candidates`}</span>
        {clusterFocus && <button type="button" onClick={() => { setClusterFocus(""); setViewport(DEFAULT_VIEWPORT); }}>Collapse to clusters</button>}
      </div>
      {clusterListOpen && <div className="topology-cluster-summary" aria-label="Cluster asset counts">
        {clusterSummaries.map(([name, count]) => <button key={name} type="button" onClick={() => { setClusterFocus(name); setViewport(DEFAULT_VIEWPORT); }}>
          {name}: {count} assets
        </button>)}
        <small>Counts describe the display-candidate graph, not necessarily every asset in the original capture. Query execution remains independent of this cluster filter.</small>
      </div>}
      {aggregateView && aggregateGraph.clusters.length > clusterRenderLimit && (
        <div className="topology-cluster-progress" role="status">
          Showing {renderedClusters.length} of {aggregateGraph.clusters.length} clusters and {renderedClusterEdges.length} of {aggregateGraph.edges.length} aggregated links.
          <button type="button" onClick={() => { setAutoRevealClusters(false); setClusterRenderLimit((value) => Math.min(value + 24, aggregateGraph.clusters.length)); }}>Show next 24 clusters</button>
          <button type="button" onClick={() => setAutoRevealClusters((value) => !value)}>{autoRevealClusters ? "Pause progressive display" : "Progressively show all"}</button>
          <button type="button" onClick={() => { setAutoRevealClusters(false); setClusterRenderLimit(24); }}>Reset cluster display</button>
        </div>
      )}
      {aggregateView && (
        <div className="topology-cluster-progress">
          <button type="button" aria-expanded={showPerformanceDetails} onClick={() => setShowPerformanceDetails((value) => !value)}>
            {showPerformanceDetails ? "Hide rendering diagnostics" : "Rendering diagnostics"}
          </button>
          {showPerformanceDetails && <span role="status">
            Rendered {renderedClusters.length}/{aggregateGraph.clusters.length} clusters and {renderedClusterEdges.length}/{aggregateGraph.edges.length} aggregated links.
            {lastFrameDelay !== null ? ` Last reveal scheduling delay: ${lastFrameDelay} ms.` : ""}
            {browserMetrics ? ` Browser frame intervals (last ${browserMetrics.samples}): mean ${browserMetrics.averageFrameMs} ms, p95 ${browserMetrics.p95FrameMs} ms, >50ms ${browserMetrics.slowFrames}; long tasks ${browserMetrics.longTasks}, longest ${browserMetrics.longestTaskMs} ms.` : " Sampling browser frames..."}
            {" "}Frame intervals include browser scheduling and background activity; they are not isolated topology paint timings.
          </span>}
        </div>
      )}
      {aggregateView && inspectedClusterEdge && (
        <div className="topology-cluster-inspector" role="region" aria-label="Aggregated communication details">
          <div className="topology-cluster-inspector-header"><strong>Observed relationships: {inspectedClusterRelationship.length}</strong>
            <button type="button" onClick={() => { setInspectedClusterEdge(null); setClusterEdgePage(0); }}>Close</button>
          </div>
          <p>These links are observed communications, not proof of routing or physical connectivity.</p>
          {inspectedClusterPageEdges.map((edge) => <button key={edge.id} type="button" onClick={() => inspectEdge(edge)}>
            {edge.source} to {edge.target} — {edge.service} ({edge.count} observations)
          </button>)}
          <div className="topology-cluster-inspector-pages">
            <button type="button" disabled={clusterEdgePage === 0} onClick={() => setClusterEdgePage((page) => page - 1)}>Previous</button>
            <span>Page {clusterEdgePage + 1} of {Math.max(1, Math.ceil(inspectedClusterRelationship.length / 25))}</span>
            <button type="button" disabled={(clusterEdgePage + 1) * 25 >= inspectedClusterRelationship.length} onClick={() => setClusterEdgePage((page) => page + 1)}>Next</button>
          </div>
        </div>
      )}
      {displayLimited && (
        <div className="topology-performance-note" role="status">
          Dense topology: showing the highest-activity {nodes.length} devices
          and {visibleEdges.length} links for responsive interaction. Use
          filters, Findings, or Selected + neighbors to narrow the view.
        </div>
      )}

      <div className="topology-toolbar topology-toolbar-option1">
        <div
          className="topology-toolbar-group topology-filter-group"
          aria-label="Topology display and filters"
        >
          <strong className="topology-control-heading">Display and filters</strong>
          <label className="topology-search">
            <span>Find</span>
            <input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Device or service…"
            />
          </label>
          <label>
            <span>Service</span>
            <select
              value={activeService}
              onChange={(event) => {
                const value = event.target.value;
                const current = filters.find(
                  (filter) => filter.key === "service",
                );
                if (value === "all") {
                  if (current) onFilter(current);
                } else onFilter({ key: "service", value, label: "Service" });
              }}
            >
              <option value="all">All observed</option>
              {activeService !== "all" && !services.includes(activeService) && (
                <option value={activeService}>{activeService}</option>
              )}
              {services.map((service) => (
                <option key={service}>{service}</option>
              ))}
            </select>
          </label>
          <label>
            <span>Filter device class</span>
            <select
              value={selectedClass}
              onChange={(event) => {
                const value = event.target.value;
                const current = filters.find(
                  (filter) => filter.key === "deviceClass",
                );
                if (value === "all") {
                  if (current) onFilter(current);
                } else onFilter({ key: "deviceClass", value, label: "Class" });
              }}
            >
              <option value="all">All classes</option>
              <option>OT</option>
              <option>IT</option>
              <option value="Edge">Network</option>
              <option>Unknown</option>
            </select>
          </label>
          <label className="topology-view-mode">
            <span>Display mode</span>
            <select
              value={preset === "risk" ? "findings" : "communication"}
              onChange={(event) => {
                if (event.target.value === "findings") applyPreset("risk");
                else applyPreset("simple");
              }}
              aria-label="Topology view"
            >
              <option value="communication">Communication</option>
              <option value="findings">Findings</option>
            </select>
          </label>
          <label className="topology-label-mode">
            <span>Labels</span>
            <select
              value={labelMode}
              onChange={(event) =>
                setLabelMode(event.target.value as LabelMode)
              }
              aria-label="Topology label density"
            >
              <option value="minimal">Minimal</option>
              <option value="full">Full</option>
              <option value="off">Off</option>
            </select>
          </label>
        </div>

        <div className="topology-toolbar-bottom-row">
          <div
            className="topology-toolbar-group topology-refinement-group"
            aria-label="Topology visibility refinements"
          >
            <label className={findingOnly ? "active" : ""}>
              <input
                type="checkbox"
                checked={findingOnly}
                onChange={(event) => setFindingOnly(event.target.checked)}
              />{" "}
              Finding-related
            </label>
            <label className={suspiciousOnly ? "active" : ""}>
              <input
                type="checkbox"
                checked={suspiciousOnly}
                onChange={(event) => setSuspiciousOnly(event.target.checked)}
              />{" "}
              Suspicious
            </label>
            <label className={hideIsolated ? "active" : ""}>
              <input
                type="checkbox"
                checked={hideIsolated}
                onChange={(event) => setHideIsolated(event.target.checked)}
              />{" "}
              Hide isolated
            </label>
            <label className={neighborsOnly ? "active" : ""}>
              <input
                type="checkbox"
                checked={neighborsOnly}
                disabled={!focusedNodeId}
                onChange={(event) => setNeighborsOnly(event.target.checked)}
              />{" "}
              Selected + neighbors
            </label>
          </div>

          <div className="topology-zoom-controls" aria-label="Topology actions">
            <button
              type="button"
              onClick={() => zoomBy(0.85)}
              aria-label="Zoom out"
              title="Zoom out"
            >
              −
            </button>
            <button
              type="button"
              onClick={() => zoomBy(1.18)}
              aria-label="Zoom in"
              title="Zoom in"
            >
              +
            </button>
            <button type="button" onClick={fitToView}>
              Fit
            </button>
            <button
              type="button"
              onClick={resetGraphView}
              aria-label="Reset graph view"
              title="Reset graph-only view settings without changing report filters"
            >
              Reset
            </button>
            <button
              type="button"
              onClick={toggleFullScreen}
              aria-pressed={isFullScreen}
            >
              {isFullScreen ? "Collapse panel" : "Expand panel"}
            </button>
            <button type="button" onClick={exportSvg}>
              Export SVG
            </button>
          </div>
        </div>
      </div>

      {(focusedNode || focusedEdge) && (
        <div
          className="topology-selection-bar"
          role="status"
          aria-live="polite"
        >
          <div>
            <strong>
              {focusedNode
                ? `Device ${focusedNode.id}`
                : `${focusedEdge!.source} → ${focusedEdge!.target}`}
            </strong>
            <span>
              {focusedNode
                ? `${focusedNode.type} · ${focusedPeerCount} connected peer${focusedPeerCount === 1 ? "" : "s"} · ${focusedNode.findingCount} finding${focusedNode.findingCount === 1 ? "" : "s"}`
                : `${focusedEdge!.service} · ${focusedEdge!.count.toLocaleString()} observation${focusedEdge!.count === 1 ? "" : "s"}${focusedEdge!.findingRelated || focusedEdge!.suspicious ? " · finding-related" : ""}`}
            </span>
          </div>
          <div className="topology-selection-actions">
            <button
              type="button"
              className="topology-filter-action"
              onClick={focusedNode ? filterFocusedDevice : filterFocusedService}
              aria-pressed={
                focusedNode
                  ? focusedDeviceFilterActive
                  : focusedServiceFilterActive
              }
              title={
                focusedNode
                  ? `${focusedDeviceFilterActive ? "Remove" : "Apply"} device filter: ${focusedNode.id}`
                  : `${focusedServiceFilterActive ? "Remove" : "Apply"} service filter: ${focusedEdge?.service || "service"}`
              }
            >
              <svg viewBox="0 0 24 24" aria-hidden="true">
                <path d="M4 5h16l-6 7v5l-4 2v-7L4 5Z" />
              </svg>
              {focusedNode
                ? `${focusedDeviceFilterActive ? "Remove" : "Filter"} device`
                : `${focusedServiceFilterActive ? "Remove" : "Filter"} service`}
            </button>
            <button type="button" onClick={clearGraphSelection}>
              Clear selection
            </button>
          </div>
        </div>
      )}

      {nodes.length ? (
        <div className="topology-canvas">
          <svg
            ref={svgRef}
            viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
            preserveAspectRatio="xMidYMid meet"
            onWheel={handleWheel}
            onPointerDown={handleCanvasPointerDown}
            onPointerMove={handleCanvasPointerMove}
            onPointerUp={handleCanvasPointerUp}
            onPointerCancel={handleCanvasPointerUp}
            role="img"
            aria-label={aggregateView ? `Clustered network topology with ${aggregateGraph.clusters.length} clusters and ${aggregateGraph.edges.length} aggregated communication links` : `Interactive network topology with ${nodes.length} devices and ${visibleEdges.length} communication links`}
          >
            <defs>
              <marker
                id="topology-arrow"
                viewBox="0 0 10 10"
                refX="8"
                refY="5"
                markerWidth="5"
                markerHeight="5"
                orient="auto-start-reverse"
              >
                <path d="M 0 0 L 10 5 L 0 10 z" fill="#8ca8b7" />
              </marker>
              <marker
                id="topology-arrow-finding"
                viewBox="0 0 10 10"
                refX="8"
                refY="5"
                markerWidth="5"
                markerHeight="5"
                orient="auto-start-reverse"
              >
                <path d="M 0 0 L 10 5 L 0 10 z" fill="#397b9d" />
              </marker>
              <marker
                id="topology-arrow-suspicious"
                viewBox="0 0 10 10"
                refX="8"
                refY="5"
                markerWidth="5"
                markerHeight="5"
                orient="auto-start-reverse"
              >
                <path d="M 0 0 L 10 5 L 0 10 z" fill="#b65349" />
              </marker>
              <marker
                id="topology-arrow-focused"
                viewBox="0 0 10 10"
                refX="8"
                refY="5"
                markerWidth="5"
                markerHeight="5"
                orient="auto-start-reverse"
              >
                <path d="M 0 0 L 10 5 L 0 10 z" fill="#005ea8" />
              </marker>
              <filter
                id="node-shadow"
                x="-60%"
                y="-60%"
                width="220%"
                height="220%"
              >
                <feDropShadow
                  dx="0"
                  dy="2"
                  stdDeviation="3"
                  floodOpacity="0.16"
                />
              </filter>
            </defs>
            <g
              transform={`translate(${viewport.x} ${viewport.y}) scale(${viewport.scale})`}
            >
              {aggregateView ? (
                <g className="topology-aggregate-view">
                  {renderedClusterEdges.map((edge) => {
                    const source = clusterPositions.get(edge.source);
                    const target = clusterPositions.get(edge.target);
                    if (!source || !target) return null;
                    return <g key={JSON.stringify([edge.source, edge.target])} role="button" tabIndex={0}
                      aria-label={`Inspect ${edge.relationships} observed relationships from ${edge.source} to ${edge.target}`}
                      onPointerDown={(event) => event.stopPropagation()}
                      onClick={(event) => { event.stopPropagation(); setInspectedClusterEdge(JSON.stringify([edge.source, edge.target])); setClusterEdgePage(0); }}
                      onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); setInspectedClusterEdge(JSON.stringify([edge.source, edge.target])); setClusterEdgePage(0); } }}>
                      <line x1={source.x} y1={source.y} x2={target.x} y2={target.y} stroke={edge.suspicious ? "#b65349" : edge.findingRelated ? "#397b9d" : "#8ca8b7"} strokeWidth={Math.min(9, 1.5 + Math.log10(edge.count + 1) * 1.8)} markerEnd="url(#topology-arrow)" />
                      <title>{`${edge.source} to ${edge.target}: ${edge.count} observations across ${edge.relationships} relationships; protocols: ${[...edge.services].join(", ")}`}</title>
                    </g>;
                  })}
                  {comparison && comparisonOverlay && comparisonChanges.map((change) => {
                    const sourceGroup = clusterMembership.get(change.edge.source);
                    const targetGroup = clusterMembership.get(change.edge.target);
                    if (!sourceGroup || !targetGroup || sourceGroup === targetGroup) return null;
                    const source = clusterPositions.get(sourceGroup);
                    const target = clusterPositions.get(targetGroup);
                    if (!source || !target) return null;
                    return <g key={`compare-${change.key}`} role="button" tabIndex={0} aria-label={`Inspect ${change.status} communication between ${change.edge.source} and ${change.edge.target}`}
                      onClick={(event) => { event.stopPropagation(); setSelectedComparisonKey(change.key); setComparisonOpen(true); }}
                      onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); setSelectedComparisonKey(change.key); setComparisonOpen(true); } }}>
                      <line x1={source.x} y1={source.y} x2={target.x} y2={target.y} stroke="transparent" strokeWidth="16" />
                      <line x1={source.x} y1={source.y} x2={target.x} y2={target.y}
                        stroke={comparisonColors[change.status]} strokeWidth={selectedComparisonKey === change.key ? 5 : 2.5}
                        strokeDasharray={change.status === "Not observed" ? "7 5" : undefined} opacity="0.9" pointerEvents="none" />
                      <title>{`${change.status}: ${change.edge.source} to ${change.edge.target} (${change.edge.service})`}</title>
                    </g>;
                  })}
                  {renderedClusters.map((cluster) => (
                    <g key={cluster.key} transform={`translate(${cluster.x} ${cluster.y})`} role="button" tabIndex={0}
                      aria-label={`Expand ${cluster.key}, ${cluster.members.length} assets`}
                      onPointerDown={(event) => event.stopPropagation()}
                      onClick={(event) => { event.stopPropagation(); setClusterFocus(cluster.key); setViewport(DEFAULT_VIEWPORT); }}
                      onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); setClusterFocus(cluster.key); setViewport(DEFAULT_VIEWPORT); } }}>
                      <rect x="-78" y="-28" width="156" height="56" rx="12" fill="#e5f0f7" stroke="#397b9d" strokeWidth="2" />
                      <text textAnchor="middle" y="-4" fontSize="13" fontWeight="600" fill="#153c56">{cluster.key.length > 22 ? `${cluster.key.slice(0, 21)}…` : cluster.key}</text>
                      <text textAnchor="middle" y="15" fontSize="12" fill="#285775">{cluster.members.length} assets · expand</text>
                      <title>{cluster.key}: {cluster.members.length} displayed assets. Activate to drill down.</title>
                    </g>
                  ))}
                </g>
              ) : (<>
              {layoutMode === "class" && (
                <g className="topology-zone-labels" aria-hidden="true">
                  <text x="185" y="46">
                    IT
                  </text>
                  <text x="520" y="46">
                    EDGE / TRANSIT
                  </text>
                  <text x="855" y="46">
                    OT
                  </text>
                </g>
              )}
              {layoutMode !== "class" && (
                <g
                  className={`topology-group-regions topology-group-${layoutMode}`}
                  aria-hidden="true"
                >
                  {groupRegions.map((region) => (
                    <g
                      key={region.key}
                      className="topology-subnet-region topology-group-region"
                    >
                      <rect
                        x={region.x}
                        y={region.y}
                        width={region.width}
                        height={region.height}
                        rx="14"
                      />
                      {labelMode !== "off" && (
                        <g
                          className="topology-subnet-label topology-group-label"
                          transform={`translate(${region.x + 12} ${region.y + 17})`}
                        >
                          <text>{region.label}</text>
                          <text
                            className="topology-subnet-count"
                            x={Math.min(
                              region.width - 24,
                              Math.max(76, region.label.length * 6.5 + 12),
                            )}
                          >
                            {region.count} device{region.count === 1 ? "" : "s"}
                          </text>
                        </g>
                      )}
                    </g>
                  ))}
                </g>
              )}
              {renderedQueryEdges.map((edge) => {
                const source = nodeMap.get(edge.source)!;
                const target = nodeMap.get(edge.target)!;
                const midX = (source.x + target.x) / 2;
                const midY = (source.y + target.y) / 2;
                const width = Math.min(
                  4.5,
                  1 + Math.log10(edge.count + 1) * 1.05,
                );
                const crossSubnet = source.subnet !== target.subnet;
                const crossRole = source.roleGroup !== target.roleGroup;
                const crossPurdue = source.purdueLevel !== target.purdueLevel;
                const crossBoundary =
                  layoutMode === "subnet"
                    ? crossSubnet
                    : layoutMode === "role"
                      ? crossRole
                      : layoutMode === "purdue"
                        ? crossPurdue
                        : false;
                const marker =
                  focusedEdgeId === edge.id
                    ? "url(#topology-arrow-focused)"
                    : edge.suspicious
                      ? "url(#topology-arrow-suspicious)"
                      : edge.findingRelated
                        ? "url(#topology-arrow-finding)"
                        : "url(#topology-arrow)";
                return (
                  <g
                    key={edge.id}
                    className={`topology-edge ${edge.suspicious ? "suspicious" : ""} ${edge.findingRelated ? "finding-related" : ""} ${crossBoundary ? "cross-boundary" : ""} ${focusedEdgeId === edge.id ? "focused" : ""} ${focusedNodeId && edge.source !== focusedNodeId && edge.target !== focusedNodeId ? "dimmed" : ""} ${focusedEdgeId && focusedEdgeId !== edge.id ? "dimmed" : ""} ${queryActive && !queryEdgeIds.has(edge.id) ? "query-dimmed" : ""} ${queryActive && queryEdgeIds.has(edge.id) ? "query-match" : ""}`}
                    onPointerDown={(event) => event.stopPropagation()}
                    onClick={(event) => {
                      event.stopPropagation();
                      inspectEdge(edge);
                    }}
                    onMouseEnter={() => setHoveredEdgeId(edge.id)}
                    onMouseLeave={() =>
                      setHoveredEdgeId((current) =>
                        current === edge.id ? null : current,
                      )
                    }
                    tabIndex={0}
                    role="button"
                    aria-label={`${edge.source} to ${edge.target}, ${edge.service}, ${edge.count} observations`}
                    onKeyDown={(event) => {
                      if (event.key === "Enter" || event.key === " ") {
                        event.preventDefault();
                        inspectEdge(edge);
                      }
                    }}
                  >
                    <line
                      className="topology-edge-hit"
                      x1={source.x}
                      y1={source.y}
                      x2={target.x}
                      y2={target.y}
                      strokeWidth={Math.max(16, width + 12)}
                    />
                    <line
                      className="topology-edge-visible"
                      x1={source.x}
                      y1={source.y}
                      x2={target.x}
                      y2={target.y}
                      strokeWidth={width}
                      markerEnd={marker}
                    />
                    {!isInteracting &&
                      (labelMode === "full" ||
                        (labelMode === "minimal" &&
                          (hoveredEdgeId === edge.id ||
                            focusedEdgeId === edge.id))) && (
                        <g
                          className="topology-edge-label"
                          transform={`translate(${midX} ${midY})`}
                        >
                          <rect
                            x={-Math.min(72, edge.service.length * 3.6 + 10)}
                            y="-8"
                            width={Math.min(
                              144,
                              edge.service.length * 7.2 + 20,
                            )}
                            height="16"
                            rx="7"
                          />
                          <text textAnchor="middle" dominantBaseline="central">
                            {edge.service.length > 18
                              ? `${edge.service.slice(0, 17)}…`
                              : edge.service}
                          </text>
                        </g>
                      )}
                    <title>
                      {edge.service} • {edge.count.toLocaleString()}{" "}
                      observations{edge.suspicious ? " • suspicious" : ""}
                    </title>
                  </g>
                );
              })}
              {nodes.map((node) => {
                const radius =
                  12 + Math.min(10, (node.degree / maxDegree) * 10);
                return (
                  <g
                    key={node.id}
                    className={`topology-node node-${node.type.toLowerCase()} ${selectedIp === node.id ? "selected" : ""} ${focusedNodeId === node.id ? "focused" : ""} ${focusedNodeId && !neighborIds.has(node.id) ? "dimmed" : ""} ${focusedEdge && node.id !== focusedEdge.source && node.id !== focusedEdge.target ? "dimmed" : ""} ${node.findingCount ? "finding-related" : ""} ${queryActive && !queryNodeIds.has(node.id) ? "query-dimmed" : ""} ${queryActive && queryNodeIds.has(node.id) ? "query-match" : ""}`}
                    transform={`translate(${node.x} ${node.y})`}
                    onPointerDown={(event) => event.stopPropagation()}
                    onClick={(event) => {
                      event.stopPropagation();
                      inspectNode(node);
                    }}
                    onDoubleClick={(event) => {
                      event.stopPropagation();
                      focusNodeNeighborhood(node);
                    }}
                    onMouseEnter={() => setHoveredNodeId(node.id)}
                    onMouseLeave={() =>
                      setHoveredNodeId((current) =>
                        current === node.id ? null : current,
                      )
                    }
                    tabIndex={0}
                    role="button"
                    aria-label={`${node.type} device ${node.id}`}
                    onKeyDown={(event) => {
                      if (event.key === "Enter" || event.key === " ") {
                        event.preventDefault();
                        inspectNode(node);
                      }
                    }}
                  >
                    <circle className="node-hit" r={radius + 8} />
                    <circle className="node-halo" r={radius + 5} />
                    <circle
                      className="node-ring"
                      r={radius}
                      filter="url(#node-shadow)"
                    />
                    <circle
                      className="node-core"
                      r={Math.max(4.5, radius * 0.36)}
                    />
                    <text className="node-type" y="3" textAnchor="middle">
                      {node.type === "Unknown" ? "?" : node.type.charAt(0)}
                    </text>
                    <circle
                      className="node-drag-handle"
                      cx={radius + 5}
                      cy={radius + 5}
                      r="6"
                      role="button"
                      aria-label={`Move device ${node.id}`}
                      onPointerDown={(event) => beginNodeDrag(event, node)}
                      onPointerUp={finishNodeDrag}
                      onPointerCancel={finishNodeDrag}
                      onClick={(event) => {
                        event.preventDefault();
                        event.stopPropagation();
                      }}
                    />
                    {node.findingCount > 0 && (
                      <g
                        className="topology-finding-marker"
                        transform={`translate(${radius - 2} ${-radius + 2})`}
                        aria-hidden="true"
                      >
                        <circle r="6" />
                        <text y="2.6" textAnchor="middle">
                          !
                        </text>
                      </g>
                    )}
                    {!isInteracting &&
                      (labelMode === "full" ||
                        (labelMode === "minimal" &&
                          (hoveredNodeId === node.id ||
                            focusedNodeId === node.id ||
                            selectedIp === node.id))) && (
                        <g
                          className="topology-node-label"
                          transform={`translate(0 ${radius + 18})`}
                        >
                          <rect x="-48" y="-11" width="96" height="21" rx="8" />
                          <text textAnchor="middle" dominantBaseline="central">
                            {node.id}
                          </text>
                        </g>
                      )}
                    <title>
                      {node.type} • {node.id}
                      {node.manufacturer ? ` • ${node.manufacturer}` : ""} • $
                      {node.subnet} • ${node.roleGroup} • ${node.purdueLevel} •
                      ${node.degree.toLocaleString()} observations$
                      {node.findingCount
                        ? ` • ${node.findingCount} finding${node.findingCount === 1 ? "" : "s"}`
                        : ""}
                    </title>
                  </g>
                );
              })}
              </>)}
              {comparison && comparisonOverlay && !aggregateView && (
                <g className="topology-comparison-overlay" aria-label="Observed communication differences">
                  {comparisonChanges.map((change) => {
                    const source = nodeMap.get(change.edge.source);
                    const target = nodeMap.get(change.edge.target);
                    if (!source || !target) return null;
                    return <g key={change.key} role="button" tabIndex={0} aria-label={`Inspect ${change.status} communication between ${change.edge.source} and ${change.edge.target}`}
                      onClick={(event) => { event.stopPropagation(); setSelectedComparisonKey(change.key); setComparisonOpen(true); }}
                      onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); setSelectedComparisonKey(change.key); setComparisonOpen(true); } }}>
                      <line x1={source.x} y1={source.y} x2={target.x} y2={target.y} stroke="transparent" strokeWidth="16" />
                      <line x1={source.x} y1={source.y} x2={target.x} y2={target.y}
                        stroke={comparisonColors[change.status]} strokeWidth={selectedComparisonKey === change.key ? 7 : change.status === "Count changed" ? 5 : 3.5}
                        strokeDasharray={change.status === "Not observed" ? "7 5" : undefined} opacity="0.9" pointerEvents="none" />
                      <title>{`${change.status}: ${change.edge.source} to ${change.edge.target} (${change.edge.service}); baseline ${change.baselineCount}, current ${change.currentCount}`}</title>
                    </g>;
                  })}
                </g>
              )}
            </g>
          </svg>

          <div
            className={`topology-legend ${legendOpen ? "expanded" : "collapsed"}`}
          >
            <button
              type="button"
              className="topology-legend-toggle"
              aria-expanded={legendOpen}
              onClick={() => setLegendOpen((open) => !open)}
            >
              <span>Legend</span>
              <span aria-hidden="true">{legendOpen ? "−" : "+"}</span>
            </button>
            {legendOpen && (
              <div className="topology-legend-items">
                <span>
                  <i className="legend-role legend-ot" />
                  OT
                </span>
                <span>
                  <i className="legend-role legend-it" />
                  IT
                </span>
                <span>
                  <i className="legend-role legend-edge" />
                  Network
                </span>
                <span>
                  <i className="legend-role legend-unknown" />
                  Unknown
                </span>
                <span>
                  <i className="legend-finding" />
                  Finding-related
                </span>
                <span>
                  <i className="legend-suspicious" />
                  Suspicious outbound
                </span>
                {layoutMode !== "class" && (
                  <span>
                    <i className="legend-cross-subnet" />
                    Cross-
                    {layoutMode === "subnet"
                      ? "subnet"
                      : layoutMode === "role"
                        ? "role"
                        : "Purdue"}
                  </span>
                )}
                <span className="legend-hint">
                  Click = details · drag handle = move · double-click = focus ·
                  funnel = filter · drag background = pan · Ctrl/⌘ + wheel =
                  zoom · Esc = clear
                </span>
              </div>
            )}
          </div>
        </div>
      ) : (
        <div className="topology-empty" role="status">
          <strong>
            {search.trim()
              ? "No topology matches this search."
              : findingOnly
                ? "No finding-related topology is visible."
                : suspiciousOnly
                  ? "No suspicious outbound topology is visible."
                  : neighborsOnly
                    ? "No selected-neighbor topology is visible."
                    : "No topology matches the current filters."}
          </strong>
          <span>
            {search.trim() || findingOnly || suspiciousOnly || neighborsOnly
              ? "Clear the topology refinements to return to the current report view."
              : "Clear the investigation filters or load a report with endpoint communication data."}
          </span>
          {(search.trim() ||
            findingOnly ||
            suspiciousOnly ||
            neighborsOnly) && (
            <button type="button" onClick={clearGraphRefinements}>
              Clear topology refinements
            </button>
          )}
        </div>
      )}
    </section>
  );

  // Render the expanded workspace outside the report Panel clipping/stacking
  // context. Keep the component itself mounted so graph state is preserved.
  return isFullScreen ? createPortal(topologyView, document.body) : topologyView;
};

export default NetworkTopology;
