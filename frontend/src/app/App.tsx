import React, { useEffect, useMemo, useRef, useState } from "react";
import "./App.css";
import "./saved-report-interactions.css";
import "./pcap-icon-actions.css";
import "./dhs-cisa-theme.css";
import "./dhs-a11y-hardening.css";
import { ElevadrReport } from "./types/Report";

import DevicePanel from "./components/DevicePanel/DevicePanel";
import ServiceRiskBreakdownPanel from "./components/ServiceRiskBreakdownPanel/ServiceRiskBreakdownPanel";
import ServiceInventoryPanel from "./components/ServiceInventoryPanel";
import ConnectionSuccessPanel from "./components/ConnectionSuccessPanel/ConnectionSuccessPanel";
import ConnectionOverviewPanel from "./components/ConnectionOverviewPanel/ConnectionOverviewPanel";
import SuspiciousOutboundConnectionsPanel from "./components/SuspiciousOutboundConnectionsPanel/SuspiciousOutboundConnectionsPanel";
import OTCrossSegmentPanel from "./components/OTCrossSegmentPanel/OTCrossSegmentPanel";
import DevicesPanel from "./components/DevicesPanel/DevicesPanel";
import UploadForm from "./components/UploadForm/UploadForm";
import SecurityOverview from "./components/SecurityOverview/SecurityOverview";
import ReportSearch from "./components/ReportSearch/ReportSearch";
import InvestigationBar from "./components/InvestigationBar/InvestigationBar";
import FindingsPanel, {
  deriveFindings,
} from "./components/FindingsPanel/FindingsPanel";
import NetworkTopology, {
  NetworkTopologyState,
} from "./components/NetworkTopology/NetworkTopology";
import ActivityTimeline from "./components/ActivityTimeline/ActivityTimeline";
import Panel from "./components/Panel/Panel";
import InfoTooltip from "./components/InfoTooltip/InfoTooltip";
import EntityDrawer from "./components/EntityDrawer/EntityDrawer";
import HelpDrawer from "./components/HelpDrawer/HelpDrawer";
import FirstRunTour from "./components/FirstRunTour/FirstRunTour";
import ZeekFlowAnalysis from "./components/ZeekFlowAnalysis";
import SupplementalSubnetPanel, {
  SupplementalSubnet,
} from "./components/SupplementalSubnetPanel";
import DetectionConfiguration from "./components/DetectionConfiguration/DetectionConfiguration";
import DetectionModuleSelector from "./components/DetectionModuleSelector/DetectionModuleSelector";
import "./report-consistency.css";
import ReportCustomization, {
  REPORT_SECTION_OPTIONS,
  ReportSectionId,
} from "./components/ReportCustomization/ReportCustomization";
import ReportGuidance from "./components/ReportGuidance/ReportGuidance";
import {
  InvestigationFilter,
  InvestigationFilterKey,
  SelectedEntity,
} from "./types/Investigation";
import {
  AUTH_EXPIRED_EVENT,
  AuthState,
  fetchAuthState,
  login,
  logout,
  authenticatedFetch,
  renewProcessingSession,
  tokenExpiresWithin,
} from "./services/authService";
import {
  deleteSavedReport,
  listSavedReports,
  loadSavedReport,
  renameSavedReport,
  SavedReportSummary,
} from "./services/reportService";
import { normalizeElevadrReport } from "./utils/reportCompatibility";
import {
  listRetainedCaptures,
  deleteRetainedCapture,
  downloadRetainedCapture,
  analyzeRetainedCapture,
  RetainedCaptureSummary,
} from "./services/captureService";
import {
  loadActiveProfile,
  normalizeProfile,
} from "./components/DetectionConfiguration/profile";
import {
  changeOwnPassword,
  createUser,
  listUsers,
  PlatformUser,
  updateUser,
} from "./services/accountService";
import { listAuditEvents, type AuditEvent } from "./services/auditService";
import {
  cleanupStorage,
  getStorageSummary,
  type StorageSummary,
} from "./services/storageService";
import {
  compareReports,
  formatComparisonValue,
  type ReportComparison,
} from "./utils/reportComparison";

const SUPPORTED_REPORT_MAJOR_VERSION = "2";

type IconName =
  | "upload"
  | "overview"
  | "traffic"
  | "assets"
  | "menu"
  | "shield"
  | "search"
  | "code"
  | "download"
  | "chevron"
  | "network"
  | "findings"
  | "topology"
  | "print"
  | "timeline"
  | "share"
  | "notes"
  | "help"
  | "settings"
  | "services"
  | "edit"
  | "trash"
  | "check"
  | "close"
  | "history"
  | "refresh"
  | "user";

function isSupportedReportVersion(version?: string): boolean {
  if (!version || typeof version !== "string") return false;
  return version.split(".")[0] === SUPPORTED_REPORT_MAJOR_VERSION;
}

const ALL_REPORT_SECTION_IDS = REPORT_SECTION_OPTIONS.map(
  (section) => section.id,
);

function initialReportSections(): Set<ReportSectionId> {
  const encoded = new URLSearchParams(window.location.search).get(
    "reportSections",
  );
  if (!encoded) return new Set(ALL_REPORT_SECTION_IDS);
  const allowed = new Set<ReportSectionId>(ALL_REPORT_SECTION_IDS);
  const selected = encoded
    .split(",")
    .filter((value): value is ReportSectionId =>
      allowed.has(value as ReportSectionId),
    );
  return selected.length ? new Set(selected) : new Set(ALL_REPORT_SECTION_IDS);
}

function moduleDisplayName(id: string): string {
  return id
    .split("_")
    .map((word) => (word ? word[0].toUpperCase() + word.slice(1) : word))
    .join(" ");
}

function contributingModules(
  report: ElevadrReport,
  section: ReportSectionId,
): string[] {
  const raw = report.arch_insights?.detector_findings;
  if (!Array.isArray(raw)) return [];
  const ids = new Set<string>();
  raw.forEach((finding) => {
    if (!finding || typeof finding !== "object") return;
    const item = finding as Record<string, unknown>;
    const moduleId = typeof item.module_id === "string" ? item.module_id : "";
    if (!moduleId) return;
    const devices = Array.isArray(item.devices) ? item.devices : [];
    const services = Array.isArray(item.services) ? item.services : [];
    const pairs = Array.isArray(item.connection_pairs)
      ? item.connection_pairs
      : [];
    const flows = Array.isArray(item.flows) ? item.flows : [];
    if (section === "overview" || section === "findings") ids.add(moduleId);
    if (section === "devices" && devices.length) ids.add(moduleId);
    if (section === "services" && services.length) ids.add(moduleId);
    if (section === "connections" && (pairs.length || flows.length))
      ids.add(moduleId);
  });
  return [...ids].sort();
}

const ModuleContributionBadge: React.FC<{
  report: ElevadrReport;
  section: ReportSectionId;
}> = ({ report, section }) => {
  const modules = contributingModules(report, section);
  if (!modules.length) return null;
  const names = modules.map(moduleDisplayName);
  return (
    <span
      className="module-contribution-badge"
      title={names.join("\n")}
      aria-label={`${modules.length} detection module${modules.length === 1 ? "" : "s"} contributed to this section`}
    >
      <span aria-hidden="true">◈</span>{" "}
      {modules.length === 1 ? names[0] : `${modules.length} detector modules`}
    </span>
  );
};

const REPORT_SECTION_META: Record<
  ReportSectionId,
  { label: string; description: string; icon: IconName }
> = {
  overview: {
    label: "Summary",
    description:
      "High-level security posture, analysis context, and overall report highlights.",
    icon: "overview",
  },
  findings: {
    label: "Findings",
    description:
      "Detected conditions, anomalies, and security observations that warrant review.",
    icon: "shield",
  },
  devices: {
    label: "Devices",
    description:
      "Observed assets, identity details, classifications, and device-level activity.",
    icon: "assets",
  },
  services: {
    label: "Services",
    description:
      "Known and unknown network services observed across the analyzed environment.",
    icon: "services",
  },
  topology: {
    label: "Topology",
    description: "Observed network topology and investigation graph.",
    icon: "topology",
  },
  connections: {
    label: "Connections",
    description:
      "Communication paths, flows, topology, and cross-segment network activity.",
    icon: "traffic",
  },
};

const ReportSectionHeading: React.FC<{
  report: ElevadrReport;
  section: ReportSectionId;
}> = ({ report, section }) => {
  const meta = REPORT_SECTION_META[section];
  return (
    <header
      className={`section-heading report-section-heading report-section-heading--${section}`}
    >
      <div className="report-section-heading-main">
        <span className="report-section-icon" aria-hidden="true">
          <Icon name={meta.icon} />
        </span>
        <div className="report-section-heading-copy">
          <h2>{meta.label}</h2>
          <p>{meta.description}</p>
        </div>
      </div>
      <ModuleContributionBadge report={report} section={section} />
    </header>
  );
};

const Icon = ({ name }: { name: IconName }) => {
  const paths: Record<IconName, React.ReactNode> = {
    upload: (
      <>
        <path d="M12 16V4" />
        <path d="m7 9 5-5 5 5" />
        <path d="M5 20h14" />
      </>
    ),
    overview: (
      <>
        <rect x="4" y="4" width="6" height="6" rx="1" />
        <rect x="14" y="4" width="6" height="6" rx="1" />
        <rect x="4" y="14" width="6" height="6" rx="1" />
        <rect x="14" y="14" width="6" height="6" rx="1" />
      </>
    ),
    traffic: (
      <>
        <path d="M4 7h12" />
        <path d="m13 4 3 3-3 3" />
        <path d="M20 17H8" />
        <path d="m11 14-3 3 3 3" />
      </>
    ),
    assets: (
      <>
        <rect x="4" y="5" width="16" height="11" rx="2" />
        <path d="M8 20h8" />
        <path d="M12 16v4" />
      </>
    ),
    menu: (
      <>
        <path d="M4 7h16" />
        <path d="M4 12h16" />
        <path d="M4 17h16" />
      </>
    ),
    shield: (
      <>
        <path d="M12 3 5 6v5c0 4.6 2.9 8 7 10 4.1-2 7-5.4 7-10V6l-7-3Z" />
        <path d="m9 12 2 2 4-4" />
      </>
    ),
    search: (
      <>
        <circle cx="11" cy="11" r="6" />
        <path d="m16 16 4 4" />
      </>
    ),
    code: (
      <>
        <path d="m9 8-4 4 4 4" />
        <path d="m15 8 4 4-4 4" />
      </>
    ),
    download: (
      <>
        <path d="M12 4v11" />
        <path d="m7 11 5 5 5-5" />
        <path d="M5 20h14" />
      </>
    ),
    chevron: <path d="m9 18 6-6-6-6" />,
    network: (
      <>
        <circle cx="6" cy="7" r="2" />
        <circle cx="18" cy="7" r="2" />
        <circle cx="12" cy="18" r="2" />
        <path d="m7.7 8.1 3 7.5M16.3 8.1l-3 7.5M8 7h8" />
      </>
    ),
    findings: (
      <>
        <path d="M5 4h14v16H5z" />
        <path d="M8 8h8M8 12h5M8 16h6" />
      </>
    ),
    topology: (
      <>
        <circle cx="5" cy="6" r="2" />
        <circle cx="19" cy="6" r="2" />
        <circle cx="12" cy="18" r="2" />
        <path d="M7 7.2l4 8.6M17 7.2l-4 8.6M7 6h10" />
      </>
    ),
    print: (
      <>
        <path d="M7 8V4h10v4" />
        <rect x="5" y="14" width="14" height="6" rx="1" />
        <path d="M5 10h14a2 2 0 0 1 2 2v4h-2M5 16H3v-4a2 2 0 0 1 2-2Z" />
      </>
    ),
    timeline: (
      <>
        <path d="M4 18V8" />
        <path d="M8 18V12" />
        <path d="M12 18V5" />
        <path d="M16 18v-7" />
        <path d="M20 18V9" />
      </>
    ),
    share: (
      <>
        <circle cx="18" cy="5" r="2" />
        <circle cx="6" cy="12" r="2" />
        <circle cx="18" cy="19" r="2" />
        <path d="m8 11 8-5M8 13l8 5" />
      </>
    ),
    notes: (
      <>
        <path d="M5 4h14v16H5z" />
        <path d="M8 8h8M8 12h8M8 16h5" />
      </>
    ),
    help: (
      <>
        <circle cx="12" cy="12" r="9" />
        <path d="M9.8 9a2.4 2.4 0 1 1 3.7 2c-.9.6-1.5 1-1.5 2" />
        <path d="M12 17h.01" />
      </>
    ),
    settings: (
      <>
        <circle cx="12" cy="12" r="3" />
        <path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1-2.8 2.8-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.6V21h-4v-.1a1.7 1.7 0 0 0-1-1.6 1.7 1.7 0 0 0-1.9.3l-.1.1L4.2 17l.1-.1a1.7 1.7 0 0 0 .3-1.9A1.7 1.7 0 0 0 3 14H3v-4h.1a1.7 1.7 0 0 0 1.6-1 1.7 1.7 0 0 0-.3-1.9L4.2 7 7 4.2l.1.1a1.7 1.7 0 0 0 1.9.3A1.7 1.7 0 0 0 10 3h4a1.7 1.7 0 0 0 1 1.6 1.7 1.7 0 0 0 1.9-.3l.1-.1L19.8 7l-.1.1a1.7 1.7 0 0 0-.3 1.9 1.7 1.7 0 0 0 1.6 1h.1v4H21a1.7 1.7 0 0 0-1.6 1Z" />
      </>
    ),
    services: (
      <>
        <path d="M5 6h14" />
        <path d="M5 12h14" />
        <path d="M5 18h14" />
        <circle cx="8" cy="6" r="1.5" />
        <circle cx="16" cy="12" r="1.5" />
        <circle cx="11" cy="18" r="1.5" />
      </>
    ),
    edit: (
      <>
        <path d="M4 20h4l11-11-4-4L4 16v4Z" />
        <path d="m13.5 6.5 4 4" />
      </>
    ),
    trash: (
      <>
        <path d="M4 7h16" />
        <path d="M9 7V4h6v3" />
        <path d="m7 7 1 13h8l1-13" />
        <path d="M10 11v5M14 11v5" />
      </>
    ),
    check: (
      <>
        <path d="m5 12 4 4L19 6" />
      </>
    ),
    close: (
      <>
        <path d="m6 6 12 12M18 6 6 18" />
      </>
    ),
    history: (
      <>
        <circle cx="12" cy="12" r="8" />
        <path d="M12 8v5l3 2" />
        <path d="M5.5 5.5 3 8V4h4" />
      </>
    ),
    refresh: (
      <>
        <path d="M20 7v5h-5" />
        <path d="M4 17v-5h5" />
        <path d="M6.1 8a7 7 0 0 1 11.8-1L20 12" />
        <path d="M17.9 16a7 7 0 0 1-11.8 1L4 12" />
      </>
    ),
    user: (
      <>
        <circle cx="12" cy="8" r="4" />
        <path d="M4.5 20c.8-4 3.3-6 7.5-6s6.7 2 7.5 6" />
      </>
    ),
  };

  return (
    <svg className="nav-icon" viewBox="0 0 24 24" aria-hidden="true">
      {paths[name]}
    </svg>
  );
};

function App() {
  const [report, setReport] = useState<ElevadrReport | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [recoveredJobs, setRecoveredJobs] = useState<Array<{
    jobId: string; phase: string; status: string; message?: string;
    detail?: string; progress?: number | null;
  }>>([]);

  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [shareStatus, setShareStatus] = useState("");
  const [helpOpen, setHelpOpen] = useState(false);
  const [welcomeInstructionsOpen, setWelcomeInstructionsOpen] = useState(false);
  const [platformView, setPlatformView] = useState<
    "open-file" | "analyses" | "storage" | "administration" | "account"
  >("open-file");
  const [adminTab, setAdminTab] = useState<"users" | "audit">("users");
  const [tourOpen, setTourOpen] = useState(
    () => localStorage.getItem("elevadr-tour-seen") !== "1",
  );
  const [activeSection, setActiveSection] = useState("overview");
  const [filters, setFilters] = useState<InvestigationFilter[]>(() => {
    const params = new URLSearchParams(window.location.search);
    const labels: Record<InvestigationFilterKey, string> = {
      service: "Service",
      port: "Port",
      deviceClass: "Class",
      risk: "Risk",
      ip: "Device",
      connection: "Connection",
      subnet: "Subnet",
      zeekState: "Zeek State",
      manufacturer: "Manufacturer",
    };
    return (
      [
        "service",
        "port",
        "deviceClass",
        "risk",
        "ip",
        "connection",
        "subnet",
        "zeekState",
        "manufacturer",
      ] as InvestigationFilterKey[]
    ).flatMap((key) => {
      const value = params.get(key);
      return value ? [{ key, value, label: labels[key] }] : [];
    });
  });
  const [selectedEntity, setSelectedEntity] = useState<SelectedEntity | null>(
    null,
  );
  const [supplementalSubnets, setSupplementalSubnets] = useState<
    SupplementalSubnet[]
  >([]);
  const [allPanelsExpanded, setAllPanelsExpanded] = useState(true);
  const [welcomeUsername, setWelcomeUsername] = useState("");
  const [welcomePassword, setWelcomePassword] = useState("");
  const [authState, setAuthState] = useState<AuthState | null>(null);
  const [authLoading, setAuthLoading] = useState(true);
  const [authSubmitting, setAuthSubmitting] = useState(false);
  const [welcomeAuthMessage, setWelcomeAuthMessage] = useState("");
  const [savedReports, setSavedReports] = useState<SavedReportSummary[]>([]);
  const [savedReportsLoading, setSavedReportsLoading] = useState(false);
  const [savedReportsMessage, setSavedReportsMessage] = useState("");
  const [savedReportQuery, setSavedReportQuery] = useState("");
  const [savedReportSort, setSavedReportSort] = useState("newest");
  const [renamingReportId, setRenamingReportId] = useState("");
  const [renameDraft, setRenameDraft] = useState("");
  const [deleteConfirmReportId, setDeleteConfirmReportId] = useState("");
  const [retainedCaptures, setRetainedCaptures] = useState<
    RetainedCaptureSummary[]
  >([]);
  const [capturesLoading, setCapturesLoading] = useState(false);
  const [capturesMessage, setCapturesMessage] = useState("");
  const [deleteConfirmCaptureId, setDeleteConfirmCaptureId] = useState("");
  const [captureAnalyzingId, setCaptureAnalyzingId] = useState("");
  const [historyCaptureId, setHistoryCaptureId] = useState("");
  const [captureMenuId, setCaptureMenuId] = useState("");
  const [compareReportIds, setCompareReportIds] = useState<string[]>([]);
  const [reportComparison, setReportComparison] =
    useState<ReportComparison | null>(null);
  const [comparisonLoading, setComparisonLoading] = useState(false);
  const [platformUsers, setPlatformUsers] = useState<PlatformUser[]>([]);
  const [accountMessage, setAccountMessage] = useState("");
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [auditMessage, setAuditMessage] = useState("");
  const [storageSummary, setStorageSummary] = useState<StorageSummary | null>(
    null,
  );
  const [storageMessage, setStorageMessage] = useState("");
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newUsername, setNewUsername] = useState("");
  const [newUserPassword, setNewUserPassword] = useState("");
  const [newUserRole, setNewUserRole] = useState("analyst");
  const [notesOpen, setNotesOpen] = useState(false);
  const [detectionConfigOpen, setDetectionConfigOpen] = useState(false);
  const [detectionModulesOpen, setDetectionModulesOpen] = useState(false);
  const [detectionProfileRevision, setDetectionProfileRevision] = useState(0);
  const [reportConfigurationStale, setReportConfigurationStale] =
    useState(false);
  const [reportRefreshPromptOpen, setReportRefreshPromptOpen] = useState(false);
  const [reportConfigurationChange, setReportConfigurationChange] =
    useState("");
  const [reportRefreshRequestRevision, setReportRefreshRequestRevision] =
    useState(0);
  const [reportRefreshInProgress, setReportRefreshInProgress] = useState(false);
  const [reportRefreshError, setReportRefreshError] = useState("");
  const [reportCustomizationOpen, setReportCustomizationOpen] = useState(false);
  const [visibleReportSections, setVisibleReportSections] = useState<
    Set<ReportSectionId>
  >(() => initialReportSections());
  const [sectionNotes, setSectionNotes] = useState<Record<string, string>>({});
  const [entityNotes, setEntityNotes] = useState<Record<string, string>>({});
  const [entityOverrides, setEntityOverrides] = useState<
    Record<string, Record<string, string>>
  >({});
  const [graphViewState, setGraphViewState] =
    useState<NetworkTopologyState | null>(null);
  const [noteDraft, setNoteDraft] = useState("");
  const isReadOnly = Boolean(
    authState?.authEnabled &&
    authState.user.authenticated &&
    authState.user.role === "read_only",
  );
  const canWriteAnalysis = !isReadOnly;

  const handleReportLoaded = (nextReport: ElevadrReport) => {
    setGraphViewState(null);
    setReport(nextReport);
    setVisibleReportSections(initialReportSections());
    setReportConfigurationStale(false);
    setReportRefreshPromptOpen(false);
    setReportConfigurationChange("");
    setReportRefreshInProgress(false);
    setReportRefreshError("");
    setReportRefreshInProgress(false);
    setReportRefreshError("");
  };

  const markReportConfigurationChanged = (
    source: "Detection Context" | "Modules",
  ) => {
    setDetectionProfileRevision((value) => value + 1);
    if (!report) return;
    setReportConfigurationChange(source);
    setReportConfigurationStale(true);
    setReportRefreshPromptOpen(true);
  };

  const requestUpdatedReport = () => {
    setReportRefreshPromptOpen(false);
    setReportRefreshError("");
    setReportRefreshInProgress(true);
    setReportRefreshRequestRevision((value) => value + 1);
  };

  const handleReportReanalysisStatus = (
    status: "started" | "completed" | "failed" | "unavailable",
    message?: string,
  ) => {
    if (status === "started") {
      setReportRefreshInProgress(true);
      setReportRefreshError("");
      return;
    }
    if (status === "completed") {
      setReportRefreshInProgress(false);
      return;
    }
    setReportRefreshInProgress(false);
    setReportRefreshError(
      message ||
        "Unable to regenerate the report with the updated configuration.",
    );
    setReportRefreshPromptOpen(true);
  };

  const refreshSavedReports = async () => {
    if (!authState?.authEnabled || !authState.user.authenticated) return;
    setSavedReportsLoading(true);
    setSavedReportsMessage("");
    try {
      setSavedReports(await listSavedReports());
    } catch (error) {
      setSavedReportsMessage(
        error instanceof Error
          ? error.message
          : "Unable to load saved reports.",
      );
    } finally {
      setSavedReportsLoading(false);
    }
  };

  const refreshRetainedCaptures = async () => {
    if (!authState?.authEnabled || !authState.user.authenticated) return;
    setCapturesLoading(true);
    setCapturesMessage("");
    try {
      setRetainedCaptures(await listRetainedCaptures());
    } catch (error) {
      setCapturesMessage(
        error instanceof Error
          ? error.message
          : "Unable to load retained captures.",
      );
    } finally {
      setCapturesLoading(false);
    }
  };

  const removeRetainedCapture = async (captureId: string) => {
    if (deleteConfirmCaptureId !== captureId) {
      setDeleteConfirmCaptureId(captureId);
      return;
    }
    try {
      await deleteRetainedCapture(captureId);
      setDeleteConfirmCaptureId("");
      await refreshRetainedCaptures();
    } catch (error) {
      setCapturesMessage(
        error instanceof Error
          ? error.message
          : "Unable to delete retained capture.",
      );
    }
  };

  const reanalyzeRetainedCapture = async (captureId: string) => {
    setCaptureAnalyzingId(captureId);
    setCapturesMessage("");
    try {
      const payload = await analyzeRetainedCapture(
        captureId,
        normalizeProfile(loadActiveProfile()),
      );
      handleReportLoaded(normalizeElevadrReport(payload).report);
    } catch (error) {
      setCapturesMessage(
        error instanceof Error
          ? error.message
          : "Unable to analyze retained capture.",
      );
    } finally {
      setCaptureAnalyzingId("");
    }
  };

  const refreshAuditEvents = async () => {
    if (!authState?.user.authenticated) return;
    setAuditMessage("");
    try {
      setAuditEvents(
        await listAuditEvents(
          authState.user.role === "admin" ? "all" : "mine",
          50,
        ),
      );
    } catch (error) {
      setAuditMessage(
        error instanceof Error ? error.message : "Unable to load activity.",
      );
    }
  };

  const refreshStorageSummary = async () => {
    if (!authState?.user.authenticated) return;
    setStorageMessage("");
    try {
      setStorageSummary(
        await getStorageSummary(
          authState.user.role === "admin" ? "all" : "mine",
        ),
      );
    } catch (error) {
      setStorageMessage(
        error instanceof Error
          ? error.message
          : "Unable to load storage usage.",
      );
    }
  };

  const runStorageCleanup = async (removeOrphans: boolean) => {
    setStorageMessage("");
    try {
      const result = await cleanupStorage(removeOrphans);
      setStorageMessage(
        `Cleanup complete: ${result.expired.expiredCaptures} expired capture(s), ${result.orphans.orphanFiles} orphan file(s) removed.`,
      );
      await refreshStorageSummary();
      await refreshRetainedCaptures();
    } catch (error) {
      setStorageMessage(
        error instanceof Error ? error.message : "Unable to clean storage.",
      );
    }
  };

  const refreshPlatformUsers = async () => {
    if (authState?.user.role !== "admin") return;
    try {
      setPlatformUsers(await listUsers());
    } catch (error) {
      setAccountMessage(
        error instanceof Error ? error.message : "Unable to load users.",
      );
    }
  };

  const submitPasswordChange = async (
    event: React.FormEvent<HTMLFormElement>,
  ) => {
    event.preventDefault();
    setAccountMessage("");
    try {
      await changeOwnPassword(currentPassword, newPassword);
      setCurrentPassword("");
      setNewPassword("");
      setAccountMessage(
        "Password changed. Sign in again with your new password.",
      );
      setTimeout(() => void handleSignOut(), 700);
    } catch (error) {
      setAccountMessage(
        error instanceof Error ? error.message : "Unable to change password.",
      );
    }
  };

  const submitNewUser = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setAccountMessage("");
    try {
      await createUser({
        username: newUsername,
        password: newUserPassword,
        role: newUserRole,
      });
      setNewUsername("");
      setNewUserPassword("");
      await refreshPlatformUsers();
      setAccountMessage("User created.");
    } catch (error) {
      setAccountMessage(
        error instanceof Error ? error.message : "Unable to create user.",
      );
    }
  };

  const changeUser = async (
    user: PlatformUser,
    changes: { role?: string; disabled?: boolean },
  ) => {
    setAccountMessage("");
    try {
      const updated = await updateUser(user.id, changes);
      setPlatformUsers((rows) =>
        rows.map((row) => (row.id === updated.id ? updated : row)),
      );
    } catch (error) {
      setAccountMessage(
        error instanceof Error ? error.message : "Unable to update user.",
      );
    }
  };

  const analysisCaptureGroups = useMemo(() => {
    const query = savedReportQuery.trim().toLowerCase();
    const retainedById = new Map(
      retainedCaptures.map((capture) => [capture.captureId, capture]),
    );
    const retainedByFilename = new Map(
      retainedCaptures.map((capture) => [capture.filename, capture]),
    );
    const groups = new Map<
      string,
      {
        key: string;
        filename: string;
        capture: RetainedCaptureSummary | null;
        analyses: SavedReportSummary[];
      }
    >();

    for (const capture of retainedCaptures) {
      groups.set(capture.captureId, {
        key: capture.captureId,
        filename: capture.filename,
        capture,
        analyses: [],
      });
    }

    for (const analysis of savedReports) {
      const retained =
        retainedById.get(analysis.captureId) ||
        retainedByFilename.get(analysis.sourceFilename) ||
        null;
      const key =
        retained?.captureId ||
        (analysis.sourceFilename
          ? `source:${analysis.sourceFilename}`
          : analysis.captureId || `report:${analysis.reportId}`);
      const existing = groups.get(key);
      if (existing) {
        existing.analyses.push(analysis);
      } else {
        groups.set(key, {
          key,
          filename: analysis.sourceFilename || analysis.title || "Unknown PCAP",
          capture: null,
          analyses: [analysis],
        });
      }
    }

    const rows = [...groups.values()]
      .map((group) => ({
        ...group,
        analyses: [...group.analyses].sort(
          (a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt),
        ),
      }))
      .filter(
        (group) =>
          !query ||
          group.filename.toLowerCase().includes(query) ||
          group.analyses.some(
            (analysis) =>
              analysis.title.toLowerCase().includes(query) ||
              analysis.sourceFilename.toLowerCase().includes(query),
          ),
      );

    return rows.sort((a, b) => {
      const aLatest = a.analyses[0];
      const bLatest = b.analyses[0];
      if (savedReportSort === "title")
        return a.filename.localeCompare(b.filename);
      if (savedReportSort === "oldest")
        return (
          Date.parse(aLatest?.createdAt || a.capture?.createdAt || "") -
          Date.parse(bLatest?.createdAt || b.capture?.createdAt || "")
        );
      if (savedReportSort === "findings-desc")
        return (bLatest?.findingCount || 0) - (aLatest?.findingCount || 0);
      if (savedReportSort === "findings-asc")
        return (aLatest?.findingCount || 0) - (bLatest?.findingCount || 0);
      return (
        Date.parse(bLatest?.createdAt || b.capture?.createdAt || "") -
        Date.parse(aLatest?.createdAt || a.capture?.createdAt || "")
      );
    });
  }, [retainedCaptures, savedReports, savedReportQuery, savedReportSort]);

  const openSavedReport = async (reportId: string) => {
    setSavedReportsMessage("");
    try {
      const payload = await loadSavedReport(reportId);
      handleReportLoaded(normalizeElevadrReport(payload).report);
    } catch (error) {
      setSavedReportsMessage(
        error instanceof Error ? error.message : "Unable to open saved report.",
      );
    }
  };

  const saveReportRename = async (reportId: string) => {
    try {
      const updated = await renameSavedReport(reportId, renameDraft);
      setSavedReports((rows) =>
        rows.map((item) => (item.reportId === reportId ? updated : item)),
      );
      setRenamingReportId("");
      setRenameDraft("");
    } catch (error) {
      setSavedReportsMessage(
        error instanceof Error
          ? error.message
          : "Unable to rename saved report.",
      );
    }
  };

  const removeSavedReport = async (reportId: string) => {
    if (deleteConfirmReportId !== reportId) {
      setDeleteConfirmReportId(reportId);
      return;
    }
    try {
      await deleteSavedReport(reportId);
      setDeleteConfirmReportId("");
      await refreshSavedReports();
    } catch (error) {
      setSavedReportsMessage(
        error instanceof Error
          ? error.message
          : "Unable to delete saved report.",
      );
    }
  };

  const toggleCompareReport = (reportId: string) => {
    setReportComparison(null);
    setCompareReportIds((current) =>
      current.includes(reportId)
        ? current.filter((id) => id !== reportId)
        : current.length < 2
          ? [...current, reportId]
          : [current[1], reportId],
    );
  };

  const compareSelectedReports = async () => {
    if (compareReportIds.length !== 2) return;
    setComparisonLoading(true);
    setCapturesMessage("");
    try {
      const [left, right] = await Promise.all(
        compareReportIds.map((id) => loadSavedReport(id)),
      );
      setReportComparison(compareReports(left, right));
    } catch (error) {
      setCapturesMessage(
        error instanceof Error
          ? error.message
          : "Unable to compare saved reports.",
      );
    } finally {
      setComparisonLoading(false);
    }
  };

  // Jobs belong to the server, not the login session. Re-query after login
  // and while authenticated so a completed job is still visible after renewal.
  useEffect(() => {
    if (!authState?.user.authenticated) { setRecoveredJobs([]); return; }
    let active = true;
    const check = async () => {
      try {
        const response = await authenticatedFetch("/api/v1/processing-jobs", { cache: "no-store" });
        if (!response.ok) return;
        const payload = await response.json() as { jobs?: typeof recoveredJobs };
        if (active) setRecoveredJobs(Array.isArray(payload.jobs) ? payload.jobs : []);
      } catch { /* retain last known state during transient network failures */ }
    };
    void check();
    const interval = window.setInterval(() => { void check(); }, 5000);
    return () => { active = false; window.clearInterval(interval); };
  }, [authState?.user.authenticated]);

  // Background tabs throttle timers; also check on focus and visibility changes.
  // Renewal is attempted before expiry, but only the server can authorize it.
  useEffect(() => {
    if (!authState?.authEnabled || !authState.user.authenticated) return;
    const check = () => {
      if (tokenExpiresWithin(20 * 60)) void renewProcessingSession();
    };
    check();
    const interval = window.setInterval(check, 60 * 1000);
    window.addEventListener("focus", check);
    document.addEventListener("visibilitychange", check);
    return () => {
      window.clearInterval(interval);
      window.removeEventListener("focus", check);
      document.removeEventListener("visibilitychange", check);
    };
  }, [authState?.authEnabled, authState?.user.authenticated]);

  const handleSignIn = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!welcomeUsername.trim() || !welcomePassword) {
      setWelcomeAuthMessage("Enter a username and password to continue.");
      return;
    }
    setAuthSubmitting(true);
    setWelcomeAuthMessage("");
    try {
      const state = await login(welcomeUsername.trim(), welcomePassword);
      setAuthState(state);
      setWelcomePassword("");
    } catch (error) {
      setWelcomeAuthMessage(
        error instanceof Error ? error.message : "Unable to sign in.",
      );
    } finally {
      setAuthSubmitting(false);
    }
  };

  const handleSignOut = async () => {
    await logout();
    setAuthState((current) =>
      current
        ? {
            ...current,
            user: {
              id: "",
              username: "",
              authenticated: false,
              role: "anonymous",
            },
          }
        : current,
    );
    setReport(null);
    setWelcomePassword("");
    setWelcomeAuthMessage("");
  };

  useEffect(() => {
    let active = true;
    fetchAuthState()
      .then((state) => {
        if (active) setAuthState(state);
      })
      .catch((error) => {
        if (active)
          setWelcomeAuthMessage(
            error instanceof Error
              ? error.message
              : "Unable to determine authentication status.",
          );
      })
      .finally(() => {
        if (active) setAuthLoading(false);
      });
    const onExpired = () => {
      setAuthState((current) =>
        current
          ? {
              ...current,
              user: {
                id: "",
                username: "",
                authenticated: false,
                role: "anonymous",
              },
            }
          : current,
      );
      setReport(null);
      setWelcomeAuthMessage("Your session expired. Sign in again to continue.");
    };
    window.addEventListener(AUTH_EXPIRED_EVENT, onExpired);
    return () => {
      active = false;
      window.removeEventListener(AUTH_EXPIRED_EVENT, onExpired);
    };
  }, []);

  useEffect(() => {
    if (authState?.authEnabled && authState.user.authenticated && !report) {
      void refreshSavedReports();
      void refreshRetainedCaptures();
      void refreshStorageSummary();
      if (authState.user.role === "admin") void refreshPlatformUsers();
    }
    if (!authState?.user.authenticated) {
      setSavedReports([]);
      setRetainedCaptures([]);
      setPlatformUsers([]);
    }
  }, [authState?.authEnabled, authState?.user.authenticated, report]);

  const authenticationRequired =
    authState?.authEnabled === true && authState.user.authenticated !== true;

  const returnToWelcome = () => {
    if (!report) return;
    setReport(null);
    // Returning to the welcome screen must not cancel an active PCAP job.
    setMobileNavOpen(false);
    setHelpOpen(false);
    setNotesOpen(false);
    setDetectionConfigOpen(false);
    setSelectedEntity(null);
    setFilters([]);
    setSupplementalSubnets([]);
    setActiveSection("overview");
    setShareStatus("");
    setSectionNotes({});
    setEntityNotes({});
    setNoteDraft("");
    setReportConfigurationStale(false);
    setReportRefreshPromptOpen(false);
    setReportConfigurationChange("");
    const cleanUrl = `${window.location.pathname}${window.location.hash || ""}`;
    window.history.replaceState({}, "", cleanUrl);
    window.scrollTo({ top: 0, behavior: "auto" });
  };

  const shareCurrentView = async () => {
    const url = window.location.href;
    try {
      if (navigator.share)
        await navigator.share({
          title: report ? `eleVADR report ${report.report_id}` : "eleVADR",
          url,
        });
      else await navigator.clipboard.writeText(url);
      setShareStatus("Link ready");
      window.setTimeout(() => setShareStatus(""), 1800);
    } catch {
      setShareStatus("");
    }
  };
  const downloadJson = (payload: unknown, filename: string) => {
    const blob = new Blob([JSON.stringify(payload, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  const entityNoteKey = (entity: SelectedEntity): string =>
    `${entity.type}|${entity.id}`;
  const entityNotesStorageKey = report
    ? `elevadr-entity-notes:${report.report_id || "report"}`
    : "";
  const entityOverridesStorageKey = report
    ? `elevadr-entity-overrides:${report.report_id || "report"}`
    : "";
  const entityNoteSection = (key: string): ReportSectionId | null => {
    const type = key.split("|", 1)[0];
    if (type === "finding") return "findings";
    if (type === "device") return "devices";
    if (type === "service") return "services";
    if (type === "connection") return "connections";
    return null;
  };

  const buildFilteredReport = () => {
    if (!report) return null;
    const included = REPORT_SECTION_OPTIONS.filter((section) =>
      visibleReportSections.has(section.id),
    ).map((section) => section.id);
    const excluded = REPORT_SECTION_OPTIONS.filter(
      (section) => !visibleReportSections.has(section.id),
    ).map((section) => section.id);
    const sections: Record<string, unknown> = {};
    if (visibleReportSections.has("overview"))
      sections.overview = {
        executive_summary: report.executive_summary,
        analysis_provenance: report.arch_insights?.analysis_provenance ?? null,
        report_compatibility:
          report.arch_insights?.report_compatibility ?? null,
      };
    if (visibleReportSections.has("findings"))
      sections.findings = {
        detector_findings: report.arch_insights?.detector_findings ?? [],
        derived_findings: deriveFindings(report),
      };
    if (visibleReportSections.has("devices"))
      sections.devices = {
        device_panel: report.modules.device_panel,
        ot_devices: report.modules.ot_devices,
        it_devices: report.modules.it_devices,
        edge_devices: report.modules.edge_devices,
      };
    if (visibleReportSections.has("services"))
      sections.services = {
        service_panel: report.modules.service_panel,
        service_risk_breakdown_panel:
          report.modules.service_risk_breakdown_panel,
        service_count_panel: report.modules.service_count_panel,
        ot_services: report.modules.ot_services,
      };
    if (visibleReportSections.has("connections"))
      sections.connections = {
        connection_success_panel: report.modules.connection_success_panel,
        suspicious_outbound_connections_panel:
          report.modules.suspicious_outbound_connections_panel,
        ot_cross_segment_lines_panel:
          report.modules.ot_cross_segment_lines_panel,
      };
    const visibleNotes = Object.fromEntries(
      Object.entries(sectionNotes).filter(([key]) =>
        visibleReportSections.has(key as ReportSectionId),
      ),
    );
    const visibleEntityNotes = Object.fromEntries(
      Object.entries(entityNotes).filter(([key, value]) => {
        const section = entityNoteSection(key);
        return (
          Boolean(value?.trim()) &&
          Boolean(section && visibleReportSections.has(section))
        );
      }),
    );
    const visibleEntityOverrides = Object.fromEntries(
      Object.entries(entityOverrides).filter(([key, value]) => {
        const section = entityNoteSection(key);
        return (
          Boolean(Object.keys(value || {}).length) &&
          Boolean(section && visibleReportSections.has(section))
        );
      }),
    );
    return {
      report_version: report.report_version,
      report_id: report.report_id,
      export_metadata: {
        filtered: true,
        source_report_id: report.report_id,
        included_sections: included,
        excluded_sections: excluded,
        active_investigation_filters: filters,
        graph_view: visibleReportSections.has("topology")
          ? graphViewState
          : null,
        note: "Derivative export from eleVADR. Sections not selected in the report view are intentionally omitted; the source report was not modified.",
      },
      sections,
      section_notes: visibleNotes,
      entity_notes: visibleEntityNotes,
      entity_overrides: visibleEntityOverrides,
    };
  };

  const handleDownloadJson = () => {
    if (!report) return;
    const filtered = buildFilteredReport();
    if (!filtered) return;
    downloadJson(
      filtered,
      `elevadr-report-${report.report_id || "report"}-filtered.json`,
    );
  };

  const handleDownloadFullJson = () => {
    if (!report) return;
    downloadJson(
      {
        ...report,
        section_notes: sectionNotes,
        entity_notes: entityNotes,
        entity_overrides: entityOverrides,
        graph_view: graphViewState,
      },
      `elevadr-report-${report.report_id || "report"}.json`,
    );
  };

  const exportAssetInventory = () => {
    if (!report) return;
    const findings = deriveFindings(report);
    const classes = [
      { name: "OT", items: report.modules.ot_devices },
      { name: "IT", items: report.modules.it_devices },
      { name: "Network", items: report.modules.edge_devices },
    ];
    const merged = new Map<
      string,
      {
        device: (typeof report.modules.ot_devices)[number];
        classes: Set<string>;
      }
    >();
    classes.forEach(({ name, items }) =>
      items.forEach((device) => {
        const ips = [
          ...(device.ip_addresses || []),
          ...(device.ipv4_ips || []),
          ...(device.ipv6_ips || []),
        ].filter(Boolean);
        const key =
          ips.sort().join("|") ||
          `${device.mac || ""}|${device.manufacturer || "Unknown"}`;
        const prior = merged.get(key);
        if (prior) prior.classes.add(name);
        else merged.set(key, { device, classes: new Set([name]) });
      }),
    );
    const rows = [...merged.values()]
      .filter(({ device, classes: deviceClasses }) =>
        filters.every((filter) => {
          const ips = [
            ...(device.ip_addresses || []),
            ...(device.ipv4_ips || []),
            ...(device.ipv6_ips || []),
          ].filter(Boolean);
          const subnets = [
            ...(device.subnets || []),
            ...(device.ipv4_subnets || []),
            ...(device.ipv6_subnets || []),
          ].filter(Boolean);
          const services = [
            ...(device.incoming_services || []),
            ...(device.sent_services || []),
          ].filter(Boolean);
          if (filter.key === "ip") return ips.includes(filter.value);
          if (filter.key === "service") return services.includes(filter.value);
          if (filter.key === "deviceClass")
            return deviceClasses.has(filter.value);
          if (filter.key === "subnet") return subnets.includes(filter.value);
          if (filter.key === "manufacturer")
            return (device.manufacturer || "Unknown") === filter.value;
          return true;
        }),
      )
      .map(({ device, classes: deviceClasses }) => {
        const ips = [
          ...(device.ip_addresses || []),
          ...(device.ipv4_ips || []),
          ...(device.ipv6_ips || []),
        ].filter(Boolean);
        const subnets = [
          ...(device.subnets || []),
          ...(device.ipv4_subnets || []),
          ...(device.ipv6_subnets || []),
        ].filter(Boolean);
        const findingCount = findings.filter((finding) =>
          ips.some((ip) => finding.ip === ip || finding.destination === ip),
        ).length;
        return [
          device.manufacturer || "Unknown",
          device.mac || "",
          ips.join("; "),
          [...deviceClasses].join("; "),
          subnets.join("; "),
          (device.sent_services || []).join("; "),
          (device.incoming_services || []).join("; "),
          findingCount,
        ];
      });
    const escape = (value: unknown) =>
      `"${String(value ?? "").replace(/"/g, '""')}"`;
    const headers = [
      "Manufacturer",
      "MAC",
      "IP Addresses",
      "Device Classes",
      "Subnets",
      "Services Out",
      "Services In",
      "Associated Findings",
    ];
    const csv = [headers, ...rows]
      .map((row) => row.map(escape).join(","))
      .join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `elevadr-asset-inventory-${report.report_id}.csv`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const hasSupportedReportVersion = report
    ? isSupportedReportVersion(report.report_version)
    : false;
  const analysisProvenance = report?.arch_insights?.analysis_provenance;
  const provenance =
    analysisProvenance && typeof analysisProvenance === "object"
      ? (analysisProvenance as Record<string, unknown>)
      : null;
  const compatibilityInfo = report?.arch_insights?.report_compatibility;
  const reportCompatibility =
    compatibilityInfo && typeof compatibilityInfo === "object"
      ? (compatibilityInfo as Record<string, unknown>)
      : null;
  const compatibilityWarnings = Array.isArray(reportCompatibility?.warnings)
    ? reportCompatibility.warnings.filter(
        (value): value is string => typeof value === "string",
      )
    : [];
  const reportFindingCount = report ? deriveFindings(report).length : 0;
  const reportDeviceCount = report
    ? report.modules.ot_devices.length +
      report.modules.it_devices.length +
      report.modules.edge_devices.length
    : 0;
  const reportServiceCount = report
    ? report.modules.service_panel.num_known_services +
      report.modules.service_panel.num_unknown_services
    : 0;
  const reportConnectionRecordCount =
    report?.modules.connection_success_panel.connections.length ?? 0;

  const closeMobileNav = () => setMobileNavOpen(false);

  const navItems = useMemo(() => {
    const base: {
      id: string;
      label: string;
      icon: IconName;
      count: number | null;
    }[] = [];

    // Keep the left navigation in the same order as the visible report sections.
    // Every scrollable section on the right gets exactly one corresponding button.
    if (report && isSupportedReportVersion(report.report_version)) {
      base.push(
        {
          id: "overview",
          label: "Summary",
          icon: "overview" as IconName,
          count: null,
        },
        {
          id: "findings",
          label: "Findings",
          icon: "findings" as IconName,
          count:
            Object.values(
              report.modules.service_risk_breakdown_panel.risk_category_counts,
            ).reduce<number>((a, b) => a + Number(b), 0) +
            report.modules.suspicious_outbound_connections_panel.length,
        },
      );

      const totalServices =
        report.modules.service_panel.num_known_services +
        report.modules.service_panel.num_unknown_services;
      const uniqueConnectionKeys = new Set<string>();
      report.modules.connection_success_panel.connections.forEach(
        (connection) => {
          const src = connection["src_endpoint.ip"];
          const dst = connection["dst_endpoint.ip"];
          if (!src || !dst) return;
          const pair = [src, dst].sort().join("|");
          const protocol =
            connection["connection_info.protocol_name"] ||
            connection["service.name"] ||
            `port:${connection["dst_endpoint.port"] ?? "unknown"}`;
          uniqueConnectionKeys.add(`${pair}|${protocol}`);
        },
      );

      base.push(
        {
          id: "devices",
          label: "Devices",
          icon: "assets" as IconName,
          count: report.modules.device_panel.hosts,
        },
        {
          id: "services",
          label: "Services",
          icon: "services" as IconName,
          count: totalServices,
        },
        {
          id: "topology",
          label: "Topology",
          icon: "topology" as IconName,
          count: uniqueConnectionKeys.size,
        },
        {
          id: "connections",
          label: "Connections",
          icon: "traffic" as IconName,
          count: uniqueConnectionKeys.size,
        },
      );
    }

    return base.filter((item) =>
      visibleReportSections.has(item.id as ReportSectionId),
    );
  }, [report, visibleReportSections]);

  const activeSectionLabel =
    navItems.find((item) => item.id === activeSection)?.label ||
    (
      {
        overview: "Summary",
        findings: "Findings",
        devices: "Devices",
        services: "Services",
        topology: "Topology",
        connections: "Connections",
      } as Record<string, string>
    )[activeSection] ||
    "Current Section";

  const notesStorageKey = report
    ? `elevadr-section-notes:${report.report_id || "report"}`
    : "";

  useEffect(() => {
    if (!report) {
      setSectionNotes({});
      setNotesOpen(false);
      return;
    }
    const stored: Record<string, string> = (() => {
      try {
        return JSON.parse(
          localStorage.getItem(
            `elevadr-section-notes:${report.report_id || "report"}`,
          ) || "{}",
        );
      } catch {
        return {};
      }
    })();

    // If future reports include notes, seed them into the same section-note model.
    const rawReport = report as ElevadrReport & {
      notes?: Record<string, string>;
      section_notes?: Record<string, string>;
      sectionNotes?: Record<string, string>;
    };
    const reportNotes =
      rawReport.section_notes ||
      rawReport.sectionNotes ||
      rawReport.notes ||
      {};
    const aliases: Record<string, string> = {
      summary: "overview",
      "executive summary": "overview",
      overview: "overview",
      findings: "findings",
      devices: "devices",
      services: "services",
      topology: "topology",
      connections: "connections",
    };
    const seeded: Record<string, string> = {};
    Object.entries(reportNotes).forEach(([key, value]) => {
      if (typeof value !== "string" || !value.trim()) return;
      const normalized = aliases[key.trim().toLowerCase()] || key;
      seeded[normalized] = value;
    });
    setSectionNotes({ ...seeded, ...stored });
  }, [report]);

  useEffect(() => {
    if (!report) {
      setEntityNotes({});
      return;
    }
    const stored: Record<string, string> = (() => {
      try {
        return JSON.parse(
          localStorage.getItem(
            `elevadr-entity-notes:${report.report_id || "report"}`,
          ) || "{}",
        );
      } catch {
        return {};
      }
    })();
    const rawReport = report as ElevadrReport & {
      entity_notes?: Record<string, string>;
      entityNotes?: Record<string, string>;
    };
    const reportNotes = rawReport.entity_notes || rawReport.entityNotes || {};
    const seeded = Object.fromEntries(
      Object.entries(reportNotes).filter(
        ([, value]) => typeof value === "string" && value.trim(),
      ),
    ) as Record<string, string>;
    setEntityNotes({ ...seeded, ...stored });
  }, [report]);

  useEffect(() => {
    if (!report) {
      setEntityOverrides({});
      return;
    }
    const stored: Record<string, Record<string, string>> = (() => {
      try {
        return JSON.parse(
          localStorage.getItem(
            `elevadr-entity-overrides:${report.report_id || "report"}`,
          ) || "{}",
        );
      } catch {
        return {};
      }
    })();
    const rawReport = report as ElevadrReport & {
      entity_overrides?: Record<string, Record<string, string>>;
      entityOverrides?: Record<string, Record<string, string>>;
    };
    const reportOverrides =
      rawReport.entity_overrides || rawReport.entityOverrides || {};
    setEntityOverrides({ ...reportOverrides, ...stored });
  }, [report]);

  const saveEntityOverrides = (
    entity: SelectedEntity,
    value: Record<string, string>,
  ) => {
    if (!report) return;
    const key = entityNoteKey(entity);
    const cleaned = Object.fromEntries(
      Object.entries(value).filter(([, item]) => item.trim()),
    ) as Record<string, string>;
    const next = { ...entityOverrides };
    if (Object.keys(cleaned).length) next[key] = cleaned;
    else delete next[key];
    setEntityOverrides(next);
    try {
      localStorage.setItem(entityOverridesStorageKey, JSON.stringify(next));
    } catch {
      /* local persistence unavailable */
    }
  };

  const resetEntityOverrides = (entity: SelectedEntity) => {
    if (!report) return;
    const next = { ...entityOverrides };
    delete next[entityNoteKey(entity)];
    setEntityOverrides(next);
    try {
      localStorage.setItem(entityOverridesStorageKey, JSON.stringify(next));
    } catch {
      /* local persistence unavailable */
    }
  };

  const saveEntityNote = (entity: SelectedEntity, value: string) => {
    if (!report) return;
    const key = entityNoteKey(entity);
    const clean = value.trim();
    const next = { ...entityNotes };
    if (clean) next[key] = value;
    else delete next[key];
    setEntityNotes(next);
    try {
      localStorage.setItem(entityNotesStorageKey, JSON.stringify(next));
    } catch {
      /* local persistence unavailable */
    }
  };

  const deleteEntityNote = (entity: SelectedEntity) => {
    if (!report) return;
    const next = { ...entityNotes };
    delete next[entityNoteKey(entity)];
    setEntityNotes(next);
    try {
      localStorage.setItem(entityNotesStorageKey, JSON.stringify(next));
    } catch {
      /* local persistence unavailable */
    }
  };

  const openSectionNotes = () => {
    if (!report) return;
    setNoteDraft(sectionNotes[activeSection] || "");
    setNotesOpen(true);
  };

  const saveSectionNotes = () => {
    if (!report) return;
    const next = { ...sectionNotes };
    const clean = noteDraft.trim();
    if (clean) next[activeSection] = noteDraft;
    else delete next[activeSection];
    setSectionNotes(next);
    try {
      localStorage.setItem(notesStorageKey, JSON.stringify(next));
    } catch {
      /* local persistence unavailable */
    }
    setNotesOpen(false);
  };

  const deleteSectionNotes = () => {
    if (!report) return;
    const next = { ...sectionNotes };
    delete next[activeSection];
    setSectionNotes(next);
    setNoteDraft("");
    try {
      localStorage.setItem(notesStorageKey, JSON.stringify(next));
    } catch {
      /* local persistence unavailable */
    }
    setNotesOpen(false);
  };

  const currentSectionHasNotes = Boolean(sectionNotes[activeSection]?.trim());
  const reportNoteCount = Object.values(sectionNotes).filter((value) =>
    value?.trim(),
  ).length;

  useEffect(() => {
    if (!notesOpen) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") setNotesOpen(false);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [notesOpen]);

  const getStickyHeaderOffset = () => {
    const titlebar = document.querySelector<HTMLElement>(".titlebar");
    const toolbar = document.querySelector<HTMLElement>(".report-toolbar");
    const titlebarBottom = titlebar?.getBoundingClientRect().bottom ?? 0;
    const toolbarBottom =
      toolbar?.getBoundingClientRect().bottom ?? titlebarBottom;

    // The report search/actions toolbar is sticky below the fixed titlebar.
    // Use its rendered bottom edge so section headings are never hidden behind
    // the toolbar, including when it wraps at tablet/mobile breakpoints.
    return Math.max(titlebarBottom, toolbarBottom) + 16;
  };

  const navScrollLockRef = useRef(0);
  const navScrollTimersRef = useRef<number[]>([]);

  // Scroll against the document, not a stale section position. Explicitly
  // disable CSS smooth scrolling for the duration of the navigation so a
  // second click is never necessary, even with long lazy-rendered tables.
  const scrollToSection = (id: string, behavior: ScrollBehavior = "auto") => {
    const target = document.getElementById(id);
    if (!target) return;
    const root = document.documentElement;
    const previousBehavior = root.style.scrollBehavior;
    root.style.scrollBehavior = "auto";
    const targetTop = target.getBoundingClientRect().top + window.scrollY;
    window.scrollTo({
      top: Math.max(0, targetTop - getStickyHeaderOffset()),
      behavior: behavior === "smooth" ? "smooth" : "instant",
    });
    root.style.scrollBehavior = previousBehavior;
  };

  useEffect(() => {
    const elements = navItems
      .map((item) => document.getElementById(item.id))
      .filter((element): element is HTMLElement => Boolean(element));
    if (!elements.length) return;

    const observer = new IntersectionObserver(
      (entries) => {
        if (Date.now() < navScrollLockRef.current) return;
        const visible = entries
          .filter((entry) => entry.isIntersecting)
          .sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
        if (visible?.target.id) setActiveSection(visible.target.id);
      },
      { rootMargin: "-18% 0px -68% 0px", threshold: [0, 0.1, 0.25] },
    );
    elements.forEach((element) => observer.observe(element));
    return () => observer.disconnect();
  }, [navItems, report]);

  useEffect(() => {
    return () => navScrollTimersRef.current.forEach(window.clearTimeout);
  }, []);

  const goToSection = (id: string) => {
    // Cancel corrections from an earlier click before navigating elsewhere.
    navScrollTimersRef.current.forEach(window.clearTimeout);
    navScrollTimersRef.current = [];
    navScrollLockRef.current = Date.now() + 1900;
    setActiveSection(id);
    closeMobileNav();
    scrollToSection(id);
    // Recalculate after React commits and after lazy tables/charts settle.
    // These are absolute target measurements, not cumulative offsets.
    window.requestAnimationFrame(() => scrollToSection(id));
    for (const delay of [100, 300, 700]) {
      navScrollTimersRef.current.push(
        window.setTimeout(() => scrollToSection(id), delay),
      );
    }
  };

  const applyFilter = (filter: InvestigationFilter) => {
    setFilters((current) => {
      const existing = current.find((item) => item.key === filter.key);
      if (existing?.value === filter.value) {
        return current.filter((item) => item.key !== filter.key);
      }
      return [...current.filter((item) => item.key !== filter.key), filter];
    });
  };

  const removeFilter = (key: InvestigationFilterKey) =>
    setFilters((current) => current.filter((item) => item.key !== key));

  const syncPanelExpansionState = () => {
    window.setTimeout(() => {
      const panels = Array.from(document.querySelectorAll(".panel"));
      setAllPanelsExpanded(
        panels.length === 0 ||
          panels.every((panel) => !panel.classList.contains("panel-collapsed")),
      );
    }, 0);
  };

  useEffect(() => {
    window.addEventListener(
      "elevadr:panel-state-changed",
      syncPanelExpansionState,
    );
    return () =>
      window.removeEventListener(
        "elevadr:panel-state-changed",
        syncPanelExpansionState,
      );
  }, []);

  useEffect(() => {
    if (report) syncPanelExpansionState();
  }, [report]);

  const toggleAllPanels = () => {
    const expanded = !allPanelsExpanded;
    window.dispatchEvent(
      new CustomEvent("elevadr:set-all-panels-expanded", {
        detail: { expanded },
      }),
    );
    setAllPanelsExpanded(expanded);
  };

  useEffect(() => {
    const url = new URL(window.location.href);
    (
      [
        "service",
        "port",
        "deviceClass",
        "risk",
        "ip",
        "connection",
        "subnet",
        "zeekState",
        "manufacturer",
      ] as InvestigationFilterKey[]
    ).forEach((key) => url.searchParams.delete(key));
    filters.forEach((filter) => url.searchParams.set(filter.key, filter.value));
    if (report && activeSection) url.searchParams.set("section", activeSection);
    else url.searchParams.delete("section");
    if (report) {
      const ordered = ALL_REPORT_SECTION_IDS.filter((id) =>
        visibleReportSections.has(id),
      );
      if (ordered.length === ALL_REPORT_SECTION_IDS.length)
        url.searchParams.delete("reportSections");
      else url.searchParams.set("reportSections", ordered.join(","));
    } else {
      url.searchParams.delete("reportSections");
    }
    window.history.replaceState({}, "", url);
  }, [filters, activeSection, report, visibleReportSections]);

  useEffect(() => {
    const section = new URLSearchParams(window.location.search).get("section");
    if (!section) return;
    // Wait for the report toolbar and section content to finish laying out, then
    // restore the deep-linked section with the same sticky-header clearance used
    // by left-side navigation.
    window.setTimeout(() => {
      if (Date.now() >= navScrollLockRef.current) scrollToSection(section, "auto");
    }, 120);
  }, [report]);

  return (
    <div
      className={`app-shell ${sidebarCollapsed ? "sidebar-is-collapsed" : ""}`}
    >
      <a className="skip-link" href="#main-content">
        Skip to main content
      </a>
      {authState?.user.authenticated && recoveredJobs.some((job) => job.status === "running" || job.status === "queued" || job.status === "completed") && (
        <aside role="status" aria-live="polite" style={{ padding: "8px 16px", background: "#eaf4fa", color: "#07334d", borderBottom: "1px solid #a9c6d6" }}>
          <strong>Recovered server processing activity: </strong>
          {recoveredJobs.filter((job) => ["running", "queued", "completed"].includes(job.status)).map((job) => (
            <span key={job.jobId} style={{ marginRight: 18 }}>
              {job.phase === "evidence" ? "Zeek evidence" : "Detection modules"}: {job.status} — {job.message || job.detail}
              {typeof job.progress === "number" ? ` (${job.progress}%)` : ""}.
            </span>
          ))}
        </aside>
      )}
      <header className="titlebar">
        <div className="titlebar-brand">
          <button
            type="button"
            className="mobile-menu-button"
            aria-label="Toggle navigation"
            aria-expanded={mobileNavOpen}
            onClick={() => setMobileNavOpen((open) => !open)}
          >
            <Icon name="menu" />
          </button>
          {report ? (
            <button
              type="button"
              className="cisa-branding brand-home-control"
              onClick={returnToWelcome}
              aria-label="Return to eleVADR welcome screen"
              title="Return to welcome screen"
            >
              <img
                className="cisa-logo"
                src="https://upload.wikimedia.org/wikipedia/commons/6/6d/Seal_of_Cybersecurity_and_Infrastructure_Security_Agency.svg"
                alt=""
              />
            </button>
          ) : (
            <div className="cisa-branding" aria-hidden="true">
              <img
                className="cisa-logo"
                src="https://upload.wikimedia.org/wikipedia/commons/6/6d/Seal_of_Cybersecurity_and_Infrastructure_Security_Agency.svg"
                alt=""
              />
            </div>
          )}
          {report ? (
            <button
              type="button"
              className="product-branding brand-title-control"
              onClick={returnToWelcome}
              aria-label="Return to eleVADR welcome screen"
              title="Return to welcome screen"
            >
              <span className="brand-name">eleVADR</span>
              <span className="brand-subtitle">
                OT Network Security Report Generator & Viewer
              </span>
            </button>
          ) : (
            <div className="product-branding">
              <span className="brand-name">eleVADR</span>
              <span className="brand-subtitle">
                OT Network Security Report Generator & Viewer
              </span>
            </div>
          )}
        </div>

        <div className="titlebar-center" />

        <div className="titlebar-actions">
          {report && (
            <ReportSearch
              report={report}
              onFilter={applyFilter}
              onSelect={setSelectedEntity}
            />
          )}
          {report && (
            <button
              type="button"
              className="top-action-button"
              onClick={shareCurrentView}
            >
              <Icon name="share" />
              <span>{shareStatus || "Share"}</span>
            </button>
          )}
          {report && (
            <button
              id="report-customize-action"
              type="button"
              className="top-action-button"
              onClick={() => setReportCustomizationOpen(true)}
            >
              <Icon name="settings" />
              <span>Customize</span>
            </button>
          )}
          {report && (
            <button
              type="button"
              className="top-action-button"
              onClick={() => window.print()}
            >
              <Icon name="print" />
              <span>Print</span>
            </button>
          )}
          {report && (
            <button
              id="report-export-action"
              type="button"
              className="top-action-button"
              onClick={handleDownloadJson}
            >
              <Icon name="download" />
              <span>Export</span>
            </button>
          )}
          {report &&
            hasSupportedReportVersion && (
              <button
                type="button"
                className="top-action-button"
                onClick={toggleAllPanels}
                aria-label={
                  allPanelsExpanded
                    ? "Collapse all sections"
                    : "Expand all sections"
                }
                title={
                  allPanelsExpanded
                    ? "Collapse all sections"
                    : "Expand all sections"
                }
              >
                <Icon name="overview" />
                <span>{allPanelsExpanded ? "Collapse" : "Expand"}</span>
              </button>
            )}
          {authState?.user.authenticated && (
            <>
              <button
                id="report-modules-action"
                type="button"
                className="top-action-button"
                disabled={!canWriteAnalysis}
                title={
                  !canWriteAnalysis
                    ? "Read-only accounts cannot change detection modules."
                    : undefined
                }
                onClick={() => setDetectionModulesOpen(true)}
              >
                <Icon name="shield" />
                <span>Modules</span>
              </button>
              <button
                id="report-context-action"
                type="button"
                className="top-action-button"
                disabled={!canWriteAnalysis}
                title={
                  !canWriteAnalysis
                    ? "Read-only accounts cannot change Analysis Context."
                    : undefined
                }
                onClick={() => setDetectionConfigOpen(true)}
              >
                <Icon name="settings" />
                <span>Context</span>
              </button>
            </>
          )}
          {authState?.authEnabled && authState.user.authenticated && (
            <button
              type="button"
              className="top-action-button auth-user-action"
              onClick={handleSignOut}
              title="Sign out"
            >
              <Icon name="user" />
              <span>
                {authState.user.username} ({authState.user.role}) - Sign Out
              </span>
            </button>
          )}
          <button
            type="button"
            className="top-action-button"
            onClick={() => setHelpOpen(true)}
          >
            <Icon name="help" />
            <span>Help</span>
          </button>
        </div>
      </header>

      <aside
        className={`sidebar ${mobileNavOpen ? "sidebar-open" : ""}`}
        aria-label="Primary navigation"
      >
        <div className="sidebar-topline">
          <button
            type="button"
            className="sidebar-collapse-button"
            onClick={() => setSidebarCollapsed((collapsed) => !collapsed)}
            aria-label={
              sidebarCollapsed ? "Expand navigation" : "Collapse navigation"
            }
          >
            <Icon name="chevron" />
          </button>
        </div>

        <nav className="sidebar-nav" aria-label="Report sections">
          {navItems.map((item) => (
            <button
              type="button"
              key={item.id}
              className={activeSection === item.id ? "active" : ""}
              aria-current={activeSection === item.id ? "location" : undefined}
              onClick={() => goToSection(item.id)}
              title={sidebarCollapsed ? item.label : undefined}
            >
              <span className="sidebar-nav-icon">
                <Icon name={item.icon} />
              </span>
              <span className="sidebar-nav-label">{item.label}</span>
              {item.count !== null && (
                <span className="sidebar-count">{item.count}</span>
              )}
            </button>
          ))}
        </nav>

        {report && hasSupportedReportVersion && (
          <div className="sidebar-notes-area">
            <button
              id="report-notes-action"
              type="button"
              className={`sidebar-notes-button ${currentSectionHasNotes ? "has-notes" : ""}`}
              onClick={openSectionNotes}
              title={`Notes for ${activeSectionLabel}${currentSectionHasNotes ? " (notes exist)" : ""}`}
              aria-label={`Notes for ${activeSectionLabel}${currentSectionHasNotes ? ", notes exist" : ""}`}
            >
              <span className="sidebar-nav-icon">
                <Icon name="notes" />
              </span>
              <span className="sidebar-notes-copy">
                <strong>Notes</strong>
              </span>
              {currentSectionHasNotes && (
                <span className="notes-present-dot" aria-hidden="true" />
              )}
              {reportNoteCount > 0 && (
                <span className="sidebar-count notes-count">
                  {reportNoteCount}
                </span>
              )}
            </button>
          </div>
        )}
      </aside>

      {mobileNavOpen && (
        <button
          className="sidebar-backdrop"
          aria-label="Close navigation"
          onClick={closeMobileNav}
        />
      )}

      <main id="main-content" className="app-main" tabIndex={-1}>
        <div className="content-container">
          {report && hasSupportedReportVersion && (
            <InvestigationBar
              filters={filters}
              onRemove={removeFilter}
              onClear={() => setFilters([])}
            />
          )}

          {report && reportConfigurationStale && !reportRefreshInProgress && (
            <div className="report-configuration-stale" role="status">
              <div>
                <strong>Report configuration changed</strong>
                <span>
                  This report still reflects the previous Context/module
                  selection.
                </span>
              </div>
              <button
                type="button"
                onClick={() => setReportRefreshPromptOpen(true)}
              >
                Reload report
              </button>
            </div>
          )}

          {report && !hasSupportedReportVersion && (
            <div className="status-container">
              <div className="loading-container">
                <p className="loading-text">Unsupported report version</p>
                <p className="error-details">
                  This report is version "{report.report_version ?? "unknown"}",
                  but this frontend only supports 2.x reports.
                </p>
              </div>
            </div>
          )}

          {report &&
            hasSupportedReportVersion && (
              <>
                <div className="report-current-section" aria-live="polite">
                  <span className="report-current-section-icon">
                    <Icon
                      name={
                        (
                          REPORT_SECTION_META[
                            activeSection as ReportSectionId
                          ] || REPORT_SECTION_META.overview
                        ).icon
                      }
                    />
                  </span>
                  <span>Current section</span>
                  <strong>{activeSectionLabel}</strong>
                </div>
                <div className="panel-grid">
                  {visibleReportSections.has("overview") && (
                    <section
                      id="overview"
                      className="dashboard-section scroll-target"
                    >
                      <ReportSectionHeading
                        report={report}
                        section="overview"
                      />
                      {provenance?.source_type === "pcap" && (
                        <div
                          className="analysis-provenance"
                          aria-label="PCAP analysis provenance"
                        >
                          <div>
                            <span>Source PCAP</span>
                            <strong>
                              {String(provenance.source_filename || "Unknown")}
                            </strong>
                          </div>
                          <div>
                            <span>Context</span>
                            <strong>
                              {String(
                                provenance.detection_context_profile_name ||
                                  "Unnamed context",
                              )}
                            </strong>
                          </div>
                          <div>
                            <span>Zeek runtime</span>
                            <strong>
                              {String(provenance.zeek_runtime || "Unknown")}
                            </strong>
                          </div>
                          <div>
                            <span>Detectors</span>
                            <strong>
                              {String(
                                provenance.detector_modules_completed ?? 0,
                              )}
                              /
                              {String(
                                provenance.detector_modules_requested ?? 0,
                              )}{" "}
                              completed
                            </strong>
                          </div>
                        </div>
                      )}
                      {reportCompatibility?.migrated === true && (
                        <div
                          className="analysis-provenance"
                          aria-label="Legacy report compatibility"
                        >
                          <div>
                            <span>Loaded report format</span>
                            <strong>
                              {String(
                                reportCompatibility.source_report_version ||
                                  "Legacy",
                              )}
                            </strong>
                          </div>
                          <div>
                            <span>Viewer format</span>
                            <strong>
                              {String(
                                reportCompatibility.normalized_report_version ||
                                  report.report_version,
                              )}
                            </strong>
                          </div>
                          <div>
                            <span>Compatibility defaults</span>
                            <strong>
                              {compatibilityWarnings.length} applied
                            </strong>
                          </div>
                          <div>
                            <span>Status</span>
                            <strong>Loaded in compatibility mode</strong>
                          </div>
                        </div>
                      )}
                      <SecurityOverview
                        report={report}
                        onFilter={applyFilter}
                        onSelect={setSelectedEntity}
                      />
                    </section>
                  )}

                  {visibleReportSections.has("findings") && (
                    <section
                      id="findings"
                      className="dashboard-section scroll-target"
                    >
                      <ReportSectionHeading
                        report={report}
                        section="findings"
                      />
                      {reportFindingCount === 0 ? (
                        <ReportGuidance
                          title="No findings were generated"
                          note="A zero-finding result means the selected detector modules did not produce findings from the evidence and policy in this report; it does not prove the environment is risk-free."
                          actions={[
                            {
                              label: "Review Modules",
                              onClick: () => setDetectionModulesOpen(true),
                              primary: true,
                            },
                            {
                              label: "Review Context",
                              onClick: () => setDetectionConfigOpen(true),
                            },
                            {
                              label: "How findings are generated",
                              onClick: () => setHelpOpen(true),
                            },
                          ]}
                        >
                          <p>
                            No selected detection module produced a reportable
                            condition using the current Analysis Context and
                            retained evidence.
                          </p>
                        </ReportGuidance>
                      ) : (
                        <FindingsPanel
                          report={report}
                          filters={filters}
                          onFilter={applyFilter}
                          onSelect={setSelectedEntity}
                          onClearFilters={() => setFilters([])}
                        />
                      )}
                    </section>
                  )}

                  {visibleReportSections.has("devices") && (
                    <section
                      id="devices"
                      className="dashboard-section scroll-target"
                    >
                      <ReportSectionHeading report={report} section="devices" />
                      {reportDeviceCount === 0 ? (
                        <ReportGuidance
                          title="No device inventory is available"
                          note={
                            provenance?.source_type === "pcap"
                              ? "For PCAP analysis, device inventory depends on endpoint traffic visible in the capture. Context can classify or authorize observed assets, but it cannot create traffic that was not captured."
                              : "For imported JSON reports, the source report may not contain a device inventory."
                          }
                          actions={[
                            {
                              label: "Review Context",
                              onClick: () => setDetectionConfigOpen(true),
                              primary: true,
                            },
                            {
                              label: "Open Help",
                              onClick: () => setHelpOpen(true),
                            },
                          ]}
                        >
                          <p>
                            eleVADR did not receive enough device records to
                            populate this section. Check capture coverage,
                            source-report completeness, and the current
                            asset/context information.
                          </p>
                        </ReportGuidance>
                      ) : (
                        <>
                          <DevicePanel
                            report={report}
                            onFilter={applyFilter}
                            footerAction={
                              <button
                                type="button"
                                className="section-action-button"
                                onClick={exportAssetInventory}
                              >
                                <Icon name="download" />
                                <span>Export Asset Inventory</span>
                              </button>
                            }
                          />
                          <DevicesPanel
                            otDevices={report.modules.ot_devices}
                            itDevices={report.modules.it_devices}
                            edgeDevices={report.modules.edge_devices}
                            reportId={report.report_id}
                            filters={filters}
                            onFilter={applyFilter}
                            onSelect={setSelectedEntity}
                          />
                        </>
                      )}
                    </section>
                  )}

                  {visibleReportSections.has("services") && (
                    <section
                      id="services"
                      className="dashboard-section scroll-target"
                    >
                      <ReportSectionHeading
                        report={report}
                        section="services"
                      />
                      {reportServiceCount === 0 ? (
                        <ReportGuidance
                          title="No services were identified"
                          note="Service identification depends on protocol and port evidence present in the report. An empty service inventory is different from a service inventory with zero findings."
                          actions={[
                            ...(reportConnectionRecordCount > 0
                              ? [
                                  {
                                    label: "Review Connections",
                                    onClick: () => goToSection("connections"),
                                    primary: true,
                                  },
                                ]
                              : []),
                            {
                              label: "Open Help",
                              onClick: () => setHelpOpen(true),
                              primary: reportConnectionRecordCount === 0,
                            },
                          ]}
                        >
                          <p>
                            No OT, IT, or unclassified service records are
                            available for this report. Review the connection
                            evidence or capture scope to confirm whether
                            application traffic was visible.
                          </p>
                        </ReportGuidance>
                      ) : (
                        <>
                          <ServiceInventoryPanel
                            serviceCount={report.modules.service_count_panel}
                            otServices={report.modules.ot_services}
                            implicatedCount={
                              new Set(
                                deriveFindings(report)
                                  .map((finding) => finding.service)
                                  .filter(Boolean),
                              ).size
                            }
                            filters={filters}
                            onFilter={applyFilter}
                            onSelect={setSelectedEntity}
                          />
                          <ServiceRiskBreakdownPanel
                            data={report.modules.service_risk_breakdown_panel}
                            reportId={report.report_id}
                            filters={filters}
                            onFilter={applyFilter}
                          />
                        </>
                      )}
                    </section>
                  )}

                  {visibleReportSections.has("topology") && (
                    <section id="topology" className="dashboard-section scroll-target">
                      <ReportSectionHeading report={report} section="topology" />
                      {reportConnectionRecordCount === 0 ? (
                        <ReportGuidance title="No topology communication records are available">
                          <p>This report does not include endpoint communications from which to construct an observed topology.</p>
                        </ReportGuidance>
                      ) : (
                          <Panel
                            id="network-topology"
                            title={
                              <div
                                style={{
                                  display: "flex",
                                  alignItems: "center",
                                  gap: "8px",
                                }}
                              >
                                <span>Network Topology</span>
                                <InfoTooltip text="Interactive view of observed devices and the communication paths between them. Select a device or connection to inspect and pivot into related evidence." />
                              </div>
                            }
                          >
                            <NetworkTopology
                              report={report}
                              filters={filters}
                              onFilter={applyFilter}
                              onSelect={setSelectedEntity}
                              onStateChange={setGraphViewState}
                            />
                          </Panel>
                      )}
                    </section>
                  )}

                  {visibleReportSections.has("connections") && (
                    <section
                      id="connections"
                      className="dashboard-section scroll-target"
                    >
                      <ReportSectionHeading
                        report={report}
                        section="connections"
                      />
                      {reportConnectionRecordCount === 0 ? (
                        <ReportGuidance
                          title="No endpoint connection records are available"
                          note={
                            provenance?.source_type === "pcap"
                              ? "For PCAP analysis, verify that the capture contains endpoint traffic and that the capture scope represents the network you intended to analyze."
                              : "For imported JSON reports, the source report may not include flow-level connection records."
                          }
                          actions={[
                            {
                              label: "Review Context",
                              onClick: () => setDetectionConfigOpen(true),
                              primary: true,
                            },
                            {
                              label: "Open Help",
                              onClick: () => setHelpOpen(true),
                            },
                          ]}
                        >
                          <p>
                            Without endpoint communication records, eleVADR
                            cannot build flow tables, topology, activity
                            relationships, or cross-segment connection views for
                            this report.
                          </p>
                        </ReportGuidance>
                      ) : (
                        <>
                          <ConnectionOverviewPanel report={report} />
                          <SupplementalSubnetPanel
                            rows={supplementalSubnets}
                            filters={filters}
                            onChange={setSupplementalSubnets}
                            onFilter={applyFilter}
                          />
                          <ZeekFlowAnalysis
                            report={report}
                            filters={filters}
                            onFilter={applyFilter}
                            onSelect={setSelectedEntity}
                          />
                          <Panel
                            id="activity-timeline"
                            title={
                              <div
                                style={{
                                  display: "flex",
                                  alignItems: "center",
                                  gap: "8px",
                                }}
                              >
                                <span>Activity Timeline</span>
                                <InfoTooltip text="Temporal view of timestamped network observations. When time data is available, use this view to identify bursts and suspicious activity over time." />
                              </div>
                            }
                          >
                            <ActivityTimeline report={report} />
                          </Panel>
                          <OTCrossSegmentPanel
                            data={report.modules.ot_cross_segment_lines_panel}
                            reportId={report.report_id}
                            filters={filters}
                            onFilter={applyFilter}
                            onSelect={setSelectedEntity}
                          />
                          <ConnectionSuccessPanel
                            data={report.modules.connection_success_panel}
                            reportId={report.report_id}
                            filters={filters}
                            onFilter={applyFilter}
                            onSelect={setSelectedEntity}
                          />
                          <SuspiciousOutboundConnectionsPanel
                            data={
                              report.modules
                                .suspicious_outbound_connections_panel
                            }
                            reportId={report.report_id}
                            filters={filters}
                            onFilter={applyFilter}
                            onSelect={setSelectedEntity}
                          />
                        </>
                      )}
                    </section>
                  )}
                </div>
              </>
            )}
        </div>
      </main>

      <div
        className={`welcome-dialog-backdrop ${report ? "is-hidden" : ""}`}
        aria-hidden={report ? true : undefined}
      >
        <div
          className="welcome-dialog"
          role="dialog"
          aria-modal="true"
          aria-labelledby="welcome-dialog-title"
          aria-describedby="welcome-dialog-description"
        >
          <div className="welcome-dialog-header">
            <h1 id="welcome-dialog-title" className="sr-only">
              eleVADR Welcome
            </h1>
            <img
              className="welcome-cisa-logo"
              src="https://upload.wikimedia.org/wikipedia/commons/6/6d/Seal_of_Cybersecurity_and_Infrastructure_Security_Agency.svg"
              alt="Cybersecurity and Infrastructure Security Agency"
            />
            <p
              id="welcome-dialog-description"
              className="welcome-dialog-description"
            >
              eleVADR generates and presents OT network security reports from
              packet captures, helping analysts quickly review observed devices,
              services, connections, and priority findings.
            </p>
          </div>

          <div className="welcome-primary-actions">
            {authLoading ? (
              <section
                className="welcome-account-panel auth-login-gate"
                aria-live="polite"
              >
                <h2>Checking authentication…</h2>
                <p>Connecting to the eleVADR backend.</p>
              </section>
            ) : authenticationRequired ? (
              <section
                className="welcome-account-panel auth-login-gate"
                aria-labelledby="welcome-account-title"
              >
                <div className="welcome-account-heading">
                  <div>
                    <h2 id="welcome-account-title">Sign in to eleVADR</h2>
                    <p>Use your eleVADR account to access analysis features.</p>
                  </div>
                </div>
                <form className="welcome-login-form" onSubmit={handleSignIn}>
                  <label>
                    <span>Username</span>
                    <input
                      type="text"
                      value={welcomeUsername}
                      onChange={(event) =>
                        setWelcomeUsername(event.target.value)
                      }
                      autoComplete="username"
                      autoFocus
                    />
                  </label>
                  <label>
                    <span>Password</span>
                    <input
                      type="password"
                      value={welcomePassword}
                      onChange={(event) =>
                        setWelcomePassword(event.target.value)
                      }
                      autoComplete="current-password"
                    />
                  </label>
                  <button
                    type="submit"
                    className="welcome-signin-button"
                    disabled={authSubmitting}
                  >
                    {authSubmitting ? "Signing in…" : "Sign in"}
                  </button>
                  {welcomeAuthMessage && (
                    <p className="welcome-auth-message" role="alert">
                      {welcomeAuthMessage}
                    </p>
                  )}
                </form>
              </section>
            ) : (
              <>
                {authState?.authEnabled && authState.user.authenticated && (
                  <>
                    <nav
                      className="platform-workspace-nav"
                      aria-label="Platform workspace"
                    >
                      {(
                        [
                          ["open-file", "Open File"],
                          ["analyses", "Analyses"],
                          ["storage", "Storage"],
                          ...(authState.user.role === "admin"
                            ? [["administration", "Administration"] as const]
                            : [["account", "Account"] as const]),
                        ] as const
                      ).map(([id, label]) => (
                        <button
                          key={id}
                          type="button"
                          className={platformView === id ? "is-active" : ""}
                          aria-current={
                            platformView === id ? "page" : undefined
                          }
                          onClick={() => setPlatformView(id)}
                        >
                          {label}
                        </button>
                      ))}
                    </nav>
                  </>
                )}
                {canWriteAnalysis ? (
                  <div style={{ display: (!authState?.authEnabled || !authState.user.authenticated || platformView === "open-file") ? undefined : "none" }}>
                    <UploadForm
                      onReportLoaded={handleReportLoaded}
                      recoveryJob={recoveredJobs.find((job) => job.status === "running" || job.status === "queued") || recoveredJobs.find((job) => job.status === "completed") || null}
                      report={report}
                      isAnalyzing={isAnalyzing}
                      setIsAnalyzing={setIsAnalyzing}
                      inputId="welcome-file-input"
                      onOpenDetectionContext={() =>
                        setDetectionConfigOpen(true)
                      }
                      onOpenDetectionModules={() =>
                        setDetectionModulesOpen(true)
                      }
                      profileRevision={detectionProfileRevision}
                      refreshRequestRevision={reportRefreshRequestRevision}
                      onReanalysisStatus={handleReportReanalysisStatus}
                    />
                  </div>
                ) : (!authState?.authEnabled || !authState.user.authenticated || platformView === "open-file") ? (
                    <section className="welcome-account-panel read-only-notice" aria-label="Read-only access">
                      <h2>Read-only access</h2>
                      <p>You can open saved reports and review retained PCAP metadata. Upload and analysis are unavailable for this account.</p>
                    </section>
                ) : null}
                {authState?.authEnabled &&
                  authState.user.authenticated &&
                  platformView === "analyses" && (
                    <section
                      className="welcome-account-panel analyses-workspace platform-workspace-view"
                      aria-labelledby="analyses-title"
                    >
                      <div className="welcome-account-heading analyses-heading">
                        <div>
                          <h2 id="analyses-title">Analyses</h2>
                          <p>
                            Work from retained captures, reopen prior analyses,
                            re-analyze with the active Detection Context, or
                            compare analysis results.
                          </p>
                        </div>
                        <button
                          type="button"
                          className="welcome-secondary-button"
                          onClick={() => {
                            void refreshSavedReports();
                            void refreshRetainedCaptures();
                          }}
                        >
                          Refresh
                        </button>
                      </div>

                      <div className="analyses-unified-toolbar">
                        <div className="saved-report-library-tools analyses-search-tools">
                          <label>
                            <span>Search</span>
                            <input
                              type="search"
                              placeholder="Analysis or PCAP name…"
                              value={savedReportQuery}
                              onChange={(event) => setSavedReportQuery(event.target.value)}
                            />
                          </label>
                          <label>
                            <span>Sort</span>
                            <select
                              value={savedReportSort}
                              onChange={(event) => setSavedReportSort(event.target.value)}
                            >
                              <option value="newest">Newest activity</option>
                              <option value="oldest">Oldest activity</option>
                              <option value="title">PCAP name</option>
                              <option value="findings-desc">Findings: high to low</option>
                              <option value="findings-asc">Findings: low to high</option>
                            </select>
                          </label>
                          <span className="saved-report-count">
                            {analysisCaptureGroups.length} PCAPs · {savedReports.length} analyses
                          </span>
                        </div>
                        {reportComparison ? (
                          <div className="report-comparison analyses-inline-comparison" aria-live="polite">
                            <div className="comparison-heading">
                              <div>
                                <span className="comparison-kicker">Analysis comparison</span>
                                <h3>What changed?</h3>
                              </div>
                              <button
                                type="button"
                                className="welcome-secondary-button"
                                onClick={() => setReportComparison(null)}
                              >
                                Close comparison
                              </button>
                            </div>
                            <div className="comparison-grid">
                              <div><span>Findings</span><strong>+{reportComparison.findings.added} / -{reportComparison.findings.removed} / ~{reportComparison.findings.changed}</strong></div>
                              <div><span>Assets</span><strong>+{reportComparison.assets.added} / -{reportComparison.assets.removed} / ~{reportComparison.assets.changed}</strong></div>
                              <div><span>Services</span><strong>+{reportComparison.services.added} / -{reportComparison.services.removed} / ~{reportComparison.services.changed}</strong></div>
                              <div><span>Context changes</span><strong>{reportComparison.contextDeltas.length}</strong></div>
                            </div>
                            <details className="comparison-details">
                              <summary>Finding changes ({reportComparison.findingDeltas.length})</summary>
                              {reportComparison.findingDeltas.length ? (
                                <ul>{reportComparison.findingDeltas.map((delta) => (
                                  <li key={delta.key}>
                                    <strong>{delta.change}: {delta.title}</strong> ({delta.moduleId})
                                    <span> Severity: {delta.severityBefore || "Not recorded"} → {delta.severityAfter || "Not recorded"}; Confidence: {delta.confidenceBefore || "Not recorded"} → {delta.confidenceAfter || "Not recorded"}</span>
                                  </li>
                                ))}</ul>
                              ) : <p>No finding changes.</p>}
                            </details>
                            <details className="comparison-details">
                              <summary>Module configuration changes ({reportComparison.moduleDeltas.length})</summary>
                              {reportComparison.moduleDeltas.length ? (
                                <ul>{reportComparison.moduleDeltas.map((delta) => (
                                  <li key={delta.path}><strong>{delta.path}</strong>: {formatComparisonValue(delta.before)} → {formatComparisonValue(delta.after)}</li>
                                ))}</ul>
                              ) : <p>No module configuration changes.</p>}
                            </details>
                            <details className="comparison-details">
                              <summary>Detection Context changes ({reportComparison.contextDeltas.length})</summary>
                              {reportComparison.contextDeltas.length ? (
                                <ul>{reportComparison.contextDeltas.map((delta) => (
                                  <li key={delta.path}><strong>{delta.path}</strong>: {formatComparisonValue(delta.before)} → {formatComparisonValue(delta.after)}</li>
                                ))}</ul>
                              ) : <p>No Detection Context changes.</p>}
                            </details>
                          </div>
                        ) : compareReportIds.length === 2 ? (
                          <div className="analyses-compare-toolbar">
                            <button
                              type="button"
                              className="welcome-secondary-button"
                              disabled={comparisonLoading}
                              onClick={() => void compareSelectedReports()}
                            >
                              {comparisonLoading ? "Comparing…" : "Compare analyses"}
                            </button>
                          </div>
                        ) : null}
                      </div>

                      {capturesLoading || savedReportsLoading ? (
                        <p>Loading analyses…</p>
                      ) : analysisCaptureGroups.length ? (
                        <div className="analysis-capture-list unified-analysis-tree">
                          {analysisCaptureGroups.map((group) => {
                            const retained = group.capture;
                            const analyses = group.analyses;
                            const latest = analyses[0];
                            const historyOpen = historyCaptureId === group.key;
                            const menuOpen = captureMenuId === group.key;
                            return (
                              <article
                                className={`analysis-capture-card ${retained ? "" : "is-not-retained"}`}
                                key={group.key}
                              >
                                <div
                                  className="analysis-capture-main analysis-capture-toggle"
                                  role="button"
                                  tabIndex={0}
                                  aria-expanded={historyOpen}
                                  onClick={() => {
                                    setHistoryCaptureId(historyOpen ? "" : group.key);
                                    setCaptureMenuId("");
                                  }}
                                  onKeyDown={(event) => {
                                    if (event.key === "Enter" || event.key === " ") {
                                      event.preventDefault();
                                      setHistoryCaptureId(historyOpen ? "" : group.key);
                                      setCaptureMenuId("");
                                    }
                                  }}
                                >
                                  <div className="analysis-capture-copy">
                                    <div className="analysis-capture-title-row">
                                      <span className="analysis-tree-chevron" aria-hidden="true">
                                        {historyOpen ? "▾" : "▸"}
                                      </span>
                                      <strong>{group.filename}</strong>
                                    </div>
                                    {retained ? (
                                      <>
                                        <span>
                                          Retained {new Date(retained.createdAt).toLocaleString()} ·{" "}
                                          {(retained.sizeBytes / (1024 * 1024)).toFixed(1)} MB ·{" "}
                                          {analyses.length} {analyses.length === 1 ? "analysis" : "analyses"}
                                        </span>
                                        <span>
                                          {retained.expiresAt
                                            ? `Expires ${new Date(retained.expiresAt).toLocaleString()}`
                                            : "No automatic expiry"}
                                        </span>
                                      </>
                                    ) : (
                                      <span className="analysis-source-state is-unavailable">
                                        PCAP not retained · {analyses.length}{" "}
                                        {analyses.length === 1 ? "analysis" : "analyses"}
                                      </span>
                                    )}
                                  </div>
                                  <div
                                    className="analysis-capture-actions"
                                    onClick={(event) => event.stopPropagation()}
                                  >
                                    {canWriteAnalysis && (
                                      <button
                                        type="button"
                                        className="welcome-secondary-button"
                                        disabled={!retained || Boolean(captureAnalyzingId)}
                                        title={
                                          retained
                                            ? undefined
                                            : "Source PCAP is not retained. Upload it again to run another analysis."
                                        }
                                        onClick={() => {
                                          if (retained)
                                            void reanalyzeRetainedCapture(retained.captureId);
                                        }}
                                      >
                                        {retained && captureAnalyzingId === retained.captureId
                                          ? "Analyzing…"
                                          : analyses.length
                                            ? "Re-analyze"
                                            : "Analyze"}
                                      </button>
                                    )}
                                    {canWriteAnalysis && (
                                      <div className="capture-overflow">
                                        <button
                                          type="button"
                                          className="capture-overflow-trigger"
                                          aria-label={`More actions for ${group.filename}`}
                                          aria-expanded={menuOpen}
                                          onClick={() =>
                                            setCaptureMenuId(menuOpen ? "" : group.key)
                                          }
                                        >
                                          ⋯
                                        </button>
                                        {menuOpen && (
                                          <div className="capture-overflow-menu">
                                            <button
                                              type="button"
                                              disabled={!retained}
                                              title={retained ? "Download the original retained capture" : "This PCAP is no longer retained."}
                                              onClick={() => {
                                                if (!retained) return;
                                                setCaptureMenuId("");
                                                void downloadRetainedCapture(retained.captureId, retained.filename).catch((error: unknown) => {
                                                  setCapturesMessage(error instanceof Error ? error.message : "PCAP download failed.");
                                                });
                                              }}
                                            >
                                              Download PCAP
                                            </button>
                                            {retained && deleteConfirmCaptureId === retained.captureId ? (
                                              <div className="capture-delete-confirmation">
                                                <strong>Delete retained PCAP?</strong>
                                                <span>
                                                  Saved analyses will remain available, but re-analysis
                                                  will require uploading the capture again.
                                                </span>
                                                <button
                                                  type="button"
                                                  className="is-destructive"
                                                  onClick={() =>
                                                    void removeRetainedCapture(retained.captureId)
                                                  }
                                                >
                                                  Delete PCAP
                                                </button>
                                                <button
                                                  type="button"
                                                  onClick={() => setDeleteConfirmCaptureId("")}
                                                >
                                                  Cancel
                                                </button>
                                              </div>
                                            ) : (
                                              <button
                                                type="button"
                                                className="is-destructive"
                                                disabled={!retained}
                                                title={
                                                  retained
                                                    ? undefined
                                                    : "This PCAP is no longer retained."
                                                }
                                                onClick={() => {
                                                  if (retained)
                                                    void removeRetainedCapture(retained.captureId);
                                                }}
                                              >
                                                Delete retained PCAP
                                              </button>
                                            )}
                                          </div>
                                        )}
                                      </div>
                                    )}
                                  </div>
                                </div>

                                {historyOpen && (
                                  <div className="capture-analysis-history analysis-tree-children">
                                    {analyses.length ? (
                                      analyses.map((analysis, index) => {
                                        const selected = compareReportIds.includes(
                                          analysis.reportId,
                                        );
                                        return (
                                          <div
                                            className={`capture-history-row analysis-tree-row ${selected ? "is-selected" : ""}`}
                                            key={analysis.reportId}
                                            role="button"
                                            tabIndex={0}
                                            onClick={() => void openSavedReport(analysis.reportId)}
                                            onKeyDown={(event) => {
                                              if (event.key === "Enter" || event.key === " ") {
                                                event.preventDefault();
                                                void openSavedReport(analysis.reportId);
                                              }
                                            }}
                                          >
                                            <div className="analysis-tree-branch" aria-hidden="true" />
                                            <input
                                              type="checkbox"
                                              aria-label={`Select analysis from ${new Date(analysis.createdAt).toLocaleString()} for comparison`}
                                              checked={selected}
                                              onClick={(event) => event.stopPropagation()}
                                              onChange={() => toggleCompareReport(analysis.reportId)}
                                            />
                                            <div className="capture-history-details">
                                              <div className="capture-history-title">
                                                <strong>
                                                  {new Date(analysis.createdAt).toLocaleString()}
                                                </strong>
                                                {index === 0 && (
                                                  <span className="analysis-current-badge">Current</span>
                                                )}
                                              </div>
                                              <span>
                                                {analysis.findingCount} findings · {analysis.deviceCount}{" "}
                                                devices
                                              </span>
                                              <span>
                                                Saved analysis · source evidence{" "}
                                                {retained ? "retained" : "not retained"}
                                              </span>
                                            </div>
                                            {canWriteAnalysis && (
                                              <div
                                                className="analysis-row-actions"
                                                onClick={(event) => event.stopPropagation()}
                                              >
                                                {renamingReportId === analysis.reportId ? (
                                                  <div className="analysis-inline-rename">
                                                    <input
                                                      value={renameDraft}
                                                      aria-label="Analysis name"
                                                      onChange={(event) =>
                                                        setRenameDraft(event.target.value)
                                                      }
                                                      onKeyDown={(event) => {
                                                        if (event.key === "Enter")
                                                          void saveReportRename(analysis.reportId);
                                                        if (event.key === "Escape") {
                                                          setRenamingReportId("");
                                                          setRenameDraft("");
                                                        }
                                                      }}
                                                    />
                                                    <button
                                                      type="button"
                                                      className="saved-report-icon-button"
                                                      aria-label="Save analysis name"
                                                      onClick={() =>
                                                        void saveReportRename(analysis.reportId)
                                                      }
                                                    >
                                                      <Icon name="check" />
                                                    </button>
                                                  </div>
                                                ) : (
                                                  <button
                                                    type="button"
                                                    className="saved-report-icon-button"
                                                    aria-label={`Rename ${analysis.title}`}
                                                    title="Rename"
                                                    onClick={() => {
                                                      setRenamingReportId(analysis.reportId);
                                                      setRenameDraft(analysis.title);
                                                      setDeleteConfirmReportId("");
                                                    }}
                                                  >
                                                    <Icon name="edit" />
                                                  </button>
                                                )}
                                                <button
                                                  type="button"
                                                  className={`saved-report-icon-button saved-report-delete ${deleteConfirmReportId === analysis.reportId ? "is-confirming" : ""}`}
                                                  aria-label={
                                                    deleteConfirmReportId === analysis.reportId
                                                      ? `Confirm delete ${analysis.title}`
                                                      : `Delete ${analysis.title}`
                                                  }
                                                  title={
                                                    deleteConfirmReportId === analysis.reportId
                                                      ? "Confirm delete"
                                                      : "Delete"
                                                  }
                                                  onClick={() =>
                                                    void removeSavedReport(analysis.reportId)
                                                  }
                                                >
                                                  <Icon
                                                    name={
                                                      deleteConfirmReportId === analysis.reportId
                                                        ? "check"
                                                        : "trash"
                                                    }
                                                  />
                                                </button>
                                              </div>
                                            )}
                                          </div>
                                        );
                                      })
                                    ) : (
                                      <p className="analysis-tree-empty">
                                        No saved analyses are linked to this PCAP yet.
                                      </p>
                                    )}
                                  </div>
                                )}
                              </article>
                            );
                          })}
                        </div>
                      ) : (
                        <p className="saved-report-empty">
                          No PCAPs or analyses match your search.
                        </p>
                      )}

                      {(savedReportsMessage || capturesMessage) && (
                        <p className="welcome-auth-message" role="alert">{savedReportsMessage || capturesMessage}</p>
                      )}
                    </section>
                  )}
                {authState?.authEnabled &&
                  authState.user.authenticated &&
                  platformView === "storage" && (
                    <section
                      className="welcome-account-panel platform-storage-panel platform-workspace-view"
                      aria-labelledby="storage-title"
                    >
                      <div className="welcome-account-heading">
                        <div>
                          <h2 id="storage-title">Storage & Retention</h2>
                          <p>
                            Reports are durable. Retained PCAPs follow the
                            configured retention and per-user storage policy.
                          </p>
                        </div>
                        <button
                          type="button"
                          className="welcome-secondary-button"
                          onClick={() => void refreshStorageSummary()}
                        >
                          Refresh
                        </button>
                      </div>
                      {storageSummary ? (
                        <div className="platform-dashboard-summary">
                          <div>
                            <span>{storageSummary.scope === "all" ? "Capture storage (all users)" : "My capture storage"}</span>
                            <strong>
                              {(
                                (storageSummary.captureBytes || 0) /
                                (1024 * 1024)
                              ).toFixed(1)}{" "}
                              MB
                            </strong>
                          </div>
                          <div>
                            <span>{storageSummary.scope === "all" ? "Report storage (all users)" : "My report storage"}</span>
                            <strong>
                              {(
                                (storageSummary.reportBytes || 0) /
                                (1024 * 1024)
                              ).toFixed(1)}{" "}
                              MB
                            </strong>
                          </div>
                          <div>
                            <span>PCAP retention</span>
                            <strong>
                              {storageSummary.retentionDays
                                ? `${storageSummary.retentionDays} days`
                                : "Disabled"}
                            </strong>
                          </div>
                          <div>
                            <span>PCAP limit</span>
                            <strong>
                              {storageSummary.limitBytes
                                ? `${(storageSummary.limitBytes / (1024 * 1024 * 1024)).toFixed(1)} GB`
                                : "Unlimited"}
                            </strong>
                          </div>
                        </div>
                      ) : (
                        <p className="saved-report-empty">
                          Storage usage has not been loaded yet.
                        </p>
                      )}
                      {authState.user.role === "admin" &&
                        storageSummary?.scope === "all" && (
                          <>
                            <p>
                              Orphan capture files detected:{" "}
                              <strong>{storageSummary.orphanFiles || 0}</strong>
                            </p>
                            <p className="storage-scope-note">Storage totals above reflect the {storageSummary.scope === "all" ? "administrator-wide" : "current account"} summary returned by the server. The per-user totals below include all storage attributed to each account.</p>
                            {storageSummary.users?.length ? (
                              <div className="platform-user-list">
                                {storageSummary.users.map((u) => (
                                  <article
                                    className="platform-user-row"
                                    key={u.ownerId}
                                  >
                                    <div>
                                      <strong>{u.username || u.ownerId}</strong>
                                      <span>
                                        {u.captureCount} PCAP(s) ·{" "}
                                        {u.reportCount} report(s)
                                      </span>
                                    </div>
                                    <div>
                                      <strong>
                                        {(u.totalBytes / (1024 * 1024)).toFixed(
                                          1,
                                        )}{" "}
                                        MB
                                      </strong>
                                    </div>
                                  </article>
                                ))}
                              </div>
                            ) : null}
                            <div className="platform-storage-maintenance">
                              <h3>Storage maintenance</h3>
                              <p>Expired captures: {storageSummary.retentionDays ? "Check available" : "Retention disabled"} · Orphan files: {storageSummary.orphanFiles ?? 0}</p>
                              <div className="saved-report-actions">
                                <button type="button" className="welcome-secondary-button"
                                  disabled={!storageSummary.retentionDays}
                                  title={!storageSummary.retentionDays ? "PCAP retention is disabled" : "Remove captures past the configured retention period"}
                                  onClick={() => { if (window.confirm("Delete expired retained PCAPs? Saved analyses will remain available.")) void runStorageCleanup(false); }}>
                                  Delete expired captures
                                </button>
                                <button type="button" className="welcome-secondary-button"
                                  disabled={!storageSummary.orphanFiles}
                                  title={!storageSummary.orphanFiles ? "No orphan capture files detected" : "Delete orphan capture files"}
                                  onClick={() => { if (window.confirm("Delete orphan capture files? This cleanup also processes expired captures. Saved analyses will remain available.")) void runStorageCleanup(true); }}>
                                  Delete orphaned files
                                </button>
                              </div>
                            </div>
                          </>
                        )}
                      {storageMessage && (
                        <p className="welcome-auth-message" role="status">
                          {storageMessage}
                        </p>
                      )}
                    </section>
                  )}
                {authState?.authEnabled && authState.user.authenticated &&
                  authState.user.role === "admin" && platformView === "administration" && (
                    <nav className="platform-admin-tabs" aria-label="Administration sections">
                      <button type="button" className={adminTab === "users" ? "is-active" : ""} onClick={() => setAdminTab("users")}>Users</button>
                      <button type="button" className={adminTab === "audit" ? "is-active" : ""} onClick={() => { setAdminTab("audit"); void refreshAuditEvents(); }}>Audit Log</button>
                    </nav>
                  )}
                {authState?.authEnabled &&
                  authState.user.authenticated &&
                  platformView === "administration" &&
                  authState.user.role === "admin" && adminTab === "audit" && (
                    <section
                      className="welcome-account-panel platform-activity-panel platform-workspace-view"
                      aria-labelledby="recent-activity-title"
                    >
                      <div className="welcome-account-heading">
                        <div>
                          <h2 id="recent-activity-title">
                            {authState.user.role === "admin"
                              ? "Audit & Activity"
                              : "Recent Activity"}
                          </h2>
                          <p>
                            {authState.user.role === "admin"
                              ? "Recent platform activity across local accounts."
                              : "Recent security and data activity for your account."}
                          </p>
                        </div>
                        <button
                          type="button"
                          className="welcome-secondary-button"
                          onClick={() => void refreshAuditEvents()}
                        >
                          Refresh
                        </button>
                      </div>
                      {auditEvents.length ? (
                        <div className="platform-activity-list">
                          {auditEvents.slice(0, 20).map((event) => (
                            <article
                              className="platform-activity-row"
                              key={event.eventId}
                            >
                              <div>
                                <strong>
                                  {event.action.replaceAll(".", " · ")}
                                </strong>
                                <span>
                                  {event.actorUsername || "System"}
                                  {event.targetType
                                    ? ` · ${event.targetType}`
                                    : ""}
                                  {event.targetId
                                    ? ` · ${event.targetId.slice(0, 12)}`
                                    : ""}
                                </span>
                              </div>
                              <div>
                                <span
                                  className={`activity-result ${event.result}`}
                                >
                                  {event.result}
                                </span>
                                <time>
                                  {event.createdAt
                                    ? new Date(event.createdAt).toLocaleString()
                                    : ""}
                                </time>
                              </div>
                            </article>
                          ))}
                        </div>
                      ) : (
                        <p className="saved-report-empty">
                          No activity has been loaded yet. Select Refresh to
                          view recent events.
                        </p>
                      )}
                      {auditMessage && (
                        <p className="welcome-auth-message" role="status">
                          {auditMessage}
                        </p>
                      )}
                    </section>
                  )}
                {authState?.authEnabled &&
                  authState.user.authenticated &&
                  (platformView === "account" ||
                    (platformView === "administration" && adminTab === "users")) && (
                    <section
                      className="welcome-account-panel platform-account-panel platform-workspace-view"
                      aria-labelledby="account-management-title"
                    >
                      <div className="welcome-account-heading">
                        <div>
                          <h2 id="account-management-title">{authState.user.role === "admin" ? "Users & Account" : "Account"}</h2>
                          <p>
                            Manage your password
                            {authState.user.role === "admin"
                              ? " and local eleVADR users"
                              : ""}
                            .
                          </p>
                        </div>
                      </div>
                      <form
                        className="platform-account-form"
                        onSubmit={submitPasswordChange}
                      >
                        <h3>Change password</h3>
                        <label>
                          <span>Current password</span>
                          <input
                            type="password"
                            autoComplete="current-password"
                            value={currentPassword}
                            onChange={(e) => setCurrentPassword(e.target.value)}
                            required
                          />
                        </label>
                        <label>
                          <span>New password</span>
                          <input
                            type="password"
                            autoComplete="new-password"
                            minLength={8}
                            value={newPassword}
                            onChange={(e) => setNewPassword(e.target.value)}
                            required
                          />
                        </label>
                        <button
                          className="welcome-secondary-button"
                          type="submit"
                        >
                          Change password
                        </button>
                      </form>
                      {authState.user.role === "admin" && (
                        <div className="platform-admin-users">
                          <form
                            className="platform-account-form"
                            onSubmit={submitNewUser}
                          >
                            <h3>Create user</h3>
                            <label>
                              <span>Username</span>
                              <input
                                value={newUsername}
                                onChange={(e) => setNewUsername(e.target.value)}
                                required
                              />
                            </label>
                            <label>
                              <span>Temporary password</span>
                              <input
                                type="password"
                                minLength={8}
                                value={newUserPassword}
                                onChange={(e) =>
                                  setNewUserPassword(e.target.value)
                                }
                                required
                              />
                            </label>
                            <label>
                              <span>Role</span>
                              <select
                                value={newUserRole}
                                onChange={(e) => setNewUserRole(e.target.value)}
                              >
                                <option value="analyst">Analyst</option>
                                <option value="read_only">Read only</option>
                                <option value="admin">Admin</option>
                              </select>
                            </label>
                            <button
                              className="welcome-secondary-button"
                              type="submit"
                            >
                              Create user
                            </button>
                          </form>
                          <div>
                            <h3>Users</h3>
                            <div className="platform-user-list">
                              {platformUsers.map((user) => (
                                <article
                                  key={user.id}
                                  className="platform-user-row"
                                >
                                  <div>
                                    <strong>{user.username}</strong>
                                    <span>
                                      {user.disabled ? "Disabled" : "Active"}
                                      {user.lastLogin
                                        ? ` · Last login ${new Date(user.lastLogin).toLocaleString()}`
                                        : ""}
                                    </span>
                                  </div>
                                  <div className="saved-report-actions">
                                    <select
                                      aria-label={`Role for ${user.username}`}
                                      value={user.role}
                                      onChange={(e) =>
                                        void changeUser(user, {
                                          role: e.target.value,
                                        })
                                      }
                                    >
                                      <option value="admin">Admin</option>
                                      <option value="analyst">Analyst</option>
                                      <option value="read_only">
                                        Read only
                                      </option>
                                    </select>
                                    <button
                                      type="button"
                                      className="welcome-secondary-button"
                                      disabled={user.id === authState.user.id}
                                      onClick={() =>
                                        void changeUser(user, {
                                          disabled: !user.disabled,
                                        })
                                      }
                                    >
                                      {user.disabled ? "Enable" : "Disable"}
                                    </button>
                                  </div>
                                </article>
                              ))}
                            </div>
                          </div>
                        </div>
                      )}
                      {accountMessage && (
                        <p className="welcome-auth-message" role="status">
                          {accountMessage}
                        </p>
                      )}
                    </section>
                  )}
              </>
            )}
          </div>
        </div>
      </div>

      {!report && welcomeInstructionsOpen && (
        <div
          className="welcome-instructions-backdrop"
          role="presentation"
          onMouseDown={(event) => {
            if (event.currentTarget === event.target)
              setWelcomeInstructionsOpen(false);
          }}
        >
          <section
            className="welcome-instructions-dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="welcome-instructions-title"
          >
            <header className="welcome-instructions-header">
              <div>
                <h2 id="welcome-instructions-title">How to Use eleVADR</h2>
                <p>
                  Open a report or packet capture, or sign in to your eleVADR
                  workspace.
                </p>
              </div>
              <button
                type="button"
                className="welcome-instructions-close"
                onClick={() => setWelcomeInstructionsOpen(false)}
                aria-label="Close instructions"
              >
                ×
              </button>
            </header>
            <div className="welcome-instructions-body">
              <section>
                <h3>Open a local file</h3>
                <p>
                  Choose a PCAP, PCAPNG, or eleVADR JSON report from your
                  computer. Packet captures are analyzed before the report view
                  opens.
                </p>
              </section>
              <section>
                <h3>Sign in</h3>
                <p>
                  Sign in with your eleVADR account. Your saved reports and
                  retained PCAPs are available from the signed-in dashboard.
                </p>
              </section>
              <section>
                <h3>Review the report</h3>
                <p>
                  Use Summary, Findings, Devices, Services, and Connections to
                  move through the long-form report. Expand or collapse panels
                  as needed.
                </p>
              </section>
              <section>
                <h3>Pivot and investigate</h3>
                <p>
                  Click highlighted devices, IPs, services, ports, subnets,
                  manufacturers, and Zeek states to apply dashboard-wide pivot
                  filters. Active pivots remain visible in the floating filter
                  toolbar.
                </p>
              </section>
              <section>
                <h3>Export and share</h3>
                <p>
                  Use Customize to include or hide sections, then share, print,
                  or export the current view. Asset Inventory Export is
                  available from the Devices section.
                </p>
              </section>
            </div>
          </section>
        </div>
      )}
      <ReportCustomization
        open={reportCustomizationOpen}
        visibleSections={visibleReportSections}
        onClose={() => setReportCustomizationOpen(false)}
        onSave={(sections) => {
          setVisibleReportSections(new Set(sections));
          const firstVisible = ALL_REPORT_SECTION_IDS.find((id) =>
            sections.has(id),
          );
          if (firstVisible && !sections.has(activeSection as ReportSectionId))
            setActiveSection(firstVisible);
          setReportCustomizationOpen(false);
        }}
        onExportFull={handleDownloadFullJson}
      />
      <DetectionModuleSelector
        open={detectionModulesOpen && canWriteAnalysis}
        onClose={(changed) => {
          setDetectionModulesOpen(false);
          if (changed) markReportConfigurationChanged("Modules");
        }}
        onOpenDetectionContext={() => {
          setDetectionModulesOpen(false);
          setDetectionConfigOpen(true);
        }}
      />
      <DetectionConfiguration
        open={detectionConfigOpen && canWriteAnalysis}
        onClose={(changed) => {
          setDetectionConfigOpen(false);
          if (changed) markReportConfigurationChanged("Detection Context");
        }}
      />

      {report && reportRefreshInProgress && (
        <div className="report-refresh-backdrop" role="presentation">
          <section
            className="report-refresh-dialog"
            role="status"
            aria-live="polite"
            aria-labelledby="report-refresh-progress-title"
          >
            <header className="report-refresh-header">
              <div>
                <p className="report-refresh-kicker">Updating report</p>
                <h2 id="report-refresh-progress-title">
                  Generating report with the updated configuration
                </h2>
              </div>
            </header>
            <div className="report-refresh-body">
              <p>
                eleVADR is re-running the detectors against the original packet
                capture using the newly saved Context and module selection.
              </p>
              <p>
                The current report remains visible underneath and will be
                replaced automatically when the updated report is ready.
              </p>
              <div className="report-refresh-working" aria-hidden="true">
                <span />
              </div>
            </div>
          </section>
        </div>
      )}

      {report && reportRefreshPromptOpen && !reportRefreshInProgress && (
        <div className="report-refresh-backdrop" role="presentation">
          <section
            className="report-refresh-dialog"
            role="alertdialog"
            aria-modal="true"
            aria-labelledby="report-refresh-title"
            aria-describedby="report-refresh-description"
          >
            <header className="report-refresh-header">
              <div>
                <p className="report-refresh-kicker">Report update required</p>
                <h2 id="report-refresh-title">
                  Reload report with the updated configuration
                </h2>
              </div>
            </header>
            <div className="report-refresh-body">
              <p id="report-refresh-description">
                {reportConfigurationChange || "Detection configuration"} changes
                were saved while this report was open. The findings currently
                displayed were generated with the previous Context and module
                selection.
              </p>
              <p>
                Generate a replacement report to apply the new configuration. If
                this report was created from a PCAP in the current session,
                eleVADR will reuse that PCAP and its retained Zeek evidence
                automatically.
              </p>
              {reportRefreshError && (
                <p className="report-refresh-error" role="alert">
                  {reportRefreshError}
                </p>
              )}
            </div>
            <footer className="report-refresh-actions">
              <button
                type="button"
                onClick={() => setReportRefreshPromptOpen(false)}
              >
                Keep current report
              </button>
              <button
                type="button"
                className="primary"
                onClick={requestUpdatedReport}
              >
                Generate and load updated report
              </button>
            </footer>
          </section>
        </div>
      )}

      {report && notesOpen && (
        <div
          className="section-notes-backdrop"
          role="presentation"
          onMouseDown={(event) => {
            if (event.currentTarget === event.target) setNotesOpen(false);
          }}
        >
          <section
            className="section-notes-dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="section-notes-title"
          >
            <header className="section-notes-header">
              <div>
                <h2 id="section-notes-title">{activeSectionLabel} Notes</h2>
                <p>
                  Notes are attached to this section of report{" "}
                  <strong>{report.report_id || "current report"}</strong>.
                </p>
              </div>
              <button
                type="button"
                className="section-notes-close"
                onClick={() => setNotesOpen(false)}
                aria-label="Close notes"
              >
                ×
              </button>
            </header>
            <div className="section-notes-body">
              <label htmlFor="section-notes-text">Analyst Notes</label>
              <textarea
                id="section-notes-text"
                value={noteDraft}
                onChange={(event) => setNoteDraft(event.target.value)}
                placeholder={`Add notes for ${activeSectionLabel}...`}
                autoFocus
              />
              <p className="section-notes-hint">
                Stored locally in this browser for this report and section.
                Backend note storage is not connected yet.
              </p>
            </div>
            <footer className="section-notes-actions">
              <div>
                {currentSectionHasNotes && (
                  <button
                    type="button"
                    className="section-notes-delete"
                    onClick={deleteSectionNotes}
                  >
                    Delete Notes
                  </button>
                )}
              </div>
              <div className="section-notes-primary-actions">
                <button
                  type="button"
                  className="section-notes-cancel"
                  onClick={() => setNotesOpen(false)}
                >
                  Cancel
                </button>
                <button
                  type="button"
                  className="section-notes-save"
                  onClick={saveSectionNotes}
                >
                  Save Notes
                </button>
              </div>
            </footer>
          </section>
        </div>
      )}
      {report && (
        <EntityDrawer
          report={report}
          entity={selectedEntity}
          filters={filters}
          note={
            selectedEntity
              ? entityNotes[entityNoteKey(selectedEntity)] || ""
              : ""
          }
          overrides={
            selectedEntity
              ? entityOverrides[entityNoteKey(selectedEntity)] || {}
              : {}
          }
          onSaveOverrides={(value) => {
            if (selectedEntity) saveEntityOverrides(selectedEntity, value);
          }}
          onResetOverrides={() => {
            if (selectedEntity) resetEntityOverrides(selectedEntity);
          }}
          onSaveNote={(value) => {
            if (selectedEntity) saveEntityNote(selectedEntity, value);
          }}
          onDeleteNote={() => {
            if (selectedEntity) deleteEntityNote(selectedEntity);
          }}
          onClose={() => setSelectedEntity(null)}
          onFilter={applyFilter}
        />
      )}
      <HelpDrawer
        isOpen={helpOpen}
        onClose={() => setHelpOpen(false)}
        report={report}
        isAnalyzing={isAnalyzing || reportRefreshInProgress}
        onStartTour={() => setTourOpen(true)}
        onOpenContext={() => setDetectionConfigOpen(true)}
        onOpenModules={() => setDetectionModulesOpen(true)}
      />
      {report && (
        <FirstRunTour
          isOpen={tourOpen}
          onClose={() => setTourOpen(false)}
          onGoTo={goToSection}
        />
      )}
    </div>
  );
}

export default App;
