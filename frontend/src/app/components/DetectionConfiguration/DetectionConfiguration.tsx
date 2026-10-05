import React, { ChangeEvent, ReactNode, useEffect, useMemo, useRef, useState } from "react";
import "./DetectionConfiguration.css";
import { MODULE_COUNT } from "./moduleCatalog";
import {
  exportProfile,
  listProfiles,
  loadActiveProfile,
  migrateProfile,
  moduleReadiness,
  normalizeProfile,
  readiness,
  saveProfile,
} from "./profile";
import {
  AssetRecord,
  AuthorizedControlAction,
  CommunicationPair,
  DetectionConfigurationProfile,
  InfrastructureEntry,
  NetworkSegment,
  SegmentPairRule,
  ValidationIssue,
} from "./types";
import {
  assetsFromCsv,
  assetsToCsv,
  captureScopeFromCsv,
  captureScopeToCsv,
  communicationsFromCsv,
  communicationsToCsv,
  controlActionsFromCsv,
  controlActionsToCsv,
  downloadText,
  externalDestinationsFromCsv,
  externalDestinationsToCsv,
  ignoredHostsFromCsv,
  ignoredHostsToCsv,
  infrastructureFromCsv,
  infrastructureToCsv,
  modulePoliciesFromCsv,
  modulePoliciesToCsv,
  segmentPairsFromCsv,
  segmentPairsToCsv,
  segmentsFromCsv,
  segmentsToCsv,
} from "./csv";
import { firstIssueFor, validateProfile } from "./validation";
import { ADVANCED_POLICY_SCHEMAS } from "./advancedPolicySchema";

type TabId =
  | "overview"
  | "captureScope"
  | "segments"
  | "assets"
  | "infrastructure"
  | "communications"
  | "segmentPairs"
  | "controlActions"
  | "ignoredHosts"
  | "externalDestinations"
  | "advanced";

type CsvKind = Exclude<TabId, "overview">;
type ModalState =
  | null
  | { kind: "close" }
  | { kind: "clearScan" }
  | { kind: "completeContext" }
  | { kind: "issues"; title: string; issues: ValidationIssue[]; message?: string };

interface Props { open: boolean; onClose: (changed?: boolean) => void; }

const tabs: { id: TabId; label: string }[] = [
  { id: "captureScope", label: "Capture Scope" },
  { id: "segments", label: "Network Segments" },
  { id: "assets", label: "Assets" },
  { id: "infrastructure", label: "Trusted Infrastructure" },
  { id: "communications", label: "Communications & Exceptions" },
  { id: "controlActions", label: "Control Authorization" },
];

const PAGE_SIZE = 50;
const emptyProvenance = () => ({ source: "user" as const, confidence: "high" as const });
const signature = (profile: DetectionConfigurationProfile) => {
  const { updatedAt: _updatedAt, ...rest } = normalizeProfile(profile);
  return JSON.stringify(rest);
};
const markUser = <T extends { source: string; confidence: string }>(item: T, changes: Partial<T>): T => ({ ...item, ...changes, source: "user", confidence: "high" }) as T;
const nameSlug = (name: string) => name.trim().replace(/[^a-z0-9]+/gi, "-").replace(/^-|-$/g, "").toLowerCase() || "detection-context";
const sortText = (a: unknown, b: unknown) => String(a ?? "").localeCompare(String(b ?? ""), undefined, { numeric: true, sensitivity: "base" });
const splitList = (value: string) => value.split(/[;,]/).map((x) => x.trim()).filter(Boolean);
const parseCodes = (value: string): Array<number | string> => splitList(value).map((x) => /^0x[0-9a-f]+$/i.test(x) ? Number.parseInt(x, 16) : /^-?\d+$/.test(x) ? Number(x) : x);
const PURDUE_LEVELS = ["0", "1", "2", "3", "3.5", "4", "5"] as const;
const purdueSelectValue = (value?: string): string => {
  const raw = String(value ?? "").trim();
  if (!raw) return "";
  const compact = raw.toLowerCase().replace(/purdue/g, "").replace(/level/g, "").replace(/^l\s*/, "").trim();
  const numeric = compact.match(/^(\d+(?:\.\d+)?)$/)?.[1];
  if (!numeric) return raw;
  const n = Number(numeric);
  return PURDUE_LEVELS.includes(String(n) as (typeof PURDUE_LEVELS)[number]) ? String(n) : raw;
};
const purdueOptions = (current?: string, suggested?: string) => {
  const selected = purdueSelectValue(current);
  const known = PURDUE_LEVELS.includes(selected as (typeof PURDUE_LEVELS)[number]);
  return <>
    <option value="">{suggested ? `Unknown (suggested Level ${suggested})` : "Unknown"}</option>
    {!known && selected && <option value={selected}>{selected}</option>}
    {PURDUE_LEVELS.map((level) => <option key={level} value={level}>Level {level}</option>)}
  </>;
};

type ContextBadgeKind = "observed" | "user" | "inferred" | "policy" | "imported" | "default";
const badgeLabel: Record<ContextBadgeKind, string> = { observed: "Observed", user: "User supplied", inferred: "Inferred", policy: "Policy", imported: "Imported", default: "Default" };
const ContextBadge: React.FC<{ kind: ContextBadgeKind; detail?: string }> = ({ kind, detail }) => <span className={`context-provenance-badge context-provenance-${kind}`} title={detail}>{badgeLabel[kind]}</span>;
const provenanceKind = (source: string): ContextBadgeKind => source === "zeek" ? "observed" : source === "user" ? "user" : source === "imported" ? "imported" : "default";
const ProvenanceBadge: React.FC<{ source: string; confidence?: string; reason?: string; observedCount?: number }> = ({ source, confidence, reason, observedCount }) => {
  const detail = [confidence ? `${confidence} confidence` : "", observedCount ? `${observedCount} observation${observedCount === 1 ? "" : "s"}` : "", reason || ""].filter(Boolean).join(" · ");
  return <ContextBadge kind={provenanceKind(source)} detail={detail || undefined}/>;
};
const ContextSourceGuide = () => <div className="context-source-guide" aria-label="Context source guide"><div><strong>How Context affects analysis</strong><span>Observed traffic is evidence, not authorization. Values marked Policy or User supplied can change how detectors interpret that evidence.</span></div><div className="context-source-legend"><ContextBadge kind="observed"/><ContextBadge kind="inferred"/><ContextBadge kind="user"/><ContextBadge kind="policy"/><ContextBadge kind="imported"/></div></div>;
const ContextHelp: React.FC<{ label: string; children: ReactNode }> = ({ label, children }) => <details className="context-inline-help"><summary aria-label={`Help: ${label}`} title={`Help: ${label}`}>?</summary><div className="context-inline-help-panel" role="note"><strong>{label}</strong><p>{children}</p></div></details>;

const Modal: React.FC<{ title: string; description?: string; children: ReactNode; actions: ReactNode; onCancel: () => void }> = ({ title, description, children, actions, onCancel }) => {
  const ref = useRef<HTMLElement | null>(null);
  useEffect(() => {
    const root = ref.current;
    if (!root) return;
    const focusable = () => Array.from(root.querySelectorAll<HTMLElement>('button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])'));
    focusable()[0]?.focus();
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") { e.preventDefault(); onCancel(); }
      if (e.key === "Tab") {
        const list = focusable();
        if (!list.length) return;
        const first = list[0], last = list[list.length - 1];
        if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
        else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
      }
    };
    root.addEventListener("keydown", handler);
    return () => root.removeEventListener("keydown", handler);
  }, [onCancel]);
  return <div className="app-modal-backdrop" role="presentation" onMouseDown={(e) => { if (e.currentTarget === e.target) onCancel(); }}>
    <section ref={ref} className="app-modal" role="alertdialog" aria-modal="true" aria-labelledby="context-modal-title" aria-describedby={description ? "context-modal-description" : undefined}>
      <header className="app-modal-header"><h2 id="context-modal-title">{title}</h2></header>
      <div className="app-modal-body">{description && <p id="context-modal-description">{description}</p>}{children}</div>
      <footer className="app-modal-actions">{actions}</footer>
    </section>
  </div>;
};

const DetectionConfiguration: React.FC<Props> = ({ open, onClose }) => {
  const [profile, setProfile] = useState<DetectionConfigurationProfile>(() => loadActiveProfile());
  const [profiles, setProfiles] = useState(() => listProfiles());
  const [clean, setClean] = useState("");
  const [tab, setTab] = useState<TabId>("captureScope");
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [status, setStatus] = useState("");
  const [suggestionStatus, setSuggestionStatus] = useState("");
  const [saveConfirmation, setSaveConfirmation] = useState("");
  const [savedDuringSession, setSavedDuringSession] = useState(false);
  const [modal, setModal] = useState<ModalState>(null);
  const [completeStep, setCompleteStep] = useState(0);
  const [copySourceId, setCopySourceId] = useState("");
  const [copyCategories, setCopyCategories] = useState({ segments: true, assets: true, infrastructure: true, captureScope: true, communications: false, segmentPairs: false, controlActions: false, ignoredHosts: false, externalDestinations: true });

  const [segmentQuery, setSegmentQuery] = useState("");
  const [segmentSort, setSegmentSort] = useState<"name" | "cidr" | "role" | "purdueLevel" | "vlanId" | "addressing">("cidr");
  const [segmentPage, setSegmentPage] = useState(1);
  const [assetQuery, setAssetQuery] = useState("");
  const [assetSort, setAssetSort] = useState<"ip" | "hostname" | "assetType" | "role">("ip");
  const [assetPage, setAssetPage] = useState(1);
  const [infraQuery, setInfraQuery] = useState("");
  const [infraSort, setInfraSort] = useState<"kind" | "value" | "label" | "observedCount">("kind");
  const [infraPage, setInfraPage] = useState(1);
  const [pairQuery, setPairQuery] = useState("");
  const [pairSort, setPairSort] = useState<"sourceIp" | "destinationIp" | "protocol" | "destinationPort" | "observedCount">("sourceIp");
  const [pairPage, setPairPage] = useState(1);
  const [segmentPairQuery, setSegmentPairQuery] = useState("");
  const [segmentPairSort, setSegmentPairSort] = useState<"sourceSegment" | "destinationSegment">("sourceSegment");
  const [segmentPairPage, setSegmentPairPage] = useState(1);
  const [controlQuery, setControlQuery] = useState("");
  const [controlSort, setControlSort] = useState<"protocol" | "source" | "destination">("protocol");
  const [controlPage, setControlPage] = useState(1);
  const [ignoredHostQuery, setIgnoredHostQuery] = useState("");
  const [ignoredHostSort, setIgnoredHostSort] = useState<"asc" | "desc">("asc");
  const [ignoredHostPage, setIgnoredHostPage] = useState(1);
  const [externalQuery, setExternalQuery] = useState("");
  const [externalSort, setExternalSort] = useState<"asc" | "desc">("asc");
  const [externalPage, setExternalPage] = useState(1);
  const [moduleQuery, setModuleQuery] = useState("");
  const [moduleSort, setModuleSort] = useState<"label" | "level">("label");
  const [advancedModule, setAdvancedModule] = useState(ADVANCED_POLICY_SCHEMAS[0]?.moduleId || "");

  const jsonInput = useRef<HTMLInputElement | null>(null);
  const csvInput = useRef<HTMLInputElement | null>(null);
  const [csvKind, setCsvKind] = useState<CsvKind | null>(null);

  useEffect(() => {
    if (!open) return;
    const active = loadActiveProfile();
    setProfiles(listProfiles());
    setProfile(active);
    setClean(signature(active));
    setModal(null);
    setStatus("");
    setSavedDuringSession(false);
  }, [open]);

  const dirty = clean !== "" && signature(profile) !== clean;
  const issues = useMemo(() => validateProfile(profile), [profile]);
  const errors = issues.filter((x) => x.severity === "error");
  const readinessItems = useMemo(() => readiness(profile), [profile]);
  const moduleItems = useMemo(() => moduleReadiness(profile), [profile]);
  const moduleCanRun = moduleItems.filter((x) => x.canRun).length;
  const moduleContextComplete = moduleItems.filter((x) => x.contextComplete).length;
  const activeCount = profile.segments.length + profile.assets.length + profile.infrastructure.length + profile.communicationPairs.length + profile.allowedHosts.length + profile.allowedSegmentPairs.length + profile.approvedExternalDestinations.length + profile.authorizedControlActions.length;
  const tabCounts: Partial<Record<TabId, number>> = {
    segments: profile.segments.length,
    assets: profile.assets.length,
    infrastructure: profile.infrastructure.length,
    communications: profile.communicationPairs.length + profile.allowedSegmentPairs.length + profile.allowedHosts.length + profile.approvedExternalDestinations.length,
    segmentPairs: profile.allowedSegmentPairs.length,
    controlActions: profile.authorizedControlActions.length,
    ignoredHosts: profile.allowedHosts.length,
    externalDestinations: profile.approvedExternalDestinations.length,
    advanced: Object.keys(profile.modulePolicies).length,
  };

  const missingReadiness = readinessItems.filter((x) => x.level === "warning");
  const completionPercent = Math.round(((readinessItems.length - missingReadiness.length) / Math.max(1, readinessItems.length)) * 100);

  const ipv4ToNumber = (value: string): number | null => {
    const parts = value.split(".").map(Number);
    if (parts.length !== 4 || parts.some((x) => !Number.isInteger(x) || x < 0 || x > 255)) return null;
    return (((parts[0] * 256 + parts[1]) * 256 + parts[2]) * 256 + parts[3]) >>> 0;
  };
  const ipInCidr = (ip: string, cidr: string): boolean => {
    const [networkText, prefixText] = cidr.split("/");
    const value = ipv4ToNumber(ip);
    const network = ipv4ToNumber(networkText);
    const prefix = Number(prefixText);
    if (value === null || network === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) return false;
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    return (value & mask) === (network & mask);
  };
  const segmentSuggestion = (segment: NetworkSegment): { likelyOt: boolean; purdue: string; reason: string } => {
    const relatedAssets = profile.assets.filter((asset) => ipInCidr(asset.ip, segment.cidr));
    const assetEvidence = relatedAssets.map((asset) => [asset.assetType, asset.role, ...(asset.services || [])].join(" ")).join(" ").toLowerCase();
    const relatedPairs = profile.communicationPairs.filter((pair) => ipInCidr(pair.sourceIp, segment.cidr) || ipInCidr(pair.destinationIp, segment.cidr));
    const pairEvidence = relatedPairs.map((pair) => `${pair.service || ""} ${pair.protocol || ""} ${pair.destinationPort ?? ""}`).join(" ").toLowerCase();
    const evidence = `${assetEvidence} ${pairEvidence}`;

    const controlEvidence = /s7|s7comm|modbus|dnp3|bacnet|enip|ethernet\/?ip|\bcip\b|codesys|fox|niagara|iccp|tase/.test(evidence) || /(?:^|\s)(?:102|502|1911|2222|44818|47808|20000)(?:\s|$)/.test(evidence);
    const otAssetEvidence = /\bplc\b|controller|hmi|rtu|ied|engineering workstation|historian|scada/.test(assetEvidence);
    const likelyOt = segment.role === "ot" || segment.suggestedRole === "ot" || /ot candidate/i.test(segment.name) || controlEvidence || otAssetEvidence;

    let purdue = segment.suggestedPurdueLevel || "";
    if (likelyOt && !purdue) {
      if (controlEvidence || /\bplc\b|controller|rtu|ied|hmi/.test(assetEvidence)) purdue = "2";
      else if (/historian|scada|engineering workstation|sql|smb|http|https/.test(assetEvidence)) purdue = "3";
      else purdue = "2";
    }

    const reason = controlEvidence ? "industrial protocol evidence" : otAssetEvidence ? "OT asset evidence" : segment.role === "ot" ? "existing OT role" : /ot candidate/i.test(segment.name) ? "scanner OT candidate" : "";
    return { likelyOt, purdue, reason };
  };
  const suggestedPurdue = (segment: NetworkSegment): string => segment.purdueLevel || segment.suggestedPurdueLevel || segmentSuggestion(segment).purdue;
  const segmentObservedFacts = (segment: NetworkSegment): string[] => {
    const facts: string[] = [];
    if (segment.observedOtProtocols?.length) facts.push(`OT: ${segment.observedOtProtocols.join(", ")}`);
    if (segment.observedVlanIds?.length) facts.push(`VLAN ${segment.observedVlanIds.join(", ")}`);
    else if (segment.vlanId !== undefined && segment.source === "zeek") facts.push(`VLAN ${segment.vlanId}`);
    if (segment.observedDhcp) facts.push("DHCP observed");
    return facts;
  };
  const observedControlCandidates = useMemo(() => {
    const seen = new Set<string>();
    return profile.communicationPairs.flatMap((pair) => {
      const token = `${pair.service || ""} ${pair.destinationPort ?? ""}`.toLowerCase();
      const protocol = /modbus|\b502\b/.test(token) ? "modbus" : /dnp3|20000/.test(token) ? "dnp3" : /s7|\b102\b/.test(token) ? "s7comm" : /enip|cip|44818|2222/.test(token) ? "enip" : "";
      if (!protocol) return [];
      const key = `${protocol}|${pair.sourceIp}|${pair.destinationIp}`;
      if (seen.has(key)) return [];
      seen.add(key);
      return [{ protocol: protocol as AuthorizedControlAction["protocol"], source: pair.sourceIp, destination: pair.destinationIp, service: pair.service || "", count: pair.observedCount || 0 }];
    }).sort((a,b) => b.count - a.count).slice(0, 100);
  }, [profile.communicationPairs]);

  const patch = (changes: Partial<DetectionConfigurationProfile>) => setProfile((current) => ({ ...current, ...changes, updatedAt: new Date().toISOString() }));
  const updateSegment = (id: string, changes: Partial<NetworkSegment>) => patch({ segments: profile.segments.map((x) => x.id === id ? markUser(x, changes) : x) });
  const updateAsset = (id: string, changes: Partial<AssetRecord>) => patch({ assets: profile.assets.map((x) => x.id === id ? markUser(x, changes) : x) });
  const updateInfra = (id: string, changes: Partial<InfrastructureEntry>) => patch({ infrastructure: profile.infrastructure.map((x) => x.id === id ? markUser(x, changes) : x) });
  const updatePair = (id: string, changes: Partial<CommunicationPair>) => patch({ communicationPairs: profile.communicationPairs.map((x) => x.id === id ? markUser(x, changes) : x) });
  const updateSegmentPair = (id: string, changes: Partial<SegmentPairRule>) => patch({ allowedSegmentPairs: profile.allowedSegmentPairs.map((x) => x.id === id ? { ...x, ...changes } : x) });
  const updateControl = (id: string, changes: Partial<AuthorizedControlAction>) => patch({ authorizedControlActions: profile.authorizedControlActions.map((x) => x.id === id ? { ...x, ...changes } : x) });

  const openCompleteContext = () => { setCompleteStep(0); setCopySourceId(""); setSuggestionStatus(""); setModal({ kind: "completeContext" }); };
  const applyNetworkSuggestions = () => {
    let updated = 0;
    const segments = profile.segments.map((segment) => {
      const suggestion = segmentSuggestion(segment);
      if (!suggestion.likelyOt) return segment;
      const changes: Partial<NetworkSegment> = {};
      if (segment.role === "unknown") changes.role = "ot";
      if (!segment.purdueLevel && suggestion.purdue) changes.purdueLevel = suggestion.purdue;
      if (!Object.keys(changes).length) return segment;
      updated += 1;
      return markUser(segment, changes);
    });
    patch({ segments });
    const message = updated
      ? `Applied OT/Purdue suggestions to ${updated} network segment${updated === 1 ? "" : "s"}. Review the suggested classifications before saving.`
      : "No additional OT/Purdue suggestions are available from the evidence currently stored in this profile.";
    setSuggestionStatus(message);
    setStatus(message);
  };
  const addControlCandidate = (candidate: { protocol: AuthorizedControlAction["protocol"]; source: string; destination: string }) => {
    const exists = profile.authorizedControlActions.some((x) => x.protocol === candidate.protocol && x.source === candidate.source && x.destination === candidate.destination);
    if (exists) return;
    patch({ authorizedControlActions: [...profile.authorizedControlActions, { id: crypto.randomUUID(), protocol: candidate.protocol, source: candidate.source, destination: candidate.destination, allowedOperations: [], allowedFunctionCodes: [], description: "Created from Zeek-observed control communication; review and specify authorized operations/function codes." }] });
  };
  const copyFromProfile = () => {
    const src = profiles.find((x) => x.id === copySourceId);
    if (!src) return;
    const uniq = <T,>(a: T[], b: T[], key: (x:T)=>string) => { const m = new Map<string,T>(); [...a,...b].forEach((x)=>m.set(key(x).toLowerCase(), x)); return [...m.values()]; };
    const changes: Partial<DetectionConfigurationProfile> = {};
    if (copyCategories.segments) changes.segments = uniq(profile.segments, src.segments, (x)=>x.cidr);
    if (copyCategories.assets) changes.assets = uniq(profile.assets, src.assets, (x)=>x.ip);
    if (copyCategories.infrastructure) changes.infrastructure = uniq(profile.infrastructure, src.infrastructure, (x)=>`${x.kind}|${x.value}`);
    if (copyCategories.captureScope) changes.captureScope = { ...src.captureScope };
    if (copyCategories.communications) changes.communicationPairs = uniq(profile.communicationPairs, src.communicationPairs, (x)=>`${x.sourceIp}|${x.destinationIp}|${x.protocol||""}|${x.destinationPort||""}`);
    if (copyCategories.segmentPairs) changes.allowedSegmentPairs = uniq(profile.allowedSegmentPairs, src.allowedSegmentPairs, (x)=>`${x.sourceSegment}|${x.destinationSegment}`);
    if (copyCategories.controlActions) changes.authorizedControlActions = uniq(profile.authorizedControlActions, src.authorizedControlActions, (x)=>`${x.protocol}|${x.source}|${x.destination}|${x.allowedOperations.join(",")}|${x.allowedFunctionCodes.join(",")}`);
    if (copyCategories.ignoredHosts) changes.allowedHosts = [...new Set([...profile.allowedHosts, ...src.allowedHosts])];
    if (copyCategories.externalDestinations) changes.approvedExternalDestinations = [...new Set([...profile.approvedExternalDestinations, ...src.approvedExternalDestinations])];
    patch(changes);
    setStatus(`Copied selected context from ${src.name}.`);
  };

  const requestClose = () => { if (dirty) setModal({ kind: "close" }); else onClose(savedDuringSession); };
  useEffect(() => {
    if (!open) return;
    const handler = (e: KeyboardEvent) => { if (e.key === "Escape" && !modal) { e.preventDefault(); requestClose(); } };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [open, modal, dirty]);

  const handleSave = () => {
    const current = validateProfile(profile);
    const errs = current.filter((x) => x.severity === "error");
    if (errs.length) {
      setModal({ kind: "issues", title: "Fix Profile Errors Before Saving", issues: current, message: "The profile was not saved because one or more fields are invalid or duplicated." });
      return;
    }
    const changedFromClean = signature(profile) !== clean;
    const saved = saveProfile(profile);
    if (changedFromClean) setSavedDuringSession(true);
    setProfile(saved);
    setProfiles(listProfiles());
    setClean(signature(saved));
    setSaveConfirmation("Profile saved locally.");
    window.setTimeout(() => setSaveConfirmation(""), 1800);
  };

  const handleJson = async (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    try {
      const parsed = JSON.parse(await file.text());
      const result = migrateProfile(parsed);
      if (!result.profile) {
        setModal({ kind: "issues", title: "Profile Import Failed", issues: result.issues, message: `${file.name} could not be loaded.` });
        return;
      }
      const errs = result.issues.filter((x) => x.severity === "error");
      if (errs.length) {
        setModal({ kind: "issues", title: "Profile Import Has Errors", issues: result.issues, message: "Correct the profile file before importing it." });
        return;
      }
      const imported = { ...result.profile, id: crypto.randomUUID(), updatedAt: new Date().toISOString() };
      setProfile(imported);
      setClean("__unsaved_import__");
      setStatus(`Loaded ${file.name}${result.migrated ? " and migrated it to schema v3" : ""}. Save to keep it in this browser.`);
      if (result.issues.some((x) => x.severity === "warning")) setModal({ kind: "issues", title: "Profile Imported With Migration Notes", issues: result.issues.filter((x) => x.severity === "warning"), message: "The profile was loaded successfully." });
    } catch (err) {
      setModal({ kind: "issues", title: "Profile Import Failed", issues: [{ path: "json", message: err instanceof Error ? err.message : "Invalid JSON file.", severity: "error" }], message: `${file.name} could not be loaded.` });
    }
  };

  const handleCsv = async (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = "";
    const kind = csvKind;
    setCsvKind(null);
    if (!file || !kind) return;
    try {
      const text = await file.text();
      let added = 0;
      if (kind === "captureScope") { patch({ captureScope: captureScopeFromCsv(text) }); added = 1; }
      if (kind === "assets") {
        const incoming = assetsFromCsv(text), existing = new Set(profile.assets.map((x) => x.ip.trim().toLowerCase()));
        const fresh = incoming.filter((x) => x.ip && !existing.has(x.ip.trim().toLowerCase())); added = fresh.length; patch({ assets: [...profile.assets, ...fresh] });
      }
      if (kind === "segments") {
        const incoming = segmentsFromCsv(text), existing = new Set(profile.segments.map((x) => x.cidr.trim().toLowerCase()));
        const fresh = incoming.filter((x) => x.cidr && !existing.has(x.cidr.trim().toLowerCase())); added = fresh.length; patch({ segments: [...profile.segments, ...fresh] });
      }
      if (kind === "infrastructure") {
        const incoming = infrastructureFromCsv(text), key = (x: InfrastructureEntry) => `${x.kind}|${x.value}`.trim().toLowerCase(), existing = new Set(profile.infrastructure.map(key));
        const fresh = incoming.filter((x) => x.value && !existing.has(key(x))); added = fresh.length; patch({ infrastructure: [...profile.infrastructure, ...fresh] });
      }
      if (kind === "communications") {
        const incoming = communicationsFromCsv(text), key = (x: CommunicationPair) => `${x.sourceIp}|${x.destinationIp}|${x.protocol || ""}|${x.destinationPort ?? ""}|${x.service || ""}`.toLowerCase(), existing = new Set(profile.communicationPairs.map(key));
        const fresh = incoming.filter((x) => x.sourceIp && x.destinationIp && !existing.has(key(x))); added = fresh.length; patch({ communicationPairs: [...profile.communicationPairs, ...fresh] });
      }
      if (kind === "segmentPairs") {
        const incoming = segmentPairsFromCsv(text), key = (x: SegmentPairRule) => `${x.sourceSegment}|${x.destinationSegment}`.toLowerCase(), existing = new Set(profile.allowedSegmentPairs.map(key));
        const fresh = incoming.filter((x) => x.sourceSegment && x.destinationSegment && !existing.has(key(x))); added = fresh.length; patch({ allowedSegmentPairs: [...profile.allowedSegmentPairs, ...fresh] });
      }
      if (kind === "controlActions") {
        const incoming = controlActionsFromCsv(text), key = (x: AuthorizedControlAction) => `${x.protocol}|${x.source}|${x.destination}|${x.allowedOperations.join(";")}|${x.allowedFunctionCodes.join(";")}`.toLowerCase(), existing = new Set(profile.authorizedControlActions.map(key));
        const fresh = incoming.filter((x) => x.source && x.destination && !existing.has(key(x))); added = fresh.length; patch({ authorizedControlActions: [...profile.authorizedControlActions, ...fresh] });
      }
      if (kind === "ignoredHosts") {
        const incoming = ignoredHostsFromCsv(text), existing = new Set(profile.allowedHosts.map((x) => x.trim().toLowerCase()));
        const fresh = incoming.filter((x) => !existing.has(x.toLowerCase())); added = fresh.length; patch({ allowedHosts: [...profile.allowedHosts, ...fresh] });
      }
      if (kind === "externalDestinations") {
        const incoming = externalDestinationsFromCsv(text), existing = new Set(profile.approvedExternalDestinations.map((x) => x.trim().toLowerCase()));
        const fresh = incoming.filter((x) => !existing.has(x.toLowerCase())); added = fresh.length; patch({ approvedExternalDestinations: [...profile.approvedExternalDestinations, ...fresh] });
      }
      if (kind === "advanced") {
        const incoming = modulePoliciesFromCsv(text); added = Object.keys(incoming).length; patch({ modulePolicies: { ...profile.modulePolicies, ...incoming } });
      }
      setStatus(`Imported ${file.name}: ${added} new or updated entr${added === 1 ? "y" : "ies"}. Duplicate keys were skipped.`);
    } catch (err) {
      setModal({ kind: "issues", title: "CSV Import Failed", issues: [{ path: "csv", message: err instanceof Error ? err.message : "CSV could not be parsed.", severity: "error" }] });
    }
  };

  const openCsv = (kind: CsvKind) => { setCsvKind(kind); setTimeout(() => csvInput.current?.click(), 0); };
  const clearScanned = () => {
    setProfile({ ...profile, segments: profile.segments.filter((x) => x.source !== "zeek"), assets: profile.assets.filter((x) => x.source !== "zeek"), infrastructure: profile.infrastructure.filter((x) => x.source !== "zeek"), communicationPairs: profile.communicationPairs.filter((x) => x.source !== "zeek"), scan: { filesScanned: 0, recordsParsed: 0, logTypes: {}, warnings: [] }, updatedAt: new Date().toISOString() });
    setScanStatus("Scanner-derived entries cleared. User-edited entries were kept.");
    setModal(null);
  };

  const segmentRows = useMemo(() => { const q = segmentQuery.trim().toLowerCase(); return [...profile.segments].filter((x) => !q || `${x.name} ${x.cidr} ${x.role} ${x.purdueLevel || ""} ${x.vlanId ?? ""} ${x.addressing}`.toLowerCase().includes(q)).sort((a, b) => sortText(a[segmentSort], b[segmentSort])); }, [profile.segments, segmentQuery, segmentSort]);
  const assetRows = useMemo(() => { const q = assetQuery.trim().toLowerCase(); return [...profile.assets].filter((x) => !q || `${x.ip} ${x.hostname || ""} ${x.macAddresses.join(" ")} ${x.assetType} ${x.role} ${x.services.join(" ")} ${x.ports.join(" ")}`.toLowerCase().includes(q)).sort((a, b) => sortText(a[assetSort], b[assetSort])); }, [profile.assets, assetQuery, assetSort]);
  const infraRows = useMemo(() => { const q = infraQuery.trim().toLowerCase(); return [...profile.infrastructure].filter((x) => !q || `${x.kind} ${x.value} ${x.label || ""} ${x.source} ${x.confidence} ${x.observedCount ?? ""}`.toLowerCase().includes(q)).sort((a, b) => sortText(a[infraSort], b[infraSort])); }, [profile.infrastructure, infraQuery, infraSort]);
  const pairRows = useMemo(() => { const q = pairQuery.trim().toLowerCase(); return [...profile.communicationPairs].filter((x) => !q || `${x.sourceIp} ${x.destinationIp} ${x.protocol || ""} ${x.destinationPort ?? ""} ${x.service || ""}`.toLowerCase().includes(q)).sort((a, b) => sortText(a[pairSort], b[pairSort])); }, [profile.communicationPairs, pairQuery, pairSort]);
  const segmentPairRows = useMemo(() => { const q = segmentPairQuery.trim().toLowerCase(); return [...profile.allowedSegmentPairs].filter((x) => !q || `${x.sourceSegment} ${x.destinationSegment} ${x.description || ""}`.toLowerCase().includes(q)).sort((a, b) => sortText(a[segmentPairSort], b[segmentPairSort])); }, [profile.allowedSegmentPairs, segmentPairQuery, segmentPairSort]);
  const controlRows = useMemo(() => { const q = controlQuery.trim().toLowerCase(); return [...profile.authorizedControlActions].filter((x) => !q || `${x.protocol} ${x.source} ${x.destination} ${x.allowedOperations.join(" ")} ${x.allowedFunctionCodes.join(" ")} ${x.description || ""}`.toLowerCase().includes(q)).sort((a, b) => sortText(a[controlSort], b[controlSort])); }, [profile.authorizedControlActions, controlQuery, controlSort]);
  const ignoredHostRows = useMemo(() => { const q = ignoredHostQuery.trim().toLowerCase(); const rows = profile.allowedHosts.map((value, index) => ({ value, index })).filter((x) => !q || x.value.toLowerCase().includes(q)); rows.sort((a, b) => (ignoredHostSort === "asc" ? 1 : -1) * sortText(a.value, b.value)); return rows; }, [profile.allowedHosts, ignoredHostQuery, ignoredHostSort]);
  const externalRows = useMemo(() => { const q = externalQuery.trim().toLowerCase(); const rows = profile.approvedExternalDestinations.map((value, index) => ({ value, index })).filter((x) => !q || x.value.toLowerCase().includes(q)); rows.sort((a, b) => (externalSort === "asc" ? 1 : -1) * sortText(a.value, b.value)); return rows; }, [profile.approvedExternalDestinations, externalQuery, externalSort]);
  const moduleRows = useMemo(() => { const q = moduleQuery.trim().toLowerCase(); const rows = moduleItems.filter((x) => !q || `${x.label} ${x.id} ${x.detail} ${x.level}`.toLowerCase().includes(q)); return rows.sort((a, b) => moduleSort === "level" ? (sortText(a.level, b.level) || sortText(a.label, b.label)) : sortText(a.label, b.label)); }, [moduleItems, moduleQuery, moduleSort]);

  useEffect(() => setSegmentPage(1), [segmentQuery, segmentSort]);
  useEffect(() => setAssetPage(1), [assetQuery, assetSort]);
  useEffect(() => setInfraPage(1), [infraQuery, infraSort]);
  useEffect(() => setPairPage(1), [pairQuery, pairSort]);
  useEffect(() => setSegmentPairPage(1), [segmentPairQuery, segmentPairSort]);
  useEffect(() => setControlPage(1), [controlQuery, controlSort]);
  useEffect(() => setIgnoredHostPage(1), [ignoredHostQuery, ignoredHostSort]);
  useEffect(() => setExternalPage(1), [externalQuery, externalSort]);

  if (!open) return null;

  const pageSlice = <T,>(rows: T[], page: number) => rows.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);
  const inputClass = (path: string) => firstIssueFor(issues, path) ? "invalid-field" : "";
  const fieldError = (path: string) => { const message = firstIssueFor(issues, path); return message ? <span className="field-error">{message}</span> : null; };
  const tableTools = (kind: CsvKind, exporter: () => void, extra?: ReactNode) => <div className="table-tools">{extra}<span className="table-tools-spacer"/><button type="button" onClick={() => openCsv(kind)}>Import CSV</button><button type="button" onClick={exporter}>Export CSV</button></div>;
  const pager = (page: number, setPage: (n: number) => void, total: number) => <div className="table-pager"><span>{total.toLocaleString()} matching entr{total === 1 ? "y" : "ies"}</span><button type="button" disabled={page <= 1} onClick={() => setPage(page - 1)}>Previous</button><span>Page {page} of {Math.max(1, Math.ceil(total / PAGE_SIZE))}</span><button type="button" disabled={page >= Math.ceil(total / PAGE_SIZE)} onClick={() => setPage(page + 1)}>Next</button></div>;

  const selectedAdvancedSchema = ADVANCED_POLICY_SCHEMAS.find((x) => x.moduleId === advancedModule);
  const setAdvancedField = (moduleId: string, key: string, value: unknown, unset = false) => {
    const current = { ...(profile.modulePolicies[moduleId] || {}) };
    if (unset) delete current[key]; else current[key] = value;
    const next = { ...profile.modulePolicies };
    if (Object.keys(current).length) next[moduleId] = current; else delete next[moduleId];
    patch({ modulePolicies: next });
  };

  return <div className="detection-config-backdrop" role="presentation" onMouseDown={(e) => { if (e.currentTarget === e.target) requestClose(); }}>
    <section className="detection-config-dialog" role="dialog" aria-modal="true" aria-labelledby="detection-config-title">
      <header className="detection-config-header"><div><p className="detection-config-kicker">Analysis setup</p><h1 id="detection-config-title">Context</h1><p>Define the site context and policy assumptions that should be applied when a PCAP is analyzed.</p></div><button type="button" className="detection-config-close" onClick={requestClose} aria-label="Close context">×</button></header>
      <div className="detection-config-toolbar">
        <label className="profile-name-field"><span>Profile Name {dirty && <em className="dirty-indicator">• Unsaved changes</em>}</span><input className={inputClass("name")} value={profile.name} onChange={(e) => patch({ name: e.target.value })}/>{fieldError("name")}</label>
        <span className="profile-toolbar-spacer" aria-hidden="true"/>
        <button type="button" onClick={() => jsonInput.current?.click()}>Load Profile</button>
        <button type="button" onClick={() => exportProfile(profile)}>Export Profile</button>
        <button type="button" className="primary" onClick={openCompleteContext}>Complete Context{missingReadiness.length ? ` (${missingReadiness.length})` : ""}</button>
        <input ref={jsonInput} className="visually-hidden-file" type="file" accept=".json,application/json" onChange={handleJson}/>
        <input ref={csvInput} className="visually-hidden-file" type="file" accept=".csv,text/csv" onChange={handleCsv}/>
        {status && <div className="scan-toolbar-summary secondary-status" role="status">{status}</div>}
      </div>

      <div className={`context-status-banner ${errors.length ? "error" : missingReadiness.length ? "warning" : "ready"}`}>
        <div className="context-status-main"><strong>{errors.length ? "Context needs correction" : missingReadiness.length ? `${missingReadiness.length} recommended context item${missingReadiness.length === 1 ? "" : "s"} incomplete` : "Ready for analysis"}</strong><span>{completionPercent}% context complete · {profile.assets.length} assets · {profile.segments.length} segments · {profile.infrastructure.length} trusted infrastructure entries · {profile.authorizedControlActions.length} control authorizations</span></div>
        <div className="context-status-side"><span>Schema v{profile.schemaVersion}</span>{dirty && <span className="context-unsaved">Unsaved changes</span>}</div>
      </div>

      <div className="detection-config-layout">
        <nav className="detection-config-tabs" aria-label="Detection context sections">
          {tabs.map((item) => {
            const cls = tab === item.id ? "active" : "";
            const count = tabCounts[item.id];
            return <button key={item.id} type="button" className={cls} onClick={() => setTab(item.id)}><span className="tab-label">{item.label}</span>{count !== undefined && <span className="tab-count">{count.toLocaleString()}</span>}</button>;
          })}
          <div className="advanced-nav-divider"/>
          <button type="button" className={tab === "advanced" ? "active advanced-nav-button" : "advanced-nav-button"} onClick={() => { setShowAdvanced(true); setTab("advanced"); }}><span className="tab-label">Advanced</span>{Object.keys(profile.modulePolicies).length > 0 && <span className="tab-count">{Object.keys(profile.modulePolicies).length}</span>}</button>
        </nav>

        <main className="detection-config-content">
          <ContextSourceGuide/>
          {tab === "captureScope" && <>
            <div className="config-section-heading"><div><div className="context-heading-row"><h2>Capture Scope</h2><ContextHelp label="Capture Scope">Use these switches only for facts you know about the monitored sensor and site. They can enable stronger detector conclusions that packet evidence alone cannot establish.</ContextHelp><ContextBadge kind="policy" detail="These answers are site policy supplied by the analyst and can change detector behavior."/></div><p>Explicitly describe assumptions that packet logs cannot prove. Enable an assumption only when it is true for the monitored scope.</p><p className="context-guidance-note"><strong>Detector impact:</strong> these settings authorize stronger interpretations such as public-to-public or IPv6-in-OT findings; leaving them unknown is safer than guessing.</p></div></div>
            <div className="scope-option-list">
              <label><input type="checkbox" checked={profile.captureScope.internalIcsOnlyExpected} onChange={(e) => patch({ captureScope: { ...profile.captureScope, internalIcsOnlyExpected: e.target.checked } })}/><span><strong>Internal ICS/OT traffic only expected</strong><small>Required before Public-to-Public Traffic can treat public-to-public flows as anomalous.</small></span></label>
              <label><input type="checkbox" checked={profile.captureScope.dedicatedOtSensor} onChange={(e) => patch({ captureScope: { ...profile.captureScope, dedicatedOtSensor: e.target.checked } })}/><span><strong>Dedicated OT/ICS sensor</strong><small>The capture point is intended to monitor only the OT/ICS environment.</small></span></label>
              <label><input type="checkbox" checked={profile.captureScope.ipv4OnlyExpected} onChange={(e) => patch({ captureScope: { ...profile.captureScope, ipv4OnlyExpected: e.target.checked } })}/><span><strong>IPv4-only OT scope expected</strong><small>Enables IPv6-in-OT policy evaluation for the monitored scope. Segment-level IPv4-only settings can also be used.</small></span></label>
            </div>
          </>}

          {tab === "segments" && <>
            <div className="config-section-heading"><div><div className="context-heading-row"><h2>Network Segments</h2><ContextHelp label="Network Segments">Role, Purdue level, addressing, VLAN, DHCP, and IPv6 settings establish site topology and expectations. Zeek-derived suggestions are starting points; edited values become authoritative analyst context.</ContextHelp><ContextBadge kind="inferred" detail="Suggested role, Purdue, and addressing values are derived from observed traffic and require analyst review."/></div><p>Observed Zeek facts are shown separately from site-policy fields. Review inferred roles, Purdue levels, VLANs, and addressing as needed.</p><p className="context-guidance-note"><strong>Use with care:</strong> accepting or editing a row marks it User supplied and makes that classification authoritative for policy evaluation.</p></div><button type="button" onClick={() => patch({ segments: [...profile.segments, { id: crypto.randomUUID(), name: "New segment", cidr: "", role: "unknown", purdueLevel: "", addressing: "unknown", ...emptyProvenance() }] })}>Add segment</button></div>
            {tableTools("segments", () => downloadText(`${nameSlug(profile.name)}-segments.csv`, segmentsToCsv(profile.segments)), <><input aria-label="Search network segments" placeholder="Search segments…" value={segmentQuery} onChange={(e) => setSegmentQuery(e.target.value)}/><select aria-label="Sort network segments" value={segmentSort} onChange={(e) => setSegmentSort(e.target.value as typeof segmentSort)}><option value="cidr">Sort: CIDR</option><option value="name">Sort: Name</option><option value="role">Sort: Role</option><option value="purdueLevel">Sort: Purdue</option><option value="vlanId">Sort: VLAN</option><option value="addressing">Sort: Addressing</option></select></>)}
            <div className="config-table-wrap"><table className="config-table"><thead><tr><th>Name</th><th>CIDR</th><th>Source</th><th>Observed</th><th>Role</th><th>Purdue</th><th>VLAN</th><th>Addressing</th><th>DHCP Policy</th><th>IPv6 Policy</th><th/></tr></thead><tbody>{pageSlice(segmentRows, segmentPage).map((x) => <tr key={x.id}><td><input className={inputClass(`segments.${x.id}.name`)} value={x.name} onChange={(e) => updateSegment(x.id, { name: e.target.value })}/>{fieldError(`segments.${x.id}.name`)}</td><td><input className={inputClass(`segments.${x.id}.cidr`)} value={x.cidr} onChange={(e) => updateSegment(x.id, { cidr: e.target.value })}/>{fieldError(`segments.${x.id}.cidr`)}</td><td><ProvenanceBadge source={x.source} confidence={x.confidence} reason={x.reason} observedCount={x.observedCount}/></td><td><div className="segment-observed">{segmentObservedFacts(x).length ? segmentObservedFacts(x).map((fact)=><span key={fact}>{fact}</span>) : <em>No segment-specific facts</em>}</div></td><td><select value={x.role} onChange={(e) => updateSegment(x.id, { role: e.target.value as NetworkSegment["role"] })}><option value="unknown">{x.suggestedRole === "ot" ? "Unknown (suggested OT)" : "Unknown"}</option><option value="ot">OT</option><option value="it">IT</option><option value="dmz">DMZ</option></select></td><td><select value={purdueSelectValue(x.purdueLevel)} onChange={(e) => updateSegment(x.id, { purdueLevel: e.target.value })}>{purdueOptions(x.purdueLevel, x.suggestedPurdueLevel)}</select></td><td><input className={inputClass(`segments.${x.id}.vlanId`)} type="number" value={x.vlanId ?? ""} onChange={(e) => updateSegment(x.id, { vlanId: e.target.value ? Number(e.target.value) : undefined })}/>{fieldError(`segments.${x.id}.vlanId`)}</td><td><select value={x.addressing} onChange={(e) => updateSegment(x.id, { addressing: e.target.value as NetworkSegment["addressing"] })}><option value="unknown">{x.suggestedAddressing === "dhcp" ? "Unknown (DHCP observed)" : "Unknown"}</option><option value="static">Static</option><option value="dhcp">DHCP</option><option value="mixed">Mixed</option></select></td><td><select value={x.dhcpAllowed === undefined ? "" : String(x.dhcpAllowed)} onChange={(e) => updateSegment(x.id, { dhcpAllowed: e.target.value === "" ? undefined : e.target.value === "true" })}><option value="">Unknown</option><option value="true">Allowed</option><option value="false">Prohibited</option></select></td><td><select value={x.ipv6Allowed === undefined ? "" : String(x.ipv6Allowed)} onChange={(e) => updateSegment(x.id, { ipv6Allowed: e.target.value === "" ? undefined : e.target.value === "true" })}><option value="">Unknown</option><option value="true">Allowed</option><option value="false">IPv4 only</option></select></td><td><button className="danger-link" type="button" onClick={() => patch({ segments: profile.segments.filter((y) => y.id !== x.id) })}>Remove</button></td></tr>)}</tbody></table></div>{pager(segmentPage, setSegmentPage, segmentRows.length)}
          </>}

          {tab === "assets" && <>
            <div className="config-section-heading"><div><div className="context-heading-row"><h2>Asset Inventory</h2><ContextHelp label="Asset Inventory">Assets discovered in traffic are observations until you edit or import authoritative identity information. Confirm IP/MAC identity carefully because several detectors use it to distinguish expected devices from identity changes.</ContextHelp><ContextBadge kind="observed" detail="Scanner-added assets originate from Zeek evidence until you edit them."/></div><p>Scanner-added hosts can be edited or removed. DHCP/ARP MAC evidence is populated when present.</p><p className="context-guidance-note"><strong>Identity impact:</strong> an edited IP/MAC mapping becomes authoritative user context and can strengthen identity-change detections.</p></div><button type="button" onClick={() => patch({ assets: [...profile.assets, { id: crypto.randomUUID(), ip: "", hostname: "", macAddresses: [], assetType: "Observed host", role: "Unknown", services: [], ports: [], ...emptyProvenance() }] })}>Add asset</button></div>
            {tableTools("assets", () => downloadText(`${nameSlug(profile.name)}-assets.csv`, assetsToCsv(profile.assets)), <><input aria-label="Search assets" placeholder="Search assets…" value={assetQuery} onChange={(e) => setAssetQuery(e.target.value)}/><select aria-label="Sort assets" value={assetSort} onChange={(e) => setAssetSort(e.target.value as typeof assetSort)}><option value="ip">Sort: IP</option><option value="hostname">Sort: Hostname</option><option value="assetType">Sort: Asset type</option><option value="role">Sort: Role</option></select></>)}
            <div className="config-table-wrap"><table className="config-table asset-config-table"><thead><tr><th>IP</th><th>Hostname</th><th>Source</th><th>MAC address(es)</th><th>Asset type</th><th>Role</th><th>Services / ports</th><th/></tr></thead><tbody>{pageSlice(assetRows, assetPage).map((x) => <tr key={x.id}><td><input className={inputClass(`assets.${x.id}.ip`)} value={x.ip} onChange={(e) => updateAsset(x.id, { ip: e.target.value })}/>{fieldError(`assets.${x.id}.ip`)}</td><td><input value={x.hostname || ""} onChange={(e) => updateAsset(x.id, { hostname: e.target.value })}/></td><td><ProvenanceBadge source={x.source} confidence={x.confidence} reason={x.reason} observedCount={x.observedCount}/></td><td><input className={inputClass(`assets.${x.id}.macAddresses`)} value={x.macAddresses.join("; ")} placeholder="00:11:22:33:44:55" onChange={(e) => updateAsset(x.id, { macAddresses: splitList(e.target.value) })}/>{fieldError(`assets.${x.id}.macAddresses`)}</td><td><input value={x.assetType} onChange={(e) => updateAsset(x.id, { assetType: e.target.value })}/></td><td><input value={x.role} onChange={(e) => updateAsset(x.id, { role: e.target.value })}/></td><td><span className="compact-evidence">{[...x.services, ...x.ports.map(String)].join(", ") || "—"}</span></td><td><button className="danger-link" type="button" onClick={() => patch({ assets: profile.assets.filter((y) => y.id !== x.id) })}>Remove</button></td></tr>)}</tbody></table></div>{pager(assetPage, setAssetPage, assetRows.length)}
          </>}

          {tab === "infrastructure" && <>
            <div className="config-section-heading"><div><div className="context-heading-row"><h2>Trusted Infrastructure</h2><ContextHelp label="Trusted Infrastructure">Add only infrastructure that the site actually trusts, such as DNS, NTP, DHCP, or management systems. A host merely providing one of these services in the capture is not proof that it should be trusted.</ContextHelp><ContextBadge kind="policy" detail="Entries in this list are treated as trusted infrastructure by applicable detectors."/></div><p>Every listed DNS, NTP, DHCP, or management entry is active detector policy.</p><p className="context-guidance-note"><strong>Detector impact:</strong> only add systems you actually trust; a discovered service is evidence, not proof that the host is authorized infrastructure.</p></div><button type="button" onClick={() => patch({ infrastructure: [...profile.infrastructure, { id: crypto.randomUUID(), kind: "dns", value: "", label: "", ...emptyProvenance() }] })}>Add entry</button></div>
            {tableTools("infrastructure", () => downloadText(`${nameSlug(profile.name)}-trusted-infrastructure.csv`, infrastructureToCsv(profile.infrastructure)), <><input aria-label="Search trusted infrastructure" placeholder="Search infrastructure…" value={infraQuery} onChange={(e) => setInfraQuery(e.target.value)}/><select aria-label="Sort trusted infrastructure" value={infraSort} onChange={(e) => setInfraSort(e.target.value as typeof infraSort)}><option value="kind">Sort: Type</option><option value="value">Sort: IP / host</option><option value="label">Sort: Label</option><option value="observedCount">Sort: Observations</option></select></>)}
            <div className="config-table-wrap"><table className="config-table"><thead><tr><th>Type</th><th>IP / host</th><th>Label</th><th>Evidence</th><th/></tr></thead><tbody>{pageSlice(infraRows, infraPage).map((x) => <tr key={x.id}><td><select value={x.kind} onChange={(e) => updateInfra(x.id, { kind: e.target.value as InfrastructureEntry["kind"] })}><option value="dns">DNS</option><option value="ntp">NTP</option><option value="dhcp">DHCP</option><option value="management">Management</option></select></td><td><input className={inputClass(`infrastructure.${x.id}.value`)} value={x.value} onChange={(e) => updateInfra(x.id, { value: e.target.value })}/>{fieldError(`infrastructure.${x.id}.value`)}</td><td><input value={x.label || ""} onChange={(e) => updateInfra(x.id, { label: e.target.value })}/></td><td><div className="context-evidence-cell"><ProvenanceBadge source={x.source} confidence={x.confidence} reason={x.reason} observedCount={x.observedCount}/><span className="compact-evidence">{x.observedCount ? `${x.observedCount} observations` : x.reason || "No additional evidence detail"}</span></div></td><td><button className="danger-link" type="button" onClick={() => patch({ infrastructure: profile.infrastructure.filter((y) => y.id !== x.id) })}>Remove</button></td></tr>)}</tbody></table></div>{pager(infraPage, setInfraPage, infraRows.length)}
          </>}

          {tab === "communications" && <>
            <div className="config-section-heading"><div><div className="context-heading-row"><h2>Communications</h2><ContextHelp label="Observed Communications">This table records communication seen in the capture and supports baselining. It does not authorize control activity, Internet access, or cross-segment exceptions.</ContextHelp><ContextBadge kind="observed" detail="Communication pairs originate from packet evidence unless edited or imported."/></div><p>Zeek-observed pairs are added automatically for context and baselining.</p><p className="context-guidance-note"><strong>Important:</strong> an observed pair does not authorize control actions. Explicit authorization belongs in Control Authorization.</p></div><button type="button" onClick={() => patch({ communicationPairs: [...profile.communicationPairs, { id: crypto.randomUUID(), sourceIp: "", destinationIp: "", protocol: "tcp", service: "", ...emptyProvenance() }] })}>Add Pair</button></div>
            {tableTools("communications", () => downloadText(`${nameSlug(profile.name)}-communications.csv`, communicationsToCsv(profile.communicationPairs)), <><input aria-label="Search communications" placeholder="Search communications…" value={pairQuery} onChange={(e) => setPairQuery(e.target.value)}/><select aria-label="Sort communications" value={pairSort} onChange={(e) => setPairSort(e.target.value as typeof pairSort)}><option value="sourceIp">Sort: Source</option><option value="destinationIp">Sort: Destination</option><option value="protocol">Sort: Protocol</option><option value="destinationPort">Sort: Port</option><option value="observedCount">Sort: Observations</option></select></>)}
            <div className="config-table-wrap"><table className="config-table"><thead><tr><th>Source</th><th>Destination</th><th>Protocol</th><th>Port</th><th>Service</th><th>Evidence</th><th/></tr></thead><tbody>{pageSlice(pairRows, pairPage).map((x) => <tr key={x.id}><td><input className={inputClass(`pairs.${x.id}.sourceIp`)} value={x.sourceIp} onChange={(e) => updatePair(x.id, { sourceIp: e.target.value })}/>{fieldError(`pairs.${x.id}.sourceIp`)}</td><td><input className={inputClass(`pairs.${x.id}.destinationIp`)} value={x.destinationIp} onChange={(e) => updatePair(x.id, { destinationIp: e.target.value })}/>{fieldError(`pairs.${x.id}.destinationIp`)}</td><td><input value={x.protocol || ""} onChange={(e) => updatePair(x.id, { protocol: e.target.value })}/></td><td><input className={inputClass(`pairs.${x.id}.destinationPort`)} type="number" value={x.destinationPort ?? ""} onChange={(e) => updatePair(x.id, { destinationPort: e.target.value ? Number(e.target.value) : undefined })}/>{fieldError(`pairs.${x.id}.destinationPort`)}</td><td><input value={x.service || ""} onChange={(e) => updatePair(x.id, { service: e.target.value })}/></td><td><div className="context-evidence-cell"><ProvenanceBadge source={x.source} confidence={x.confidence} reason={x.reason} observedCount={x.observedCount}/><span className="compact-evidence">{x.observedCount ? `${x.observedCount} observed` : x.reason || "No observation count"}</span></div>{fieldError(`pairs.${x.id}.duplicate`)}</td><td><button className="danger-link" type="button" onClick={() => patch({ communicationPairs: profile.communicationPairs.filter((y) => y.id !== x.id) })}>Remove</button></td></tr>)}</tbody></table></div>{pager(pairPage, setPairPage, pairRows.length)}
          </>}

          {tab === "communications" && <>
            <div className="config-section-heading"><div><div className="context-heading-row"><h2>Segment Exceptions</h2><ContextHelp label="Segment Exceptions">Use these rules for known, expected communication between configured segments. They are scoped exceptions and should not be used as a substitute for control authorization or external-destination approval.</ContextHelp><ContextBadge kind="policy"/></div><p>Allow expected communication between configured network segments.</p><p className="context-guidance-note"><strong>Scope:</strong> this exception applies only to detectors mapped to segment-pair policy; it does not authorize unrelated control actions or Internet egress.</p></div><button type="button" onClick={() => patch({ allowedSegmentPairs: [...profile.allowedSegmentPairs, { id: crypto.randomUUID(), sourceSegment: "", destinationSegment: "", description: "" }] })}>Add Segment Pair</button></div>
            {tableTools("segmentPairs", () => downloadText(`${nameSlug(profile.name)}-segment-communication-exceptions.csv`, segmentPairsToCsv(profile.allowedSegmentPairs)), <><input aria-label="Search segment communication exceptions" placeholder="Search segment pairs…" value={segmentPairQuery} onChange={(e) => setSegmentPairQuery(e.target.value)}/><select value={segmentPairSort} onChange={(e) => setSegmentPairSort(e.target.value as typeof segmentPairSort)}><option value="sourceSegment">Sort: Source segment</option><option value="destinationSegment">Sort: Destination segment</option></select></>)}
            <datalist id="segment-options">{profile.segments.map((x) => <React.Fragment key={x.id}><option value={x.name}/><option value={x.cidr}/></React.Fragment>)}</datalist>
            <div className="config-table-wrap"><table className="config-table"><thead><tr><th>Source segment</th><th>Destination segment</th><th>Description</th><th/></tr></thead><tbody>{pageSlice(segmentPairRows, segmentPairPage).map((x) => <tr key={x.id}><td><input list="segment-options" className={inputClass(`segmentPairs.${x.id}.sourceSegment`)} value={x.sourceSegment} onChange={(e) => updateSegmentPair(x.id, { sourceSegment: e.target.value })}/>{fieldError(`segmentPairs.${x.id}.sourceSegment`)}</td><td><input list="segment-options" className={inputClass(`segmentPairs.${x.id}.destinationSegment`)} value={x.destinationSegment} onChange={(e) => updateSegmentPair(x.id, { destinationSegment: e.target.value })}/>{fieldError(`segmentPairs.${x.id}.destinationSegment`)}</td><td><input value={x.description || ""} onChange={(e) => updateSegmentPair(x.id, { description: e.target.value })}/></td><td><button className="danger-link" type="button" onClick={() => patch({ allowedSegmentPairs: profile.allowedSegmentPairs.filter((y) => y.id !== x.id) })}>Remove</button></td></tr>)}</tbody></table></div>{pager(segmentPairPage, setSegmentPairPage, segmentPairRows.length)}
          </>}

          {tab === "controlActions" && <>
            <div className="config-section-heading"><div><div className="context-heading-row"><h2>Control Authorization</h2><ContextHelp label="Control Authorization">These are explicit permissions for control-changing OT behavior. Keep source, destination, protocol, operation, and function-code scope as narrow as possible so legitimate maintenance does not suppress unrelated findings.</ContextHelp><ContextBadge kind="policy" detail="These rules explicitly authorize scoped OT control behavior."/></div><p>Explicitly authorize expected Modbus, DNP3, S7comm, and EtherNet/IP control, write, programming, or firmware paths.</p><p className="context-guidance-note"><strong>High-impact policy:</strong> keep source, destination, operation, and function-code scope as narrow as possible. Observed traffic alone never creates authorization.</p></div><button type="button" onClick={() => patch({ authorizedControlActions: [...profile.authorizedControlActions, { id: crypto.randomUUID(), protocol: "modbus", source: "", destination: "", allowedOperations: [], allowedFunctionCodes: [], description: "" }] })}>Add Control Action</button></div>
            {tableTools("controlActions", () => downloadText(`${nameSlug(profile.name)}-authorized-control-actions.csv`, controlActionsToCsv(profile.authorizedControlActions)), <><input aria-label="Search authorized control actions" placeholder="Search control actions…" value={controlQuery} onChange={(e) => setControlQuery(e.target.value)}/><select value={controlSort} onChange={(e) => setControlSort(e.target.value as typeof controlSort)}><option value="protocol">Sort: Protocol</option><option value="source">Sort: Source</option><option value="destination">Sort: Destination</option></select></>)}
            <div className="config-table-wrap"><table className="config-table control-action-table"><thead><tr><th>Protocol</th><th>Source</th><th>Destination</th><th>Allowed operations</th><th>Function codes</th><th>Description</th><th/></tr></thead><tbody>{pageSlice(controlRows, controlPage).map((x) => <tr key={x.id}><td><select value={x.protocol} onChange={(e) => updateControl(x.id, { protocol: e.target.value as AuthorizedControlAction["protocol"] })}><option value="modbus">Modbus</option><option value="dnp3">DNP3</option><option value="s7comm">S7comm</option><option value="enip">EtherNet/IP (CIP)</option></select></td><td><input className={inputClass(`controlActions.${x.id}.source`)} value={x.source} placeholder="IP, host, or CIDR" onChange={(e) => updateControl(x.id, { source: e.target.value })}/>{fieldError(`controlActions.${x.id}.source`)}</td><td><input className={inputClass(`controlActions.${x.id}.destination`)} value={x.destination} placeholder="IP, host, or CIDR" onChange={(e) => updateControl(x.id, { destination: e.target.value })}/>{fieldError(`controlActions.${x.id}.destination`)}</td><td><input value={x.allowedOperations.join("; ")} placeholder="write; stop; program_download" onChange={(e) => updateControl(x.id, { allowedOperations: splitList(e.target.value) })}/></td><td><input value={x.allowedFunctionCodes.join("; ")} placeholder="5; 6; 16 or 0x1A" onChange={(e) => updateControl(x.id, { allowedFunctionCodes: parseCodes(e.target.value) })}/>{fieldError(`controlActions.${x.id}.authorization`)}</td><td><input value={x.description || ""} onChange={(e) => updateControl(x.id, { description: e.target.value })}/></td><td><button className="danger-link" type="button" onClick={() => patch({ authorizedControlActions: profile.authorizedControlActions.filter((y) => y.id !== x.id) })}>Remove</button></td></tr>)}</tbody></table></div>{pager(controlPage, setControlPage, controlRows.length)}
          </>}

          {tab === "communications" && <>
            <div className="config-section-heading"><div><div className="context-heading-row"><h2>Ignored Hosts</h2><ContextHelp label="Ignored Hosts">Ignored hosts can suppress findings in detectors that honor this policy. Prefer a narrow detector-specific exception when possible instead of broadly ignoring a host.</ContextHelp><ContextBadge kind="policy"/></div><p>Applicable detectors may omit findings involving these hosts.</p><p className="context-guidance-note"><strong>High-impact policy:</strong> use sparingly because ignored hosts can suppress otherwise actionable findings.</p></div><button type="button" onClick={() => patch({ allowedHosts: [...profile.allowedHosts, ""] })}>Add Host</button></div>
            {tableTools("ignoredHosts", () => downloadText(`${nameSlug(profile.name)}-hosts-ignored-by-detectors.csv`, ignoredHostsToCsv(profile.allowedHosts)), <><input aria-label="Search hosts ignored by detectors" placeholder="Search ignored hosts…" value={ignoredHostQuery} onChange={(e) => setIgnoredHostQuery(e.target.value)}/><select value={ignoredHostSort} onChange={(e) => setIgnoredHostSort(e.target.value as typeof ignoredHostSort)}><option value="asc">Sort: Host ascending</option><option value="desc">Sort: Host descending</option></select></>)}
            <div className="config-table-wrap"><table className="config-table list-config-table"><thead><tr><th>Host / IP address</th><th/></tr></thead><tbody>{ignoredHostRows.length === 0 ? <tr><td colSpan={2} className="empty-list-cell">{profile.allowedHosts.length ? "No ignored hosts match the current filter." : "No hosts are currently excluded."}</td></tr> : pageSlice(ignoredHostRows, ignoredHostPage).map(({ value, index }) => <tr key={`${index}-${value}`}><td><input className={inputClass(`allowedHosts.${index}`)} value={value} onChange={(e) => patch({ allowedHosts: profile.allowedHosts.map((v, j) => j === index ? e.target.value : v) })}/>{fieldError(`allowedHosts.${index}`)}</td><td><button className="danger-link" type="button" onClick={() => patch({ allowedHosts: profile.allowedHosts.filter((_, j) => j !== index) })}>Remove</button></td></tr>)}</tbody></table></div>{pager(ignoredHostPage, setIgnoredHostPage, ignoredHostRows.length)}
          </>}

          {tab === "communications" && <>
            <div className="config-section-heading"><div><div className="context-heading-row"><h2>Approved External Destinations</h2><ContextHelp label="Approved External Destinations">List only Internet or external destinations that OT systems are expected to contact. Approval affects matching egress behavior; it does not make the destination generally trusted for other detector decisions.</ContextHelp><ContextBadge kind="policy"/></div><p>External hosts or networks that outbound detectors should treat as expected.</p><p className="context-guidance-note"><strong>Scope:</strong> approval applies only to matching egress policy and does not create general host trust or control authorization.</p></div><button type="button" onClick={() => patch({ approvedExternalDestinations: [...profile.approvedExternalDestinations, ""] })}>Add Destination</button></div>
            {tableTools("externalDestinations", () => downloadText(`${nameSlug(profile.name)}-approved-external-destinations.csv`, externalDestinationsToCsv(profile.approvedExternalDestinations)), <><input aria-label="Search approved external destinations" placeholder="Search destinations…" value={externalQuery} onChange={(e) => setExternalQuery(e.target.value)}/><select value={externalSort} onChange={(e) => setExternalSort(e.target.value as typeof externalSort)}><option value="asc">Sort: Destination ascending</option><option value="desc">Sort: Destination descending</option></select></>)}
            <div className="config-table-wrap"><table className="config-table list-config-table"><thead><tr><th>Approved external destination</th><th/></tr></thead><tbody>{externalRows.length === 0 ? <tr><td colSpan={2} className="empty-list-cell">{profile.approvedExternalDestinations.length ? "No destinations match the current filter." : "No approved external destinations configured."}</td></tr> : pageSlice(externalRows, externalPage).map(({ value, index }) => <tr key={`${index}-${value}`}><td><input className={inputClass(`externalDestinations.${index}`)} value={value} placeholder="198.51.100.25 or 198.51.100.0/24" onChange={(e) => patch({ approvedExternalDestinations: profile.approvedExternalDestinations.map((v, j) => j === index ? e.target.value : v) })}/>{fieldError(`externalDestinations.${index}`)}</td><td><button className="danger-link" type="button" onClick={() => patch({ approvedExternalDestinations: profile.approvedExternalDestinations.filter((_, j) => j !== index) })}>Remove</button></td></tr>)}</tbody></table></div>{pager(externalPage, setExternalPage, externalRows.length)}
          </>}

          {showAdvanced && tab === "advanced" && <>
            <div className="config-section-heading"><div><div className="context-heading-row"><h2>Advanced Module Overrides</h2><ContextHelp label="Advanced Module Overrides">These settings alter individual detector defaults. Change them only when site requirements justify the override, and prefer first-class Context fields when they express the same policy more clearly.</ContextHelp><ContextBadge kind="policy"/></div><p>Known detector policy fields are presented from a schema generated from the current 75-module source. Leave fields unset to use detector defaults.</p><p className="context-guidance-note"><strong>Expert setting:</strong> overrides take precedence for the selected detector; unset fields continue to use detector defaults.</p></div></div>
            <div className="advanced-module-picker"><label><span>Module</span><select value={advancedModule} onChange={(e) => setAdvancedModule(e.target.value)}>{ADVANCED_POLICY_SCHEMAS.map((schema) => <option key={schema.moduleId} value={schema.moduleId}>{schema.moduleId}</option>)}</select></label><span>Override fields are stored by module; detector policy mapping is backend-owned.</span></div>
            {selectedAdvancedSchema && <div className="advanced-field-grid">{selectedAdvancedSchema.fields.map((field) => {
              const value = profile.modulePolicies[selectedAdvancedSchema.moduleId]?.[field.key];
              if (field.type === "boolean") return <label key={field.key}><span>{field.key}</span><select value={value === undefined ? "" : String(Boolean(value))} onChange={(e) => e.target.value === "" ? setAdvancedField(selectedAdvancedSchema.moduleId, field.key, undefined, true) : setAdvancedField(selectedAdvancedSchema.moduleId, field.key, e.target.value === "true")}><option value="">Use detector default</option><option value="true">True</option><option value="false">False</option></select></label>;
              if (field.type === "number") return <label key={field.key}><span>{field.key}</span><input type="number" value={typeof value === "number" ? value : ""} placeholder="Detector default" onChange={(e) => e.target.value === "" ? setAdvancedField(selectedAdvancedSchema.moduleId, field.key, undefined, true) : setAdvancedField(selectedAdvancedSchema.moduleId, field.key, Number(e.target.value))}/></label>;
              if (field.type === "string") return <label key={field.key}><span>{field.key}</span><input value={typeof value === "string" ? value : ""} placeholder="Detector default" onChange={(e) => e.target.value === "" ? setAdvancedField(selectedAdvancedSchema.moduleId, field.key, undefined, true) : setAdvancedField(selectedAdvancedSchema.moduleId, field.key, e.target.value)}/></label>;
              return <label key={`${selectedAdvancedSchema.moduleId}-${field.key}-${JSON.stringify(value)}`} className="advanced-json-field"><span>{field.key}</span><textarea spellCheck={false} defaultValue={value === undefined ? "" : JSON.stringify(value, null, 2)} placeholder="Unset = detector default. Enter JSON for arrays/objects." onBlur={(e) => { const text = e.target.value.trim(); if (!text) { setAdvancedField(selectedAdvancedSchema.moduleId, field.key, undefined, true); return; } try { setAdvancedField(selectedAdvancedSchema.moduleId, field.key, JSON.parse(text)); setStatus(""); } catch { setStatus(`${field.key}: invalid JSON; value was not applied.`); } }}/></label>;
            })}</div>}
            <details className="advanced-raw-json"><summary>Raw module override JSON (fallback)</summary><textarea spellCheck={false} value={JSON.stringify(profile.modulePolicies, null, 2)} onChange={(e) => { try { patch({ modulePolicies: JSON.parse(e.target.value || "{}") }); setStatus(""); } catch { setStatus("Advanced JSON is not valid yet; changes were not applied."); } }}/></details>
          </>}
        </main>
      </div>

      {modal?.kind === "completeContext" && <Modal title="Complete Context" onCancel={() => setModal(null)} actions={<><button onClick={() => setModal(null)}>Close</button>{completeStep > 0 && <button onClick={() => setCompleteStep((n) => Math.max(0, n - 1))}>Back</button>}{completeStep < 4 ? <button className="primary" onClick={() => setCompleteStep((n) => Math.min(4, n + 1))}>Next</button> : <button className="primary" onClick={() => { setModal(null); setTab("captureScope"); }}>Finish</button>}</>}>
        <div className="context-wizard">
          <div className="wizard-progress" aria-label={`Step ${completeStep + 1} of 5`}><span style={{ width: `${((completeStep + 1) / 5) * 100}%` }}/></div>
          {completeStep === 0 && <div className="wizard-step"><h3>Context completion</h3><div className="wizard-summary"><strong>{completionPercent}%</strong><span>of readiness categories currently satisfied</span></div><p>Zeek has already populated observable facts. This workflow focuses on context that still needs classification, site-policy answers, or authorization review.</p>{missingReadiness.length ? <ul className="wizard-missing-list">{missingReadiness.map((item) => <li key={item.id}><strong>{item.label}</strong><span>{item.detail}</span></li>)}</ul> : <div className="wizard-good">All general readiness categories currently have the required context.</div>}<div className="wizard-scan-facts"><span>{profile.scan.filesScanned} Zeek log files scanned</span><span>{profile.assets.length} assets</span><span>{profile.segments.length} segments</span><span>{profile.infrastructure.length} infrastructure entries</span><span>{profile.communicationPairs.length} communications</span><span>{profile.scan.dhcpAssignmentsObserved || 0} DHCP observations</span><span>{profile.scan.ipv6AddressesObserved || 0} IPv6 addresses observed</span></div></div>}
          {completeStep === 1 && <div className="wizard-step"><div className="wizard-step-heading"><div><div className="context-heading-row"><h3>1. Classify discovered networks</h3><ContextBadge kind="inferred"/></div><p>Review role and Purdue level. Suggested Purdue values are based on observed protocol evidence and should be verified.</p></div><div className="wizard-suggestion-actions"><button type="button" onClick={applyNetworkSuggestions}>Apply OT/Purdue Suggestions</button><span className="wizard-suggestion-status" role="status" aria-live="polite">{suggestionStatus || "\u00a0"}</span></div></div><div className="wizard-table-wrap"><table className="wizard-table"><thead><tr><th>Network</th><th>Observed</th><th>Role</th><th>Purdue</th><th>Addressing</th><th>IPv6</th></tr></thead><tbody>{profile.segments.map((segment) => <tr key={segment.id}><td><strong>{segment.cidr}</strong><small>{segment.name}</small></td><td><strong>{segment.observedCount || 0} hosts</strong>{segmentObservedFacts(segment).map((fact)=><small key={fact}>{fact}</small>)}</td><td><select value={segment.role} onChange={(e)=>updateSegment(segment.id,{role:e.target.value as NetworkSegment["role"]})}><option value="unknown">{segment.suggestedRole === "ot" ? "Unknown (suggested OT)" : "Unknown"}</option><option value="ot">OT</option><option value="it">IT</option><option value="dmz">DMZ</option></select></td><td><select value={purdueSelectValue(segment.purdueLevel)} onChange={(e)=>updateSegment(segment.id,{purdueLevel:e.target.value})}><option value="">{suggestedPurdue(segment) ? `Unknown (suggested Level ${suggestedPurdue(segment)})` : "Unknown"}</option>{!PURDUE_LEVELS.includes(purdueSelectValue(segment.purdueLevel) as (typeof PURDUE_LEVELS)[number]) && purdueSelectValue(segment.purdueLevel) && <option value={purdueSelectValue(segment.purdueLevel)}>{purdueSelectValue(segment.purdueLevel)}</option>}{PURDUE_LEVELS.map((level)=><option key={level} value={level}>Level {level}</option>)}</select></td><td><select value={segment.addressing} onChange={(e)=>updateSegment(segment.id,{addressing:e.target.value as NetworkSegment["addressing"]})}><option value="unknown">{segment.suggestedAddressing === "dhcp" ? "Unknown (DHCP observed)" : "Unknown"}</option><option value="static">Static</option><option value="dhcp">DHCP</option><option value="mixed">Mixed</option></select></td><td><select value={segment.ipv6Allowed === undefined ? "" : String(segment.ipv6Allowed)} onChange={(e)=>updateSegment(segment.id,{ipv6Allowed:e.target.value===""?undefined:e.target.value==="true"})}><option value="">Unknown</option><option value="true">Allowed</option><option value="false">IPv4 only</option></select></td></tr>)}</tbody></table></div></div>}
          {completeStep === 2 && <div className="wizard-step"><div className="context-heading-row"><h3>2. Capture assumptions and trusted infrastructure</h3><ContextBadge kind="policy"/></div><p>These are site-policy questions that traffic alone cannot prove. Infrastructure discovered in Zeek is already active in the profile.</p><div className="wizard-question-list"><label><input type="checkbox" checked={profile.captureScope.internalIcsOnlyExpected} onChange={(e)=>patch({captureScope:{...profile.captureScope,internalIcsOnlyExpected:e.target.checked}})}/><span><strong>Internal ICS/OT traffic only is expected in this capture</strong><small>Required before public-to-public traffic can be treated as anomalous.</small></span></label><label><input type="checkbox" checked={profile.captureScope.dedicatedOtSensor} onChange={(e)=>patch({captureScope:{...profile.captureScope,dedicatedOtSensor:e.target.checked}})}/><span><strong>This is a dedicated OT/ICS sensor</strong><small>Helps establish that OT-focused assumptions apply to the monitored scope.</small></span></label><label><input type="checkbox" checked={profile.captureScope.ipv4OnlyExpected} onChange={(e)=>patch({captureScope:{...profile.captureScope,ipv4OnlyExpected:e.target.checked}})}/><span><strong>IPv4-only behavior is expected for this OT scope</strong><small>Enables IPv6-in-OT detection where appropriate.</small></span></label></div><div className="wizard-infra-summary">{(["dns","ntp","dhcp","management"] as const).map((kind)=><div key={kind}><strong>{profile.infrastructure.filter((x)=>x.kind===kind).length}</strong><span>{kind.toUpperCase()} entr{profile.infrastructure.filter((x)=>x.kind===kind).length===1?"y":"ies"}</span></div>)}</div></div>}
          {completeStep === 3 && <div className="wizard-step"><div className="context-heading-row"><h3>3. Review observed control relationships</h3><ContextBadge kind="observed"/></div><p>Zeek-observed control communications can be turned into authorization-rule candidates. Observation does not prove authorization, so rules created here still require you to specify the allowed operations or function codes.</p>{observedControlCandidates.length ? <div className="wizard-control-list">{observedControlCandidates.map((c)=><div key={`${c.protocol}|${c.source}|${c.destination}`}><span><strong>{c.source} → {c.destination}</strong><small>{c.protocol.toUpperCase()} · {c.service || "service inferred from port"} · observed {c.count} time(s)</small></span><button type="button" disabled={profile.authorizedControlActions.some((x)=>x.protocol===c.protocol&&x.source===c.source&&x.destination===c.destination)} onClick={()=>addControlCandidate(c)}>{profile.authorizedControlActions.some((x)=>x.protocol===c.protocol&&x.source===c.source&&x.destination===c.destination)?"Added":"Create Rule"}</button></div>)}</div> : <div className="wizard-good">No Modbus, DNP3, S7comm, or EtherNet/IP/CIP communication candidates were found in the current Communications list.</div>}</div>}
          {completeStep === 4 && <div className="wizard-step"><h3>4. Reuse context from another profile</h3><p>Site metadata often remains stable between captures. Copy selected categories from a saved profile instead of re-entering them.</p><label className="wizard-copy-source"><span>Copy from saved profile</span><select value={copySourceId} onChange={(e)=>setCopySourceId(e.target.value)}><option value="">Select profile…</option>{profiles.filter((x)=>x.id!==profile.id).map((x)=><option key={x.id} value={x.id}>{x.name}</option>)}</select></label><div className="wizard-copy-grid">{Object.entries({segments:"Network Segments",assets:"Asset Inventory",infrastructure:"Trusted Infrastructure",captureScope:"Capture Scope",communications:"Communications",segmentPairs:"Segment Exceptions",controlActions:"Authorized Control Actions",ignoredHosts:"Hosts Ignored by Detectors",externalDestinations:"Approved External Destinations"}).map(([key,label])=><label key={key}><input type="checkbox" checked={copyCategories[key as keyof typeof copyCategories]} onChange={(e)=>setCopyCategories((v)=>({...v,[key]:e.target.checked}))}/><span>{label}</span></label>)}</div><button type="button" className="primary" disabled={!copySourceId} onClick={copyFromProfile}>Copy Selected Context</button><div className="wizard-finish-summary"><strong>{missingReadiness.length}</strong><span>general readiness item(s) still need attention. Finish returns to the profile editor. Use Complete Context again at any time to review remaining recommendations.</span></div></div>}
        </div>
      </Modal>}



      {modal?.kind === "close" && <Modal title="Unsaved Changes" onCancel={() => setModal(null)} actions={<><button onClick={() => setModal(null)}>Keep Editing</button><button className="danger" onClick={() => { setModal(null); onClose(savedDuringSession); }}>Discard &amp; Close</button></>}><p>The current Context has changes that have not been saved.</p><p>Save them before closing if you want to keep them.</p></Modal>}
      {modal?.kind === "clearScan" && <Modal title="Clear Scanner-Derived Data?" onCancel={() => setModal(null)} actions={<><button onClick={() => setModal(null)}>Cancel</button><button className="danger" onClick={clearScanned}>Clear Scanned Data</button></>}><p>This removes entries that still have Zeek as their source and clears the last-scan summary.</p><p>Entries you manually added or edited are kept.</p></Modal>}
      {modal?.kind === "issues" && <Modal title={modal.title} onCancel={() => setModal(null)} actions={<button onClick={() => setModal(null)}>Close</button>}><p>{modal.message}</p><ul className="modal-issue-list">{modal.issues.map((x, i) => <li key={`${x.path}-${i}`}><strong>{x.severity === "error" ? "Error" : "Note"}:</strong> {x.message}</li>)}</ul></Modal>}

      <footer className="detection-config-footer"><span>{errors.length ? `${errors.length} validation error${errors.length === 1 ? "" : "s"}` : missingReadiness.length ? `${missingReadiness.length} recommended item${missingReadiness.length === 1 ? "" : "s"} incomplete` : "Context ready for analysis"}</span><div>{saveConfirmation && <span className="save-confirmation" role="status">{saveConfirmation}</span>}<button type="button" onClick={requestClose}>Done</button><button type="button" className="primary" onClick={handleSave}>Save</button></div></footer>
    </section>
  </div>;
};

export default DetectionConfiguration;
