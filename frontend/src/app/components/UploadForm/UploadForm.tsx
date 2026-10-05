import React, { ChangeEvent, Dispatch, SetStateAction, useEffect, useMemo, useRef, useState } from "react";
import { ElevadrReport } from "../../types/Report";
import { normalizeElevadrReport } from "../../utils/reportCompatibility";
import {
  activateProfile,
  createEmptyProfile,
  listProfiles,
  loadActiveProfile,
  normalizeProfile,
  removeProfile,
  saveProfile,
} from "../DetectionConfiguration/profile";
import { DetectionConfigurationProfile } from "../DetectionConfiguration/types";
import { ALL_DETECTION_MODULES } from "../DetectionConfiguration/moduleCatalog";
import { mergeScanIntoProfile, ZeekScanResult } from "../DetectionConfiguration/zeekScanner";
import "./UploadForm.css";

const PCAP_ANALYSIS_URL = (() => {
  const configured = (import.meta as ImportMeta & { env?: Record<string, string | undefined> }).env?.VITE_PCAP_ANALYSIS_URL?.trim();
  return configured || "/api/v1/pcap-analysis";
})();
const PCAP_CONTEXT_DISCOVERY_URL = (() => {
  const configured = (import.meta as ImportMeta & { env?: Record<string, string | undefined> }).env?.VITE_PCAP_CONTEXT_DISCOVERY_URL?.trim();
  return configured || "/api/v1/pcap-context-discovery";
})();

interface ProgressEvent { stage: string; progress: number | null; message: string; detail?: string | null; elapsedSeconds?: number; }
interface UploadFormProps {
  onReportLoaded: (report: ElevadrReport) => void;
  report: ElevadrReport | null;
  isAnalyzing: boolean;
  setIsAnalyzing?: Dispatch<SetStateAction<boolean>>;
  inputId?: string;
  onOpenDetectionContext?: () => void;
  onOpenDetectionModules?: () => void;
  profileRevision?: number;
  refreshRequestRevision?: number;
  onReanalysisStatus?: (status: "started" | "completed" | "failed" | "unavailable", message?: string) => void;
}
type SupportedFileKind = "pcap" | "json";

class AnalysisCanceledError extends Error {
  constructor(message = "Analysis canceled.") { super(message); this.name = "AnalysisCanceledError"; }
}

const UploadForm: React.FC<UploadFormProps> = ({
  onReportLoaded, report, isAnalyzing, setIsAnalyzing, inputId, onOpenDetectionContext, onOpenDetectionModules, profileRevision = 0,
  refreshRequestRevision = 0, onReanalysisStatus,
}) => {
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState<ProgressEvent | null>(null);
  const [selectedFileName, setSelectedFileName] = useState<string | null>(null);
  const [selectedFileKind, setSelectedFileKind] = useState<SupportedFileKind | null>(null);
  const [pendingPcap, setPendingPcap] = useState<File | null>(null);
  const [contextDialogOpen, setContextDialogOpen] = useState(false);
  const [selectedProfileId, setSelectedProfileId] = useState(() => {
    const stored = listProfiles();
    const active = loadActiveProfile();
    return stored.some((profile) => profile.id === active.id) ? active.id : stored[0]?.id || "";
  });
  const [profileListRevision, setProfileListRevision] = useState(0);
  const [contextDiscovery, setContextDiscovery] = useState<ZeekScanResult | null>(null);
  const [zeekEvidenceToken, setZeekEvidenceToken] = useState<string | null>(null);
  const [zeekEvidencePcapSha256, setZeekEvidencePcapSha256] = useState<string | null>(null);
  const [lastPcapSession, setLastPcapSession] = useState<{ file: File; evidenceToken: string; pcapSha256: string } | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);
  const activeJobUrlRef = useRef<string | null>(null);
  const cancelRequestedRef = useRef(false);
  const lastHandledRefreshRequestRef = useRef(refreshRequestRevision);

  const profiles = useMemo(() => listProfiles(), [profileRevision, contextDialogOpen, profileListRevision]);
  const selectedProfile: DetectionConfigurationProfile | null = useMemo(
    () => profiles.find((profile) => profile.id === selectedProfileId) || profiles[0] || null,
    [profiles, selectedProfileId],
  );
  const effectiveProfile: DetectionConfigurationProfile | null = useMemo(
    () => selectedProfile && contextDiscovery ? mergeScanIntoProfile(selectedProfile, contextDiscovery) : selectedProfile,
    [selectedProfile, contextDiscovery],
  );


  const getFileKind = (file: File): SupportedFileKind | null => {
    const name = file.name.toLowerCase();
    if (name.endsWith(".json") || file.type === "application/json") return "json";
    if (name.endsWith(".pcap") || name.endsWith(".pcapng")) return "pcap";
    return null;
  };

  const loadJsonReport = async (file: File): Promise<void> => {
    try {
      const parsed: unknown = JSON.parse(await file.text());
      const { report: normalized } = normalizeElevadrReport(parsed);
      onReportLoaded(normalized);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to load JSON report");
    }
  };

  const discoverPcapContext = async (file: File): Promise<{ scan: ZeekScanResult; evidenceToken: string; pcapSha256: string }> => {
    setError(null);
    setIsAnalyzing?.(true);
    setProgress({ stage: "uploading", progress: 1, message: "Uploading packet capture for one-time Zeek evidence extraction…", detail: file.name });
    try {
      const formData = new FormData();
      formData.append("file", file);
      const response = await fetch(PCAP_CONTEXT_DISCOVERY_URL, { method: "POST", body: formData });
      const text = await response.text();
      let payload: unknown;
      try { payload = JSON.parse(text); } catch { payload = null; }
      if (!response.ok) {
        const message = payload && typeof payload === "object" && "message" in payload
          ? String((payload as { message?: unknown }).message || "")
          : text;
        throw new Error(message || `PCAP context discovery failed with status ${response.status}`);
      }
      const jobId = payload && typeof payload === "object" && "jobId" in payload
        ? String((payload as { jobId?: unknown }).jobId || "")
        : "";
      if (!jobId) throw new Error("Backend did not return a context-discovery job ID.");

      const statusUrl = `${PCAP_CONTEXT_DISCOVERY_URL.replace(/\/$/, "")}/${encodeURIComponent(jobId)}`;
      activeJobUrlRef.current = statusUrl;
      cancelRequestedRef.current = false;
      for (;;) {
        await new Promise((resolve) => window.setTimeout(resolve, 650));
        const statusResponse = await fetch(statusUrl, { method: "GET", cache: "no-store" });
        const statusText = await statusResponse.text();
        let statusPayload: unknown;
        try { statusPayload = JSON.parse(statusText); } catch { statusPayload = null; }
        if (!statusResponse.ok || !statusPayload || typeof statusPayload !== "object") {
          throw new Error(`Unable to read PCAP context-discovery progress (${statusResponse.status}).`);
        }
        const status = statusPayload as {
          status?: string;
          stage?: string;
          progress?: number | null;
          message?: string;
          detail?: string | null;
          elapsedSeconds?: number;
          result?: unknown;
        };
        setProgress({
          stage: status.stage || "discovery",
          progress: typeof status.progress === "number" ? status.progress : null,
          message: status.message || "Discovering Detection Context…",
          detail: status.detail ?? null,
          elapsedSeconds: typeof status.elapsedSeconds === "number" ? status.elapsedSeconds : undefined,
        });
        if (status.status === "canceled") throw new AnalysisCanceledError(status.message || "Context discovery canceled.");
        if (status.status === "failed") throw new Error(status.message || "PCAP context discovery failed.");
        if (status.status === "completed") {
          const result = status.result;
          if (!result || typeof result !== "object" || !Array.isArray((result as Partial<ZeekScanResult>).assets) || !Array.isArray((result as Partial<ZeekScanResult>).segments)) {
            throw new Error("Backend did not return valid Detection Context discovery data.");
          }
          const evidenceToken = "evidenceToken" in result ? String((result as { evidenceToken?: unknown }).evidenceToken || "") : "";
          const evidence = "evidence" in result && (result as { evidence?: unknown }).evidence && typeof (result as { evidence?: unknown }).evidence === "object"
            ? (result as { evidence: { pcapSha256?: unknown } }).evidence
            : null;
          const pcapSha256 = evidence ? String(evidence.pcapSha256 || "") : "";
          if (!evidenceToken || !pcapSha256) throw new Error("Backend did not retain complete Zeek evidence identity for detector analysis.");
          return { scan: result as ZeekScanResult, evidenceToken, pcapSha256 };
        }
      }
    } finally {
      activeJobUrlRef.current = null;
      cancelRequestedRef.current = false;
      setIsAnalyzing?.(false);
    }
  };

  const analyzePcap = async (file: File, profile: DetectionConfigurationProfile, evidenceToken: string | null, evidencePcapSha256: string | null): Promise<string | null> => {
    setError(null);
    setIsAnalyzing?.(true);
    setProgress({ stage: "preparing-analysis", progress: 1, message: evidenceToken ? "Applying Detection Context to retained Zeek evidence…" : "Uploading PCAP and Detection Context…", detail: file.name });
    try {
      const formData = new FormData();
      formData.append("profile", JSON.stringify(normalizeProfile(profile)));
      formData.append("sourceFilename", file.name);
      if (evidenceToken) {
        formData.append("evidenceToken", evidenceToken);
        if (evidencePcapSha256) formData.append("evidencePcapSha256", evidencePcapSha256);
      } else formData.append("file", file);
      const response = await fetch(PCAP_ANALYSIS_URL, { method: "POST", body: formData });
      const text = await response.text();
      let payload: unknown;
      try { payload = JSON.parse(text); } catch { payload = null; }
      if (!response.ok) {
        const message = payload && typeof payload === "object" && "message" in payload
          ? String((payload as { message?: unknown }).message || "")
          : text;
        throw new Error(message || `PCAP analysis failed with status ${response.status}`);
      }
      const jobId = payload && typeof payload === "object" && "jobId" in payload
        ? String((payload as { jobId?: unknown }).jobId || "")
        : "";
      if (!jobId) throw new Error("Backend did not return a PCAP-analysis job ID.");

      const statusUrl = `${PCAP_ANALYSIS_URL.replace(/\/$/, "")}/${encodeURIComponent(jobId)}`;
      activeJobUrlRef.current = statusUrl;
      cancelRequestedRef.current = false;
      for (;;) {
        await new Promise((resolve) => window.setTimeout(resolve, 650));
        const statusResponse = await fetch(statusUrl, { method: "GET", cache: "no-store" });
        const statusText = await statusResponse.text();
        let statusPayload: unknown;
        try { statusPayload = JSON.parse(statusText); } catch { statusPayload = null; }
        if (!statusResponse.ok || !statusPayload || typeof statusPayload !== "object") {
          throw new Error(`Unable to read PCAP analysis progress (${statusResponse.status}).`);
        }
        const status = statusPayload as {
          status?: string;
          stage?: string;
          progress?: number | null;
          message?: string;
          detail?: string | null;
          elapsedSeconds?: number;
          result?: unknown;
        };
        setProgress({
          stage: status.stage || "analysis",
          progress: typeof status.progress === "number" ? status.progress : null,
          message: status.message || "Analyzing PCAP…",
          detail: status.detail ?? null,
          elapsedSeconds: typeof status.elapsedSeconds === "number" ? status.elapsedSeconds : undefined,
        });
        if (status.status === "canceled") throw new AnalysisCanceledError(status.message || "PCAP analysis canceled.");
        if (status.status === "failed") throw new Error(status.message || "PCAP analysis failed.");
        if (status.status === "completed") {
          const { report: normalized } = normalizeElevadrReport(status.result);
          setProgress({ stage: "loading-report", progress: 100, message: "Loading generated eleVADR report…", detail: normalized.report_id });
          onReportLoaded(normalized);
          return null;
        }
      }
    } catch (err) {
      const message = err instanceof AnalysisCanceledError ? err.message : err instanceof Error ? err.message : "Failed to analyze PCAP";
      if (!(err instanceof AnalysisCanceledError)) setError(message);
      return message;
    } finally {
      activeJobUrlRef.current = null;
      cancelRequestedRef.current = false;
      setIsAnalyzing?.(false);
    }
  };

  const processFile = async (file: File): Promise<void> => {
    if (isAnalyzing) return;
    setError(null); setProgress(null);
    const kind = getFileKind(file);
    if (!kind) {
      setSelectedFileName(null); setSelectedFileKind(null);
      setError("Unsupported file type. Choose a .pcap, .pcapng, or eleVADR .json report.");
      return;
    }
    setSelectedFileName(file.name); setSelectedFileKind(kind);
    if (kind === "json") {
      setLastPcapSession(null);
      setPendingPcap(null); setContextDiscovery(null); setZeekEvidenceToken(null); setZeekEvidencePcapSha256(null); setContextDialogOpen(false); await loadJsonReport(file); return;
    }
    setLastPcapSession(null);
    setZeekEvidenceToken(null);
    setZeekEvidencePcapSha256(null);
    setPendingPcap(file);
    try {
      const discovery = await discoverPcapContext(file);
      setContextDiscovery(discovery.scan);
      setZeekEvidenceToken(discovery.evidenceToken);
      setZeekEvidencePcapSha256(discovery.pcapSha256);
      setLastPcapSession({ file, evidenceToken: discovery.evidenceToken, pcapSha256: discovery.pcapSha256 });
      const stored = listProfiles();
      const active = loadActiveProfile();
      const nextId = stored.some((profile) => profile.id === active.id) ? active.id : stored[0]?.id || "";
      setSelectedProfileId(nextId);
      setContextDialogOpen(true);
      setProgress(null);
    } catch (err) {
      setPendingPcap(null);
      setContextDiscovery(null);
      setZeekEvidenceToken(null);
      setZeekEvidencePcapSha256(null);
      if (!(err instanceof AnalysisCanceledError)) setError(err instanceof Error ? err.message : "Failed to discover Detection Context from PCAP");
      else { setProgress(null); setSelectedFileName(null); setSelectedFileKind(null); }
    }
  };

  useEffect(() => {
    if (refreshRequestRevision === lastHandledRefreshRequestRef.current) return;
    lastHandledRefreshRequestRef.current = refreshRequestRevision;
    if (!refreshRequestRevision) return;
    if (!lastPcapSession) {
      onReanalysisStatus?.("unavailable", "The original packet capture is not available in this browser session. Reopen the PCAP to generate a report with the updated configuration.");
      return;
    }

    const profile = normalizeProfile(loadActiveProfile());
    onReanalysisStatus?.("started");
    void analyzePcap(lastPcapSession.file, profile, lastPcapSession.evidenceToken, lastPcapSession.pcapSha256)
      .then((analysisError) => {
        if (analysisError) onReanalysisStatus?.("failed", analysisError);
        else onReanalysisStatus?.("completed");
      });
  }, [refreshRequestRevision]);

  const cancelActiveAnalysis = async () => {
    const url = activeJobUrlRef.current;
    if (!url || cancelRequestedRef.current) return;
    cancelRequestedRef.current = true;
    setProgress((current) => ({
      stage: "canceling", progress: null, message: "Canceling analysis…", detail: current?.detail ?? null, elapsedSeconds: current?.elapsedSeconds,
    }));
    try {
      await fetch(url, { method: "DELETE" });
    } catch {
      cancelRequestedRef.current = false;
      setError("Unable to send the cancellation request. The analysis may still be running.");
    }
  };

  const handleFileInput = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]; if (file) void processFile(file); event.target.value = "";
  };
  const openFilePicker = () => { if (!isAnalyzing && !contextDialogOpen) inputRef.current?.click(); };
  const closeContextDialog = () => {
    setContextDialogOpen(false); setPendingPcap(null); setContextDiscovery(null); setZeekEvidenceToken(null); setZeekEvidencePcapSha256(null); setSelectedFileName(null); setSelectedFileKind(null);
  };
  const materializeSelectedProfile = (): DetectionConfigurationProfile | null => {
    if (!effectiveProfile) return null;
    const saved = saveProfile(normalizeProfile(effectiveProfile));
    activateProfile(saved.id);
    setProfileListRevision((value) => value + 1);
    return saved;
  };

  const startAnalysis = () => {
    if (!pendingPcap) return;
    const profile = materializeSelectedProfile();
    if (!profile) { setError("Create or select a Context before analyzing the PCAP."); return; }
    const file = pendingPcap;
    const evidenceToken = zeekEvidenceToken;
    const evidencePcapSha256 = zeekEvidencePcapSha256;
    setContextDialogOpen(false); setPendingPcap(null); setContextDiscovery(null);
    void analyzePcap(file, profile, evidenceToken, evidencePcapSha256);
  };

  const createNewDetectionContext = () => {
    const existingNames = new Set(profiles.map((profile) => profile.name.trim().toLowerCase()));
    let name = "New Context";
    let suffix = 2;
    while (existingNames.has(name.toLowerCase())) {
      name = `New Context ${suffix}`;
      suffix += 1;
    }
    const empty = { ...createEmptyProfile(), name };
    const populated = contextDiscovery ? mergeScanIntoProfile(empty, contextDiscovery) : empty;
    const created = saveProfile(populated);
    setSelectedProfileId(created.id);
    setProfileListRevision((value) => value + 1);
    onOpenDetectionContext?.();
  };

  const deleteSelectedDetectionContext = () => {
    if (!selectedProfile) return;
    const remaining = removeProfile(selectedProfile.id);
    const next = remaining[0] || null;
    setSelectedProfileId(next?.id || "");
    if (next) activateProfile(next.id);
    setProfileListRevision((value) => value + 1);
  };

  const editSelectedDetectionContext = () => {
    const profile = materializeSelectedProfile();
    if (!profile) { createNewDetectionContext(); return; }
    onOpenDetectionContext?.();
  };

  return <div className="upload-container">
    <div className={`file-picker-panel ${isAnalyzing ? "is-busy" : ""}`} role="button" tabIndex={isAnalyzing || contextDialogOpen ? -1 : 0}
      aria-disabled={isAnalyzing || contextDialogOpen} aria-label="Open a PCAP, PCAPNG, or JSON report" onClick={openFilePicker}
      onKeyDown={(event) => { if ((event.key === "Enter" || event.key === " ") && !isAnalyzing && !contextDialogOpen) { event.preventDefault(); openFilePicker(); } }}>
      <input ref={inputRef} id={inputId} className="file-picker-input" type="file" accept=".pcap,.pcapng,.json,application/json"
        aria-label="Open PCAP or JSON report" onChange={handleFileInput} disabled={isAnalyzing} />
      <div className="file-picker-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M12 16V4"/><path d="m7 9 5-5 5 5"/><path d="M5 20h14"/></svg></div>
      <div className="file-picker-copy"><strong>{isAnalyzing ? "Analyzing packet capture…" : "Open a report or packet capture"}</strong>
        <span>{isAnalyzing ? progress?.message ?? "Preparing analysis…" : "Choose a PCAP, PCAPNG, or eleVADR JSON report to open."}</span>
        <div className="file-picker-types" aria-hidden="true"><span>PCAP</span><span>PCAPNG</span><span>JSON</span></div></div>
      {!isAnalyzing && <button type="button" className="file-picker-button" onClick={(event) => { event.stopPropagation(); openFilePicker(); }}>Choose file</button>}
    </div>

    {selectedFileName && <div className="selected-file-status" aria-live="polite">
      <span className={`selected-file-kind ${selectedFileKind ?? ""}`}>{selectedFileKind === "pcap" ? "Packet capture" : "JSON report"}</span>
      <strong>{selectedFileName}</strong>
      {report && !isAnalyzing && <span className="report-source-meta"><b>Report ID</b> {report.report_id}</span>}
      {(error || (selectedFileKind === "pcap" && isAnalyzing) || (selectedFileKind === "pcap" && contextDialogOpen)) &&
        <span>{error ? "Could not load" : isAnalyzing ? "Analysis in progress" : "Awaiting Context"}</span>}
    </div>}

    {isAnalyzing && <div className="upload-status" aria-live="polite"><div className="upload-progress-row">
      <div className="upload-progress-copy"><p className="loading-text">{progress?.message ?? "Starting analysis…"}</p>
        {progress?.detail && <p className="progress-detail">{progress.detail}</p>}</div>
      <p className="progress-percent">{progress?.progress !== null && progress?.progress !== undefined
        ? `${progress.progress}%`
        : progress?.elapsedSeconds !== undefined ? `${Math.floor(progress.elapsedSeconds / 60)}:${String(Math.floor(progress.elapsedSeconds % 60)).padStart(2, "0")}` : "Working"}</p></div>
      <div className={`progress-bar-track ${progress?.progress == null ? "is-indeterminate" : ""}`} role="progressbar" aria-valuemin={0} aria-valuemax={100}
        {...(progress?.progress == null ? {} : { "aria-valuenow": progress.progress })}>
        <div className="progress-bar-fill" style={progress?.progress == null ? undefined : { width: `${progress.progress}%` }} /></div>
      <div className="analysis-running-actions"><button type="button" className="analysis-module-cancel" onClick={() => void cancelActiveAnalysis()} disabled={cancelRequestedRef.current}>Cancel analysis</button></div></div>}

    {error && <div className="error-container" role="alert"><p className="error-text">Unable to open file</p><p className="error-details">{error}</p></div>}

    {contextDialogOpen && pendingPcap && <div className="analysis-module-backdrop" role="presentation"><div className="analysis-module-dialog" role="dialog" aria-modal="true" aria-labelledby="pcap-context-title">
      <div className="analysis-module-header"><div><span className="analysis-module-eyebrow">Packet Capture Analysis</span>
        <h2 id="pcap-context-title">Choose Context</h2>
        <p>Zeek evidence has been extracted once from <strong>{pendingPcap.name}</strong>. Choose a Context; observed assets, segments, infrastructure, and communications will prepopulate it, and the same retained Zeek evidence will be reused for detector analysis.</p></div>
        <button type="button" className="analysis-module-close" onClick={closeContextDialog} aria-label="Cancel PCAP analysis">×</button></div>
      {effectiveProfile && <section className="analysis-module-selection-summary" aria-label="Detection module selection summary">
        <div className="analysis-module-section-heading">
          <span className="analysis-module-section-title">Module Selection</span>
          {onOpenDetectionModules && <button type="button" className="analysis-section-edit" onClick={onOpenDetectionModules} aria-label="Edit Modules" title="Edit Modules">
            <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 20h4l11-11-4-4L4 16v4Z"/><path d="m13.5 6.5 4 4"/></svg>
          </button>}
        </div>
        <div><strong>{effectiveProfile.selectedModules.length} of {ALL_DETECTION_MODULES.length}</strong><span>detection modules selected for this context</span></div>
      </section>}
      <div className="analysis-module-toolbar"><div className="context-profile-picker">
        <div className="analysis-module-section-heading">
          <span className="analysis-module-section-title">Context Profile</span>
          {onOpenDetectionContext && <button type="button" className="analysis-section-edit" onClick={editSelectedDetectionContext} aria-label={effectiveProfile ? "Edit Context" : "Create Context"} title={effectiveProfile ? "Edit Context" : "Create Context"}>
            <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 20h4l11-11-4-4L4 16v4Z"/><path d="m13.5 6.5 4 4"/></svg>
          </button>}
        </div>
        <div className="context-profile-select-row"><select value={selectedProfile?.id || ""} onChange={(e) => {
          if (e.target.value === "__new__") { createNewDetectionContext(); return; }
          setSelectedProfileId(e.target.value); activateProfile(e.target.value);
        }}>
          {!profiles.length && <option value="" disabled>Select or create a Context</option>}
          {profiles.map((profile) => <option key={profile.id} value={profile.id}>{profile.name}</option>)}
          <option value="__new__">+ New Context</option>
        </select>
        {selectedProfile && <button type="button" className="context-profile-delete" onClick={deleteSelectedDetectionContext} aria-label={`Delete ${selectedProfile.name}`} title={`Delete ${selectedProfile.name}`}>×</button>}</div>
      </div></div>
      {effectiveProfile ? <div className="analysis-module-note"><strong>{effectiveProfile.name}</strong> · {effectiveProfile.assets.length} assets · {effectiveProfile.segments.length} segments · {effectiveProfile.communicationPairs.length} observed pairs. Observed facts from the retained Zeek evidence have been applied; policy choices remain yours. Analyze PCAP will reuse the same evidence without running Zeek again.</div>
        : <div className="analysis-module-note"><strong>No saved Context.</strong> Choose <em>+ New Context</em> to create one prepopulated with observations from this PCAP.</div>}
      <div className="analysis-module-actions"><button type="button" className="analysis-module-cancel" onClick={closeContextDialog}>Cancel</button>
        <button type="button" className="analysis-module-run" onClick={startAnalysis} disabled={!effectiveProfile} title={!effectiveProfile ? "Create or select a Context before analyzing this PCAP." : "Analyze this PCAP using the selected Context and detection modules."}>Analyze PCAP</button></div>
    </div></div>}
  </div>;
};

export default UploadForm;
