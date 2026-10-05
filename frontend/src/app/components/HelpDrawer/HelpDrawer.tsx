import React, { useEffect, useMemo, useState } from "react";
import type { ElevadrReport } from "../../types/Report";
import "./HelpDrawer.css";

type HelpTab = "start" | "glossary" | "diagnostics";

interface Props {
  isOpen: boolean;
  onClose: () => void;
  report?: ElevadrReport | null;
  isAnalyzing?: boolean;
  onStartTour?: () => void;
  onOpenContext?: () => void;
  onOpenModules?: () => void;
}

const terms: Array<[string, string]> = [
  ["Analysis Context", "Site knowledge and analyst-supplied policy used to interpret packet evidence. Context can affect detector scope, authorization, and suppression decisions."],
  ["Authoritative", "A value treated as trusted site policy because it was explicitly supplied, confirmed, or imported by the analyst rather than merely observed in traffic."],
  ["Baseline", "A learned period or set of observations used to establish expected behavior before looking for later changes."],
  ["CIP", "Common Industrial Protocol, used by EtherNet/IP. eleVADR can inspect CIP service behavior such as tag writes and session activity."],
  ["Detection module", "An individual eleVADR detector that evaluates packet-derived evidence and Analysis Context for a specific behavior or policy condition."],
  ["Finding", "A prioritized interpretation of evidence produced by a detection module. Findings should be validated against the site's known architecture and approved behavior."],
  ["Inferred", "A value suggested by eleVADR from observed evidence. Inferred values require analyst review and are not equivalent to explicit site policy."],
  ["Observed", "A fact derived from the PCAP or Zeek logs. Observation alone does not imply that the behavior is trusted, approved, or authorized."],
  ["Policy", "An Analysis Context value that can directly influence detector behavior, such as trusted infrastructure, approved destinations, or explicit control authorization."],
  ["Purdue level", "A logical level in the Purdue Enterprise Reference Architecture used to describe where systems sit between field/control and enterprise environments."],
  ["Provenance", "Information showing where evidence or a conclusion came from, including Zeek log type, fields, packet-derived observations, Analysis Context, and detector logic."],
  ["Zeek UID", "A Zeek connection identifier used to correlate records that describe the same network conversation across supported logs."],
  ["OT device", "Operational technology equipment or systems that monitor or control physical processes."],
  ["Network device", "A device positioned between network segments, such as a firewall, router, gateway, or similar transit system."],
  ["Risk-tagged service", "A detected network service associated with one or more risk categories in the eleVADR report."],
  ["Cross-segment communication", "Traffic observed between different network segments. It may be expected, but unexpected paths can indicate segmentation weaknesses."],
  ["Suspicious outbound", "Outbound communication that met eleVADR's suspicious-connection criteria and deserves validation."],
  ["Connection success", "The proportion of observed connections that completed successfully according to the report evidence."],
  ["Topology", "A relationship view showing detected devices as nodes and observed communications or services as links."],
  ["Trusted infrastructure", "DNS, NTP, DHCP, management, or similar systems explicitly trusted by site policy. Merely observing a host provide a service does not make it trusted."],
  ["Control authorization", "Explicit permission for scoped control-changing OT behavior. Authorization should be narrow by source, destination, protocol, operation, and function code."],
  ["False positive", "A finding where the detector correctly matched its rule, but the behavior is legitimate for the site after analyst validation."],
];

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

const HelpDrawer: React.FC<Props> = ({
  isOpen,
  onClose,
  report = null,
  isAnalyzing = false,
  onStartTour,
  onOpenContext,
  onOpenModules,
}) => {
  const [tab, setTab] = useState<HelpTab>("start");
  const [query, setQuery] = useState("");
  const [copyStatus, setCopyStatus] = useState("");
  const filtered = useMemo(() => terms.filter(([term, definition]) => `${term} ${definition}`.toLowerCase().includes(query.trim().toLowerCase())), [query]);

  useEffect(() => {
    if (!isOpen) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const provenance = asRecord(report?.arch_insights?.analysis_provenance);
  const diagnostics: Array<[string, string]> = [
    ["Report loaded", report ? "Yes" : "No"],
    ["Analysis status", isAnalyzing ? "Analysis in progress" : "Idle"],
    ["Report version", report?.report_version || "No report loaded"],
    ["Report ID", report?.report_id || "No report loaded"],
    ["Source type", String(provenance?.source_type || "Unknown")],
    ["Source filename", String(provenance?.source_filename || "Unknown")],
    ["Analysis Context", String(provenance?.detection_context_profile_name || "Unknown")],
    ["Zeek runtime", String(provenance?.zeek_runtime || "Unknown")],
    ["Detector completion", provenance ? `${String(provenance.detector_modules_completed ?? "Unknown")}/${String(provenance.detector_modules_requested ?? "Unknown")}` : "Unknown"],
    ["Browser", navigator.userAgent],
    ["Online", navigator.onLine ? "Yes" : "No"],
    ["Path", window.location.pathname],
  ];

  const copyDiagnostics = async () => {
    const text = ["eleVADR diagnostics", ...diagnostics.map(([label, value]) => `${label}: ${value}`)].join("\n");
    try {
      await navigator.clipboard.writeText(text);
      setCopyStatus("Copied");
    } catch {
      setCopyStatus("Copy unavailable");
    }
    window.setTimeout(() => setCopyStatus(""), 1800);
  };

  const launchAndClose = (action?: () => void) => {
    if (!action) return;
    onClose();
    action();
  };

  return <>
    <button className="help-backdrop" aria-label="Close help" onClick={onClose} />
    <aside className="help-drawer" role="dialog" aria-modal="true" aria-labelledby="help-title">
      <div className="help-head">
        <div><p>eleVADR Help Center</p><h2 id="help-title">Help and support</h2></div>
        <button type="button" onClick={onClose} aria-label="Close help">×</button>
      </div>

      <nav className="help-tabs" aria-label="Help Center sections">
        <button type="button" className={tab === "start" ? "active" : ""} aria-pressed={tab === "start"} onClick={() => setTab("start")}>Getting started</button>
        <button type="button" className={tab === "glossary" ? "active" : ""} aria-pressed={tab === "glossary"} onClick={() => setTab("glossary")}>Glossary</button>
        <button type="button" className={tab === "diagnostics" ? "active" : ""} aria-pressed={tab === "diagnostics"} onClick={() => setTab("diagnostics")}>Diagnostics</button>
      </nav>

      {tab === "start" && <div className="help-section">
        <div className="help-intro">Use this guide for the normal eleVADR workflow. Help remains available before and after a report is loaded.</div>
        <div className="help-workflow" aria-label="eleVADR workflow">
          <article><span>1</span><div><h3>Open a PCAP or report</h3><p>PCAP/PCAPNG files enter the analysis workflow. Existing eleVADR JSON reports open directly in the report viewer.</p></div></article>
          <article><span>2</span><div><h3>Review Analysis Context</h3><p>Confirm site facts and policy that traffic alone cannot prove. Observed traffic is evidence, not authorization.</p></div></article>
          <article><span>3</span><div><h3>Review detection modules</h3><p>Confirm the selected modules and use each module's standardized help to understand inputs, logic, thresholds, context influence, and false positives.</p></div></article>
          <article><span>4</span><div><h3>Investigate findings</h3><p>Use <strong>Why flagged?</strong> to follow the observation → detector rule → Analysis Context → conclusion decision path before validating the detailed evidence.</p></div></article>
          <article><span>5</span><div><h3>Pivot through the network</h3><p>Use devices, services, connections, filters, and topology to follow related evidence without losing the report-level context.</p></div></article>
          <article><span>6</span><div><h3>Document and export</h3><p>Add analyst notes or reviewed overrides, customize report sections, then share, print, or export the derivative report.</p></div></article>
        </div>
        <div className="help-actions" aria-label="Help shortcuts">
          <button type="button" onClick={() => launchAndClose(onOpenContext)}>Open Analysis Context</button>
          <button type="button" onClick={() => launchAndClose(onOpenModules)}>Open detection modules</button>
          <button type="button" disabled={!report || !onStartTour} title={!report ? "Load a report before starting the report walkthrough." : undefined} onClick={() => launchAndClose(onStartTour)}>Replay report walkthrough</button>
        </div>
        {!report && <p className="help-note">The report walkthrough becomes available after a report is loaded. Analysis Context, module help, glossary, and diagnostics remain available now.</p>}
      </div>}

      {tab === "glossary" && <div className="help-section">
        <div className="help-intro">Search eleVADR, OT, Zeek, and Analysis Context terminology. Definitions describe how the terms are used in this application.</div>
        <label className="help-search"><span>Search glossary</span><input autoFocus value={query} onChange={event => setQuery(event.target.value)} placeholder="e.g. authorization, Zeek UID, Purdue" /></label>
        <div className="help-terms">{filtered.map(([term, definition]) => <article key={term}><h3>{term}</h3><p>{definition}</p></article>)}{!filtered.length && <p className="help-empty">No glossary terms match that search.</p>}</div>
      </div>}

      {tab === "diagnostics" && <div className="help-section">
        <div className="help-intro">Use these details when troubleshooting or reporting a problem. Diagnostics describe the viewer and loaded report state; they do not include raw packet contents.</div>
        <div className="help-diagnostics" role="list">{diagnostics.map(([label, value]) => <div key={label} role="listitem"><span>{label}</span><strong>{value}</strong></div>)}</div>
        <div className="help-diagnostic-actions"><button type="button" onClick={copyDiagnostics}>Copy diagnostics</button><span role="status" aria-live="polite">{copyStatus}</span></div>
        <section className="help-support-note"><h3>When asking for support</h3><p>Include the copied diagnostics, the action you were performing, the visible error message, and whether the issue reproduces with another report or capture. Do not share sensitive PCAPs or report data unless your handling requirements permit it.</p></section>
      </div>}
    </aside>
  </>;
};

export default HelpDrawer;
