import React, { useEffect, useMemo, useRef, useState } from "react";
import "./DetectionModuleSelector.css";
import { ALL_DETECTION_MODULES } from "../DetectionConfiguration/moduleCatalog";
import { DETECTION_MODULE_DETAILS } from "../DetectionConfiguration/moduleDetails";
import { DETECTION_MODULE_REFERENCES } from "../DetectionConfiguration/moduleReferences";
import type { DetectionModuleDetail } from "../DetectionConfiguration/moduleDetails";
import { standardizedModuleHelp } from "../DetectionConfiguration/moduleHelp";
import { loadActiveProfile, moduleReadiness, saveProfile } from "../DetectionConfiguration/profile";
import { DetectionConfigurationProfile, ModuleReadinessItem } from "../DetectionConfiguration/types";

interface Props {
  open: boolean;
  onClose: (changed?: boolean) => void;
  onOpenDetectionContext: () => void;
}

type StatusFilter = "all" | "ready" | "needs-context" | "selected";
type SortMode = "name-asc" | "name-desc" | "ready-first" | "needs-context-first";

const DetectionModuleSelector: React.FC<Props> = ({ open, onClose, onOpenDetectionContext }) => {
  const dialogRef = useRef<HTMLElement | null>(null);
  const [profile, setProfile] = useState<DetectionConfigurationProfile>(() => loadActiveProfile());
  const [selected, setSelected] = useState<Set<string>>(() => new Set(loadActiveProfile().selectedModules));
  const [initialSelection, setInitialSelection] = useState<string>("");
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<StatusFilter>("all");
  const [sortMode, setSortMode] = useState<SortMode>("name-asc");
  const [status, setStatus] = useState("");
  const [detailModuleId, setDetailModuleId] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    const active = loadActiveProfile();
    const next = new Set(active.selectedModules);
    setProfile(active);
    setSelected(next);
    setInitialSelection([...next].sort().join("\n"));
    setQuery("");
    setFilter("all");
    setSortMode("name-asc");
    setStatus("");
    setDetailModuleId(null);
  }, [open]);

  const allReadiness = useMemo(() => {
    const withAllModules = { ...profile, selectedModules: [...ALL_DETECTION_MODULES] };
    const map = new Map<string, ModuleReadinessItem>();
    moduleReadiness(withAllModules).forEach((item) => map.set(item.id, item));
    return map;
  }, [profile]);

  const rows = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return ALL_DETECTION_MODULES
      .map((id) => allReadiness.get(id))
      .filter((item): item is ModuleReadinessItem => Boolean(item))
      .filter((item) => {
        const isSelected = selected.has(item.id);
        if (filter === "ready" && !item.contextComplete) return false;
        if (filter === "needs-context" && item.contextComplete) return false;
        if (filter === "selected" && !isSelected) return false;
        if (!needle) return true;
        return item.label.toLowerCase().includes(needle)
          || item.id.toLowerCase().includes(needle)
          || item.detail.toLowerCase().includes(needle);
      })
      .sort((a, b) => {
        if (sortMode === "name-desc") return b.label.localeCompare(a.label);
        if (sortMode === "ready-first" && a.contextComplete !== b.contextComplete) return a.contextComplete ? -1 : 1;
        if (sortMode === "needs-context-first" && a.contextComplete !== b.contextComplete) return a.contextComplete ? 1 : -1;
        return a.label.localeCompare(b.label);
      });
  }, [allReadiness, filter, query, selected, sortMode]);

  const readyCount = useMemo(() => [...allReadiness.values()].filter((item) => item.contextComplete).length, [allReadiness]);
  const needsContextCount = ALL_DETECTION_MODULES.length - readyCount;
  const changed = [...selected].sort().join("\n") !== initialSelection;
  const detailModule: DetectionModuleDetail | null = detailModuleId ? DETECTION_MODULE_DETAILS[detailModuleId] || null : null;
  const detailReadiness = detailModuleId ? allReadiness.get(detailModuleId) || null : null;
  const detailReferences = detailModuleId ? DETECTION_MODULE_REFERENCES[detailModuleId] || [] : [];
  const detailHelp = detailModule && detailReadiness ? standardizedModuleHelp(detailModule, detailReadiness.detail) : null;

  useEffect(() => {
    if (!open) return;
    const root = dialogRef.current;
    if (!root) return;
    const focusable = () => Array.from(root.querySelectorAll<HTMLElement>('button:not([disabled]),input:not([disabled]),select:not([disabled]),[tabindex]:not([tabindex="-1"])'));
    window.setTimeout(() => focusable()[0]?.focus(), 0);
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        if (detailModuleId) {
          setDetailModuleId(null);
        } else {
          onClose(false);
        }
        return;
      }
      if (event.key !== "Tab") return;
      const scope = detailModuleId ? root.querySelector<HTMLElement>(".module-detail-dialog") : root;
      const items = Array.from((scope || root).querySelectorAll<HTMLElement>('button:not([disabled]),input:not([disabled]),select:not([disabled]),[tabindex]:not([tabindex="-1"])'));
      if (!items.length) return;
      const first = items[0];
      const last = items[items.length - 1];
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    };
    root.addEventListener("keydown", onKeyDown);
    return () => root.removeEventListener("keydown", onKeyDown);
  }, [detailModuleId, open, onClose]);

  if (!open) return null;

  const toggle = (id: string) => {
    setSelected((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
    setStatus("");
  };

  const persistSelection = (): boolean => {
    if (!selected.size) {
      setStatus("Select at least one detection module before saving.");
      return false;
    }
    if (changed) {
      const ordered = ALL_DETECTION_MODULES.filter((id) => selected.has(id));
      saveProfile({ ...profile, selectedModules: ordered });
    }
    return true;
  };

  const save = () => {
    if (!persistSelection()) return;
    onClose(changed);
  };

  const openDetectionContext = () => {
    if (selected.size && changed) persistSelection();
    onOpenDetectionContext();
  };

  const selectReady = () => setSelected(new Set([...allReadiness.values()].filter((item) => item.contextComplete).map((item) => item.id)));

  return (
    <div className="module-selector-backdrop" role="presentation" onMouseDown={(event) => { if (event.currentTarget === event.target) onClose(false); }}>
      <section ref={dialogRef} className="module-selector-dialog" role="dialog" aria-modal="true" aria-labelledby="module-selector-title" aria-describedby="module-selector-description">
        <header className="module-selector-header">
          <div>
            <span className="module-selector-eyebrow">Analysis setup</span>
            <h2 id="module-selector-title">Modules</h2>
            <p id="module-selector-description">Choose which detectors will run. Readiness reflects whether the active Context contains the site-specific details each module uses.</p>
          </div>
          <button type="button" className="module-selector-close" onClick={() => onClose(false)} aria-label="Close modules">×</button>
        </header>

        <div className="module-selector-summary" aria-label="Detection module readiness summary">
          <div><strong>{selected.size}</strong><span>Selected</span></div>
          <div className="is-ready"><strong>{readyCount}</strong><span>Ready</span></div>
          <div className="needs-context"><strong>{needsContextCount}</strong><span>Needs context</span></div>
          <div><strong>{ALL_DETECTION_MODULES.length}</strong><span>Available</span></div>
        </div>

        <div className="module-selector-legend" aria-label="Readiness legend">
          <span><i className="legend-dot ready" />Ready — required site context is present</span>
          <span><i className="legend-dot warning" />Needs context — module can run, but site-specific information is missing</span>
        </div>

        <div className="module-selector-toolbar">
          <label className="module-selector-search">
            <span className="sr-only">Search modules</span>
            <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search modules…" />
          </label>
          <select value={filter} onChange={(event) => setFilter(event.target.value as StatusFilter)} aria-label="Filter modules">
            <option value="all">All modules</option>
            <option value="selected">Selected only</option>
            <option value="ready">Ready</option>
            <option value="needs-context">Needs context</option>
          </select>
          <select value={sortMode} onChange={(event) => setSortMode(event.target.value as SortMode)} aria-label="Sort modules">
            <option value="name-asc">Name A–Z</option>
            <option value="name-desc">Name Z–A</option>
            <option value="ready-first">Ready first</option>
            <option value="needs-context-first">Needs context first</option>
          </select>
          <div className="module-selector-bulk-actions">
            <button type="button" onClick={() => setSelected(new Set(ALL_DETECTION_MODULES))}>Select all</button>
            <button type="button" onClick={selectReady}>Select ready</button>
            <button type="button" onClick={() => setSelected(new Set())}>Clear</button>
          </div>
        </div>

        <div className="module-selector-list" role="list" aria-label="Available modules">
          {rows.map((item) => {
            const isSelected = selected.has(item.id);
            return (
              <div key={item.id} className={`module-selector-row ${item.contextComplete ? "is-ready" : "needs-context"} ${isSelected ? "is-selected" : "is-unselected"}`} role="listitem">
                <label className="module-selector-choice">
                  <input type="checkbox" checked={isSelected} onChange={() => toggle(item.id)} />
                  <span className="module-selector-check" aria-hidden="true">{isSelected ? "✓" : ""}</span>
                  <span className="module-selector-copy">
                    <span className="module-selector-name">{item.label}</span>
                    <span className="module-selector-id">{item.id}</span>
                    <span className="module-selector-detail">{item.detail}</span>
                  </span>
                </label>
                <span className="module-selector-row-actions">
                  <span className={`module-selector-status ${item.contextComplete ? "ready" : "warning"}`}>
                    {item.contextComplete ? "Ready" : "Needs context"}
                  </span>
                  <button
                    type="button"
                    className="module-selector-details-button"
                    onClick={() => setDetailModuleId(item.id)}
                    aria-label={`View details for ${item.label}`}
                  >
                    Details
                  </button>
                </span>
              </div>
            );
          })}
          {!rows.length && <div className="module-selector-empty">No modules match the current search/filter.</div>}
        </div>


        {detailModule && detailReadiness && (
          <div className="module-detail-backdrop" role="presentation" onMouseDown={(event) => { if (event.currentTarget === event.target) setDetailModuleId(null); }}>
            <section className="module-detail-dialog" role="dialog" aria-modal="true" aria-labelledby="module-detail-title" aria-describedby="module-detail-description">
              <header className="module-detail-header">
                <div>
                  <span className="module-selector-eyebrow">Module details</span>
                  <h3 id="module-detail-title">{detailModule.name}</h3>
                  <p id="module-detail-description">{detailModule.id}</p>
                </div>
                <button type="button" className="module-selector-close" onClick={() => setDetailModuleId(null)} aria-label="Close module details">×</button>
              </header>

              <div className="module-detail-body">
                <div className="module-detail-readiness">
                  <span className={`module-selector-status ${detailReadiness.contextComplete ? "ready" : "warning"}`}>
                    {detailReadiness.contextComplete ? "Ready" : "Needs context"}
                  </span>
                  <span>{selected.has(detailModule.id) ? "Selected for analysis" : "Not selected for analysis"}</span>
                </div>

                {detailHelp && (
                  <div className="module-help-standard" aria-label="Standardized module help">
                    <p className="module-help-audit-note">
                      <strong>Implementation-backed:</strong> purpose, inputs, detection logic, exposed settings, and Context influence are checked against the detector catalog and policy schema.
                      <span> Typical scenarios, false positives, and validation steps are analyst guidance and do not change detector logic.</span>
                    </p>
                    <section className="module-detail-section">
                      <h4>Purpose</h4>
                      <p>{detailModule.relevance}</p>
                    </section>

                    <section className="module-detail-section">
                      <h4>Inputs</h4>
                      <ul>{detailHelp.inputs.map((item) => <li key={item}>{item}</li>)}</ul>
                    </section>

                    <section className="module-detail-section">
                      <h4>Detection logic</h4>
                      <p>{detailHelp.detectionLogic}</p>
                    </section>

                    <section className="module-detail-section">
                      <h4>Thresholds and tunable settings</h4>
                      <ul>{detailHelp.thresholds.map((item) => <li key={item}>{item}</li>)}</ul>
                    </section>

                    <section className="module-detail-section">
                      <h4>Detection Context influence</h4>
                      <ul>{detailHelp.contextInfluence.map((item) => <li key={item}>{item}</li>)}</ul>
                    </section>

                    <section className="module-detail-section">
                      <h4>Typical true positive</h4>
                      <p>{detailHelp.truePositiveExample}</p>
                    </section>

                    <section className="module-detail-section">
                      <h4>Potential false positives</h4>
                      <ul>{detailHelp.falsePositiveExamples.map((item) => <li key={item}>{item}</li>)}</ul>
                    </section>

                    <section className="module-detail-section">
                      <h4>Analyst validation</h4>
                      <ol>{detailHelp.validationSteps.map((item) => <li key={item}>{item}</li>)}</ol>
                    </section>
                  </div>
                )}

                <section className="module-detail-section">
                  <h4>Learn more</h4>
                  <p className="module-detail-reference-intro">External references that explain the protocol, behavior, or security concept behind this detector.</p>
                  <ul className="module-detail-reference-list">
                    {detailReferences.map((reference) => (
                      <li key={reference.url}>
                        <a href={reference.url} target="_blank" rel="noopener noreferrer">
                          <span>{reference.title}</span>
                          <small>{reference.source}</small>
                          <span className="module-detail-external-icon" aria-hidden="true">↗</span>
                        </a>
                      </li>
                    ))}
                  </ul>
                </section>


              </div>

              <footer className="module-detail-footer">
                {!detailReadiness.contextComplete && (
                  <button type="button" onClick={() => { setDetailModuleId(null); openDetectionContext(); }}>Edit Context</button>
                )}
                <button type="button" className="module-detail-close-button" onClick={() => setDetailModuleId(null)}>Close</button>
              </footer>
            </section>
          </div>
        )}

        <footer className="module-selector-footer">
          <div>
            {status && <p className="module-selector-error" role="alert">{status}</p>}
            <button type="button" className="module-selector-context-button" onClick={openDetectionContext}>Edit Context</button>
          </div>
          <div className="module-selector-footer-actions">
            <button type="button" onClick={() => onClose(false)}>Cancel</button>
            <button type="button" className="module-selector-save" onClick={save} disabled={!changed || selected.size === 0}>Save</button>
          </div>
        </footer>
      </section>
    </div>
  );
};

export default DetectionModuleSelector;
