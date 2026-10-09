import React, { useEffect, useRef, useState } from "react";
import "./ReportCustomization.css";

export type ReportSectionId =
  | "overview"
  | "findings"
  | "devices"
  | "services"
  | "connections"
  | "topology";

export interface ReportSectionOption {
  id: ReportSectionId;
  label: string;
  description: string;
  sensitive?: boolean;
}

export const REPORT_SECTION_OPTIONS: ReportSectionOption[] = [
  {
    id: "overview",
    label: "Summary",
    description:
      "Executive summary, report provenance, and high-level security overview.",
  },
  {
    id: "findings",
    label: "Findings",
    description: "Prioritized detector and report-derived findings.",
  },
  {
    id: "devices",
    label: "Devices",
    description:
      "Asset inventory, classifications, addresses, and related device details.",
    sensitive: true,
  },
  {
    id: "services",
    label: "Services",
    description:
      "Observed services, service counts, and service-risk information.",
  },
  {
    id: "topology",
    label: "Topology",
    description: "Observed network graph and investigation workspace.",
    sensitive: true,
  },
  {
    id: "connections",
    label: "Connections",
    description:
      "Observed flows, topology, timing, segmentation, and external communications.",
    sensitive: true,
  },
];

interface Props {
  open: boolean;
  visibleSections: Set<ReportSectionId>;
  onSave: (sections: Set<ReportSectionId>) => void;
  onClose: () => void;
  onExportFull: () => void;
}

const ReportCustomization: React.FC<Props> = ({
  open,
  visibleSections,
  onSave,
  onClose,
  onExportFull,
}) => {
  const dialogRef = useRef<HTMLElement | null>(null);
  const [draft, setDraft] = useState<Set<ReportSectionId>>(
    new Set(visibleSections),
  );

  useEffect(() => {
    if (!open) return;
    setDraft(new Set(visibleSections));
  }, [open, visibleSections]);

  useEffect(() => {
    if (!open) return;
    const root = dialogRef.current;
    if (!root) return;
    const focusable = () =>
      Array.from(
        root.querySelectorAll<HTMLElement>(
          'button:not([disabled]),input:not([disabled]),[tabindex]:not([tabindex="-1"])',
        ),
      );
    window.setTimeout(() => focusable()[0]?.focus(), 0);
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        onClose();
        return;
      }
      if (event.key !== "Tab") return;
      const items = focusable();
      if (!items.length) return;
      const first = items[0];
      const last = items[items.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      }
      if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    root.addEventListener("keydown", onKeyDown);
    return () => root.removeEventListener("keydown", onKeyDown);
  }, [open, onClose]);

  if (!open) return null;

  const toggle = (id: ReportSectionId) => {
    setDraft((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const changed = REPORT_SECTION_OPTIONS.some(
    (section) => draft.has(section.id) !== visibleSections.has(section.id),
  );

  return (
    <div
      className="report-customization-backdrop"
      role="presentation"
      onMouseDown={(event) => {
        if (event.currentTarget === event.target) onClose();
      }}
    >
      <section
        ref={dialogRef}
        className="report-customization-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="report-customization-title"
        aria-describedby="report-customization-description"
      >
        <header className="report-customization-header">
          <div>
            <span className="report-customization-eyebrow">Report output</span>
            <h2 id="report-customization-title">Customize</h2>
            <p id="report-customization-description">
              Choose which report sections are visible and included in print,
              shared-view links, and filtered JSON exports. The original report
              data is not modified.
            </p>
          </div>
          <button
            type="button"
            className="report-customization-close"
            onClick={onClose}
            aria-label="Close report customization"
          >
            ×
          </button>
        </header>

        <div className="report-customization-summary">
          <strong>{draft.size}</strong>
          <span>
            of {REPORT_SECTION_OPTIONS.length} report sections included
          </span>
        </div>

        <div className="report-customization-toolbar">
          <button
            type="button"
            onClick={() =>
              setDraft(
                new Set(REPORT_SECTION_OPTIONS.map((section) => section.id)),
              )
            }
          >
            Show all
          </button>
          <button
            type="button"
            onClick={() => setDraft(new Set<ReportSectionId>())}
          >
            Clear
          </button>
          <span>
            Sections marked sensitive may contain asset, address, or
            communications details.
          </span>
        </div>

        <div
          className="report-customization-list"
          role="group"
          aria-label="Report sections"
        >
          {REPORT_SECTION_OPTIONS.map((section) => {
            const checked = draft.has(section.id);
            return (
              <label
                key={section.id}
                className={`report-customization-row ${checked ? "is-selected" : "is-unselected"}`}
              >
                <input
                  type="checkbox"
                  checked={checked}
                  onChange={() => toggle(section.id)}
                />
                <span className="report-customization-check" aria-hidden="true">
                  {checked ? "✓" : ""}
                </span>
                <span className="report-customization-copy">
                  <span className="report-customization-name">
                    {section.label}
                    {section.sensitive && (
                      <span className="report-sensitive-tag">
                        Potentially sensitive
                      </span>
                    )}
                  </span>
                  <span>{section.description}</span>
                </span>
              </label>
            );
          })}
        </div>

        <div className="report-customization-note">
          Filtered JSON exports are clearly marked as derivatives and list the
          included/excluded sections. Hiding a section never deletes it from the
          source report.
        </div>

        <footer className="report-customization-footer">
          <button type="button" onClick={onExportFull}>
            Export full JSON
          </button>
          <div>
            <button type="button" onClick={onClose}>
              Cancel
            </button>
            <button
              type="button"
              className="report-customization-save"
              onClick={() => onSave(draft)}
              disabled={!changed || draft.size === 0}
            >
              Save view
            </button>
          </div>
        </footer>
      </section>
    </div>
  );
};

export default ReportCustomization;
