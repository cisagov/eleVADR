import React, { useMemo } from "react";
import "./ExecutiveSummary.css";
import { ElevadrReport } from "../../types/Report";
import { InvestigationFilter, SelectedEntity } from "../../types/Investigation";
import { deriveFindings } from "../FindingsPanel/FindingsPanel";
import Panel from "../Panel/Panel";
import PivotValue from "../PivotValue/PivotValue";

interface ExecutiveSummaryProps {
  report: ElevadrReport;
  filters?: InvestigationFilter[];
  onFilter?: (filter: InvestigationFilter) => void;
  onSelect?: (entity: SelectedEntity) => void;
}

const ExecutiveSummary: React.FC<ExecutiveSummaryProps> = ({ report, filters = [], onFilter, onSelect }) => {
  const findings = useMemo(
    () => deriveFindings(report).filter((finding) => finding.severity === "critical" || finding.severity === "high"),
    [report],
  );

  const openFinding = (findingId: string) => {
    onSelect?.({ type: "finding", id: findingId });
  };

  const filterFindingEntity = (filter: InvestigationFilter) => {
    onFilter?.(filter);
    window.setTimeout(() => document.getElementById("findings")?.scrollIntoView({ behavior: "smooth", block: "start" }), 0);
  };

  return (
    <Panel id="summary-high-priority-findings" title="High-Priority Findings">
      <section className="priority-findings" aria-label="High-Priority Findings">
        <div className="priority-findings-toolbar">
          <span className="priority-findings-kicker">Triage</span>
          {findings.length > 0 && (
            <button
              type="button"
              className="priority-findings-count"
              onClick={() => document.getElementById("findings")?.scrollIntoView({ behavior: "smooth", block: "start" })}
            >
              {findings.length} {findings.length === 1 ? "finding" : "findings"} · View all
            </button>
          )}
        </div>

        {findings.length === 0 ? (
          <div className="executive-summary-empty">No High or Critical findings were reported.</div>
        ) : (
          <div className="priority-findings-list">
            {findings.slice(0, 6).map((finding) => (
              <article className={`priority-finding priority-finding-${finding.severity}`} key={finding.id}>
                <div className="priority-finding-marker" aria-hidden="true" />
                <div className="priority-finding-content">
                  <div className="priority-finding-title-row">
                    <span className={`priority-severity priority-severity-${finding.severity}`}>{finding.severity}</span>
                    <h4>{finding.title}</h4>
                  </div>
                  <p>{finding.summary}</p>
                  {(finding.ip || finding.service) && (
                    <div className="priority-finding-pivots" aria-label="Finding pivots">
                      {finding.ip && onFilter && <PivotValue filter={{ key: "ip", value: finding.ip!, label: "Device" }} filters={filters} onFilter={filterFindingEntity}>{finding.ip}</PivotValue>}
                      {finding.service && onFilter && <PivotValue filter={{ key: "service", value: finding.service!, label: "Service" }} filters={filters} onFilter={filterFindingEntity}>{finding.service}</PivotValue>}
                    </div>
                  )}
                </div>
                <button type="button" className="priority-finding-link" onClick={() => openFinding(finding.id)}>Inspect</button>
              </article>
            ))}
          </div>
        )}
      </section>
    </Panel>
  )
};

export default ExecutiveSummary;
