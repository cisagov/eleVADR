import React from "react";
import "./ReportGuidance.css";

export interface ReportGuidanceAction {
  label: string;
  onClick: () => void;
  primary?: boolean;
}

interface Props {
  title: string;
  children: React.ReactNode;
  actions?: ReportGuidanceAction[];
  note?: React.ReactNode;
  ariaLabel?: string;
}

const ReportGuidance: React.FC<Props> = ({ title, children, actions = [], note, ariaLabel }) => (
  <div className="report-guidance" role="status" aria-label={ariaLabel || title}>
    <div className="report-guidance-icon" aria-hidden="true">i</div>
    <div className="report-guidance-content">
      <h3>{title}</h3>
      <div className="report-guidance-copy">{children}</div>
      {note && <p className="report-guidance-note">{note}</p>}
      {actions.length > 0 && (
        <div className="report-guidance-actions">
          {actions.map((action) => (
            <button
              key={action.label}
              type="button"
              className={action.primary ? "report-guidance-action primary" : "report-guidance-action"}
              onClick={action.onClick}
            >
              {action.label}
            </button>
          ))}
        </div>
      )}
    </div>
  </div>
);

export default ReportGuidance;
