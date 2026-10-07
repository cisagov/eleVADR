import React from "react";
import { InvestigationFilter } from "../../types/Investigation";
import "./InvestigationBar.css";

interface Props {
  filters: InvestigationFilter[];
  onRemove: (key: InvestigationFilter["key"]) => void;
  onClear: () => void;
}

const InvestigationBar: React.FC<Props> = ({ filters, onRemove, onClear }) => {
  if (!filters.length) return null;
  return (
    <div
      className="investigation-bar"
      role="region"
      aria-label="Active investigation filters"
    >
      <div className="investigation-bar-label">
        <span className="pulse-dot" /> Active Pivot Filters
      </div>
      <div className="investigation-chips">
        {filters.map((filter) => (
          <button
            key={filter.key}
            type="button"
            className="investigation-chip"
            onClick={() => onRemove(filter.key)}
            title="Remove filter"
          >
            <span>{filter.label}</span>
            <strong>{filter.value}</strong>
            <span aria-hidden="true">×</span>
          </button>
        ))}
      </div>
      <button type="button" className="clear-investigation" onClick={onClear}>
        Clear all
      </button>
    </div>
  );
};
export default InvestigationBar;
